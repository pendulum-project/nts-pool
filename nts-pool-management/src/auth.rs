use std::{fmt::Display, ops::Deref};

use anyhow::{Context, anyhow};
use axum::{
    RequestExt, RequestPartsExt,
    extract::{FromRef, FromRequestParts, OptionalFromRequestParts, Request, State},
    http::request::Parts,
    middleware::Next,
    response::{IntoResponse, Response},
};
use axum_extra::extract::{
    CookieJar,
    cookie::{Cookie, SameSite},
};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use tokio::task_local;
use tracing::debug;

use crate::{
    AppState,
    error::AppError,
    models::user::{User, UserId, UserRole},
};

pub const AUTH_COOKIE_NAME: &str = "auth";

#[derive(Debug, Serialize, Deserialize)]
struct JwtClaims {
    exp: usize, // Required (validate_exp defaults to true in validation). Expiration time (as UTC timestamp)
    iat: usize, // Issued at (as UTC timestamp)
    nbf: usize, // Not Before (as UTC timestamp)
    sub: UserId, // Subject (whom token refers to)
    role: UserRole, // role in the application of the subject
    email: String, // email of the subject
}

#[derive(Debug)]
pub struct NotLoggedInError;

impl std::error::Error for NotLoggedInError {}

impl Display for NotLoggedInError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "User is not logged in")
    }
}

fn create_jwt(
    encoding_key: &EncodingKey,
    user: &User,
    valid_for: std::time::Duration,
) -> Result<String, AppError> {
    let claims = JwtClaims {
        exp: (chrono::Utc::now() + valid_for).timestamp() as usize,
        iat: chrono::Utc::now().timestamp() as usize,
        nbf: chrono::Utc::now().timestamp() as usize,
        sub: user.id,
        role: user.role,
        email: user.email.clone(),
    };
    Ok(encode(&Header::default(), &claims, encoding_key).context("Failed to encode JWT")?)
}

fn validate_jwt(
    token: &str,
    decoding_key: &DecodingKey,
) -> Result<(UserId, UserRole, String), AppError> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    validation.validate_nbf = true;

    let token_data = decode::<JwtClaims>(token, decoding_key, &validation)
        .context("Failed to decode or validate JWT")?;
    Ok((
        token_data.claims.sub,
        token_data.claims.role,
        token_data.claims.email,
    ))
}

fn create_session_cookie(
    user: &User,
    valid_for: std::time::Duration,
    encoding_key: &EncodingKey,
) -> Result<Cookie<'static>, AppError> {
    let token = create_jwt(encoding_key, user, valid_for)?;
    let mut cookie = Cookie::new(AUTH_COOKIE_NAME, token);
    cookie.set_secure(true);
    cookie.set_http_only(true);
    cookie.set_same_site(SameSite::Strict);

    Ok(cookie)
}

pub fn login_into(
    user: &User,
    valid_for: std::time::Duration,
    encoding_key: &EncodingKey,
    cookie_jar: CookieJar,
) -> Result<CookieJar, AppError> {
    let cookie = create_session_cookie(user, valid_for, encoding_key)?;
    Ok(cookie_jar.add(cookie))
}

/// Can be extracted from a request, but only if there is a logged in user with the administrator role.
#[derive(Debug, Clone)]
pub struct Administrator(UserSession);

impl Deref for Administrator {
    type Target = UserSession;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Administrator {
    pub fn into_inner(self) -> UserSession {
        self.0
    }
}

impl From<Administrator> for UserSession {
    fn from(administrator: Administrator) -> Self {
        administrator.into_inner()
    }
}

/// Can be extracted from a request, but only if there is a logged in user with the server manager role.
#[derive(Debug, Clone)]
pub struct ServerManager(UserSession);

impl Deref for ServerManager {
    type Target = UserSession;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ServerManager {
    pub fn into_inner(self) -> UserSession {
        self.0
    }
}

impl From<ServerManager> for UserSession {
    fn from(server_manager: ServerManager) -> Self {
        server_manager.into_inner()
    }
}

/// Can be extracted from a request, but only if there is a logged in user.
#[derive(Debug, Clone)]
pub struct UserSession {
    pub user_id: UserId,
    pub role: UserRole,
    pub email: String,
}

task_local! {
    /// This task local is used to store the currently logged in user.
    ///
    /// Handlers should always use the extractors instead of this task local.
    pub static USER_SESSION: Option<UserSession>;
}

/// Middleware that retrieves the user session from the request.
pub async fn auth_middleware(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let cookie_jar = request
        .extract_parts::<CookieJar>()
        .await
        .expect("Extracting CookieJar should never fail");

    let user_session = if let Some(cookie) = cookie_jar.get(AUTH_COOKIE_NAME) {
        let decoding_key = DecodingKey::from_ref(&state);
        match validate_jwt(cookie.value(), &decoding_key) {
            Ok((user_id, role, email)) => Some(UserSession {
                user_id,
                role,
                email,
            }),
            Err(e) => match e.downcast_ref::<jsonwebtoken::errors::Error>() {
                Some(e) if *e.kind() == jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                    // expected failure, ignore and no longer allow session for logged in user
                    None
                }
                Some(e) => {
                    // we ignore other kinds of jwt errors as well, but log them for debugging purposes
                    debug!("JWT validation error: {e}");
                    None
                }
                _ => {
                    // other errors are weird, they result in a server error
                    return AppError::from(
                        e.into_inner()
                            .context("Session state has unexpected invalid data"),
                    )
                    .into_response();
                }
            },
        }
    } else {
        // There is no session cookie, so user is not logged in
        None
    };

    USER_SESSION.scope(user_session, next.run(request)).await
}

impl<S> OptionalFromRequestParts<S> for UserSession
where
    S: Send + Sync,
    DecodingKey: FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(
        _parts: &mut Parts,
        _state: &S,
    ) -> Result<Option<Self>, Self::Rejection> {
        Ok(USER_SESSION.get())
    }
}

impl<S> FromRequestParts<S> for UserSession
where
    S: Send + Sync,
    DecodingKey: FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match parts
            .extract_with_state::<Option<UserSession>, S>(state)
            .await
        {
            Ok(Some(session)) => Ok(session),
            Ok(None) => Err(NotLoggedInError)?,
            Err(e) => Err(e),
        }
    }
}

impl<S> FromRequestParts<S> for Administrator
where
    S: Send + Sync,
    DecodingKey: FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match parts.extract_with_state::<UserSession, S>(state).await {
            Ok(session) if session.role == UserRole::Administrator => Ok(Administrator(session)),
            _ => Err(anyhow!("No administrator user available"))?,
        }
    }
}

impl<S> FromRequestParts<S> for ServerManager
where
    S: Send + Sync,
    DecodingKey: FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match parts.extract_with_state::<UserSession, S>(state).await {
            Ok(session) if session.role == UserRole::ServerManager => Ok(ServerManager(session)),
            _ => Err(anyhow!("No server manager user available"))?,
        }
    }
}
