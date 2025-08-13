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
    user_id: UserId,
    valid_for: std::time::Duration,
) -> Result<String, AppError> {
    let claims = JwtClaims {
        exp: (chrono::Utc::now() + valid_for).timestamp() as usize,
        iat: chrono::Utc::now().timestamp() as usize,
        nbf: chrono::Utc::now().timestamp() as usize,
        sub: user_id,
    };
    Ok(encode(&Header::default(), &claims, encoding_key).context("Failed to encode JWT")?)
}

fn validate_jwt(token: &str, decoding_key: &DecodingKey) -> Result<UserId, AppError> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    validation.validate_nbf = true;

    let token_data = decode::<JwtClaims>(token, decoding_key, &validation)
        .context("Failed to decode or validate JWT")?;
    Ok(token_data.claims.sub)
}

fn create_session_cookie(
    user: &User,
    valid_for: std::time::Duration,
    encoding_key: &EncodingKey,
) -> Result<Cookie<'static>, AppError> {
    let token = create_jwt(encoding_key, user.id, valid_for)?;
    let mut cookie = Cookie::new(AUTH_COOKIE_NAME, token);
    cookie.set_secure(true);
    cookie.set_http_only(true);
    cookie.set_same_site(SameSite::Strict);

    Ok(cookie)
}

pub fn login_into(
    user: &User,
    valid_for: Option<std::time::Duration>,
    encoding_key: &EncodingKey,
    cookie_jar: CookieJar,
) -> Result<CookieJar, AppError> {
    let cookie = create_session_cookie(
        user,
        valid_for.unwrap_or_else(|| std::time::Duration::from_secs(3600 * 24 * 14)),
        encoding_key,
    )?;
    Ok(cookie_jar.add(cookie))
}

/// Represents a user that is logged in but possibly blocked or not activated.
#[derive(Debug, Clone)]
pub struct UnsafeLoggedInUser(User);

impl UnsafeLoggedInUser {
    pub fn into_inner(self) -> User {
        self.0
    }

    pub fn as_user(&self) -> &User {
        &self.0
    }
}

/// Represents an authenticated user that is activated and not blocked.
#[derive(Debug, Clone)]
pub struct AuthenticatedUser(User);

impl AuthenticatedUser {
    pub fn into_inner(self) -> User {
        self.0
    }

    pub fn as_user(&self) -> &User {
        &self.0
    }
}

/// Can be extracted from a request, but only if there is a logged in user with the administrator role.
#[derive(Debug, Clone)]
pub struct Administrator(AuthenticatedUser);

impl Deref for Administrator {
    type Target = User;

    fn deref(&self) -> &Self::Target {
        &self.0.0
    }
}

impl Administrator {
    pub fn into_inner(self) -> AuthenticatedUser {
        self.0
    }

    pub fn as_user(&self) -> &User {
        &self.0.0
    }
}

impl From<Administrator> for User {
    fn from(administrator: Administrator) -> Self {
        administrator.into_inner().into_inner()
    }
}

impl From<Administrator> for AuthenticatedUser {
    fn from(administrator: Administrator) -> Self {
        administrator.into_inner()
    }
}

/// Can be extracted from a request, but only if there is a logged in user with the server manager role.
#[derive(Debug, Clone)]
pub struct Manager(AuthenticatedUser);

impl Deref for Manager {
    type Target = User;

    fn deref(&self) -> &Self::Target {
        &self.0.0
    }
}

impl Manager {
    pub fn into_inner(self) -> AuthenticatedUser {
        self.0
    }

    pub fn as_user(&self) -> &User {
        &self.0.0
    }
}

impl From<Manager> for User {
    fn from(server_manager: Manager) -> Self {
        server_manager.into_inner().into_inner()
    }
}

task_local! {
    /// This task local is used to store the currently logged in user.
    ///
    /// Handlers should always use the extractors instead of this task local.
    pub static CURRENT_USER: Option<User>;
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

    let current_user = if let Some(cookie) = cookie_jar.get(AUTH_COOKIE_NAME) {
        let decoding_key = DecodingKey::from_ref(&state);
        match validate_jwt(cookie.value(), &decoding_key) {
            // get_by_id returns None if no user is found, which means the JWT will be ignored
            Ok(user_id) => match crate::models::user::get_by_id(&state.db, user_id)
                .await
                .context("Failed to retrieve user from database")
            {
                Ok(user) => user,
                Err(e) => {
                    return AppError::from(e).into_response();
                }
            },
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

    CURRENT_USER.scope(current_user, next.run(request)).await
}

impl<S> OptionalFromRequestParts<S> for UnsafeLoggedInUser
where
    S: Send + Sync,
    DecodingKey: FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(
        _parts: &mut Parts,
        _state: &S,
    ) -> Result<Option<Self>, Self::Rejection> {
        let user = CURRENT_USER.get();
        Ok(user.map(UnsafeLoggedInUser))
    }
}

impl<S> FromRequestParts<S> for UnsafeLoggedInUser
where
    S: Send + Sync,
    DecodingKey: FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match parts
            .extract_with_state::<Option<UnsafeLoggedInUser>, S>(state)
            .await
        {
            Ok(Some(session)) => Ok(session),
            Ok(None) => Err(NotLoggedInError)?,
            Err(e) => Err(e),
        }
    }
}

impl<S> OptionalFromRequestParts<S> for AuthenticatedUser
where
    S: Send + Sync,
    DecodingKey: FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(
        _parts: &mut Parts,
        _state: &S,
    ) -> Result<Option<Self>, Self::Rejection> {
        let user = CURRENT_USER.get();
        Ok(user.and_then(|user| {
            if user.is_disabled() || !user.is_activated() {
                None
            } else {
                Some(AuthenticatedUser(user))
            }
        }))
    }
}

impl<S> FromRequestParts<S> for AuthenticatedUser
where
    S: Send + Sync,
    DecodingKey: FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match parts
            .extract_with_state::<Option<AuthenticatedUser>, S>(state)
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
        match parts
            .extract_with_state::<AuthenticatedUser, S>(state)
            .await
        {
            Ok(session) if session.as_user().role == UserRole::Administrator => {
                Ok(Administrator(session))
            }
            _ => Err(anyhow!("No administrator user available"))?,
        }
    }
}

impl<S> FromRequestParts<S> for Manager
where
    S: Send + Sync,
    DecodingKey: FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match parts
            .extract_with_state::<AuthenticatedUser, S>(state)
            .await
        {
            Ok(session) if session.as_user().role == UserRole::Manager => Ok(Manager(session)),
            _ => Err(anyhow!("No server manager user available"))?,
        }
    }
}

/// Generate a random activation token that the user can enter to activate their account.
pub fn generate_activation_token() -> (String, chrono::DateTime<chrono::Utc>) {
    use rand::Rng;

    let mut rng = rand::rng();
    let activation_token = (0..8)
        .map(|_| rng.random_range(0..10).to_string())
        .collect();
    let activation_token_expires_at = chrono::Utc::now() + chrono::Duration::days(1);
    (activation_token, activation_token_expires_at)
}
