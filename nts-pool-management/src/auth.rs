use std::ops::Deref;

use anyhow::{Context, anyhow};
use axum::{
    RequestPartsExt,
    extract::{FromRef, FromRequestParts, OptionalFromRequestParts},
    http::request::Parts,
};
use axum_extra::extract::{
    CookieJar,
    cookie::{Cookie, SameSite},
};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};

use crate::{
    error::AppError,
    models::user::{User, UserId, UserRole},
};

#[derive(Debug, Serialize, Deserialize)]
struct JwtClaims {
    exp: usize, // Required (validate_exp defaults to true in validation). Expiration time (as UTC timestamp)
    iat: usize, // Issued at (as UTC timestamp)
    nbf: usize, // Not Before (as UTC timestamp)
    sub: UserId, // Subject (whom token refers to)
    role: UserRole, // role in the application of the subject
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
    };
    Ok(encode(&Header::default(), &claims, encoding_key).context("Failed to encode JWT")?)
}

fn validate_jwt(token: &str, decoding_key: &DecodingKey) -> Result<(UserId, UserRole), AppError> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    validation.validate_nbf = true;

    let token_data = decode::<JwtClaims>(token, decoding_key, &validation)
        .context("Failed to decode or validate JWT")?;
    Ok((token_data.claims.sub, token_data.claims.role))
}

fn create_session_cookie(
    user: &User,
    valid_for: std::time::Duration,
    encoding_key: &EncodingKey,
) -> Result<Cookie<'static>, AppError> {
    let token = create_jwt(encoding_key, user, valid_for)?;
    let mut cookie = Cookie::new("auth", token);
    cookie.set_secure(true);
    cookie.set_http_only(true);
    cookie.set_same_site(SameSite::Strict);

    Ok(cookie)
}

fn login_into(
    user: &User,
    valid_for: std::time::Duration,
    encoding_key: &EncodingKey,
    cookie_jar: CookieJar,
) -> Result<CookieJar, AppError> {
    let cookie = create_session_cookie(user, valid_for, encoding_key)?;
    Ok(cookie_jar.add(cookie))
}

/// Can be extracted from a request, but only if there is a logged in user with the administrator role.
pub struct Administrator(UserId);

/// Can be extracted from a request, but only if there is a logged in user with the server manager role.
pub struct ServerManager(UserId);

impl Deref for Administrator {
    type Target = UserId;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Deref for ServerManager {
    type Target = UserId;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Administrator {
    pub fn into_inner(self) -> UserId {
        self.0
    }
}

impl ServerManager {
    pub fn into_inner(self) -> UserId {
        self.0
    }
}

/// Can be extracted from a request, but only if there is a logged in user.
pub struct UserSession {
    user_id: UserId,
    role: UserRole,
}

impl<S> OptionalFromRequestParts<S> for UserSession
where
    S: Send + Sync,
    DecodingKey: FromRef<S>,
{
    type Rejection = AppError;

    fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> impl Future<Output = Result<Option<Self>, Self::Rejection>> + Send {
        async {
            let cookie_jar = parts
                .extract::<CookieJar>()
                .await
                .expect("Extracting CookieJar should never fail");
            if let Some(cookie) = cookie_jar.get("auth") {
                match validate_jwt(cookie.value(), &DecodingKey::from_ref(state)) {
                    Ok((user_id, role)) => Ok(Some(UserSession { user_id, role })),
                    Err(e) => match e.downcast_ref::<jsonwebtoken::errors::Error>() {
                        Some(e)
                            if *e.kind() == jsonwebtoken::errors::ErrorKind::ExpiredSignature =>
                        {
                            Ok(None)
                        }
                        _ => Err(e.into_inner())
                            .context("Session state has unexpected invalid data")?,
                    },
                }
            } else {
                Ok(None)
            }
        }
    }
}

impl<S> FromRequestParts<S> for UserSession
where
    S: Send + Sync,
    DecodingKey: FromRef<S>,
{
    type Rejection = AppError;

    fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        async {
            match parts
                .extract_with_state::<Option<UserSession>, S>(state)
                .await
            {
                Ok(Some(session)) => Ok(session),
                Ok(None) => Err(anyhow!("User not logged in"))?,
                Err(e) => Err(e),
            }
        }
    }
}

impl<S> FromRequestParts<S> for Administrator
where
    S: Send + Sync,
    DecodingKey: FromRef<S>,
{
    type Rejection = AppError;

    fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        async {
            match parts.extract_with_state::<UserSession, S>(state).await {
                Ok(session) if session.role == UserRole::Administrator => {
                    Ok(Administrator(session.user_id))
                }
                _ => Err(anyhow!("No administrator user available"))?,
            }
        }
    }
}

impl<S> FromRequestParts<S> for ServerManager
where
    S: Send + Sync,
    DecodingKey: FromRef<S>,
{
    type Rejection = AppError;

    fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        async {
            match parts.extract_with_state::<UserSession, S>(state).await {
                Ok(session) if session.role == UserRole::ServerManager => {
                    Ok(ServerManager(session.user_id))
                }
                _ => Err(anyhow!("No server manager user available"))?,
            }
        }
    }
}
