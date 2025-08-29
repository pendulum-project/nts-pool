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
use eyre::{Context, OptionExt};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::{
    AppState, InfallibleUnwrap,
    error::AppError,
    models::user::{User, UserId, UserRole},
};

pub const AUTH_COOKIE_NAME: &str = "auth";

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

/// Generate a random password reset token that the user can use to reset their password.
pub fn generate_password_reset_token() -> (String, chrono::DateTime<chrono::Utc>) {
    use rand::{Rng, distr::Alphanumeric};

    let token = rand::rng()
        .sample_iter(&Alphanumeric)
        .take(30)
        .map(char::from)
        .collect();
    let expires = chrono::Utc::now() + chrono::Duration::days(1);
    (token, expires)
}

/// Checks if a password is valid for use in our system.
pub fn is_valid_password(password: &str) -> bool {
    password.len() >= 8 && !is_too_large_password(password)
}

/// Checks if the password is too large, should be used to prevent running the
/// password hash function on too large passwords.
pub fn is_too_large_password(password: &str) -> bool {
    password.len() > 256
}

#[derive(Debug, Serialize, Deserialize)]
struct JwtClaims {
    exp: usize, // Required (validate_exp defaults to true in validation). Expiration time (as UTC timestamp)
    iat: usize, // Issued at (as UTC timestamp)
    nbf: usize, // Not Before (as UTC timestamp)
    sub: UserId, // Subject (whom token refers to)
}

#[derive(Debug, derive_more::Display, derive_more::Error)]
#[display("User is not logged in")]
pub struct NotLoggedInError;

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
    Ok(encode(&Header::default(), &claims, encoding_key).wrap_err("Failed to encode JWT")?)
}

fn validate_jwt(token: &str, decoding_key: &DecodingKey) -> Result<UserId, AppError> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    validation.validate_nbf = true;

    let token_data = decode::<JwtClaims>(token, decoding_key, &validation)
        .wrap_err("Failed to decode or validate JWT")?;
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

pub trait IntoUserOption {
    fn into_user_option(self) -> Option<User>;
}

impl IntoUserOption for User {
    fn into_user_option(self) -> Option<User> {
        Some(self)
    }
}

impl IntoUserOption for Option<User> {
    fn into_user_option(self) -> Option<User> {
        self
    }
}

/// Represents a user that is logged in but possibly blocked or not activated.
#[derive(Debug, Clone, derive_more::Deref, derive_more::Into, derive_more::From)]
pub struct UnsafeLoggedInUser(User);

impl IntoUserOption for UnsafeLoggedInUser {
    fn into_user_option(self) -> Option<User> {
        Some(self.into())
    }
}

impl IntoUserOption for Option<UnsafeLoggedInUser> {
    fn into_user_option(self) -> Option<User> {
        self.map(|user| user.into())
    }
}

/// Represents an authenticated user that is activated and not blocked.
#[derive(Debug, Clone, derive_more::Deref, derive_more::Into)]
pub struct AuthorizedUser(User);

impl IntoUserOption for AuthorizedUser {
    fn into_user_option(self) -> Option<User> {
        Some(self.into())
    }
}

impl IntoUserOption for Option<AuthorizedUser> {
    fn into_user_option(self) -> Option<User> {
        self.map(|user| user.into())
    }
}

impl TryFrom<User> for AuthorizedUser {
    type Error = AppError;

    fn try_from(user: User) -> Result<Self, Self::Error> {
        if user.is_disabled() {
            Err(eyre::eyre!("User is disabled").into())
        } else if !user.is_activated() {
            Err(eyre::eyre!("User is not activated").into())
        } else {
            Ok(AuthorizedUser(user))
        }
    }
}

/// Can be extracted from a request, but only if there is a logged in user with the administrator role.
#[derive(Debug, Clone, derive_more::Deref, derive_more::Into)]
pub struct Administrator(AuthorizedUser);

impl IntoUserOption for Administrator {
    fn into_user_option(self) -> Option<User> {
        Some(self.into())
    }
}

impl IntoUserOption for Option<Administrator> {
    fn into_user_option(self) -> Option<User> {
        self.map(|admin| admin.into())
    }
}

impl From<Administrator> for User {
    fn from(administrator: Administrator) -> Self {
        AuthorizedUser::from(administrator).into()
    }
}

impl TryFrom<User> for Administrator {
    type Error = AppError;

    fn try_from(user: User) -> Result<Self, Self::Error> {
        if user.role == UserRole::Administrator {
            Ok(Administrator(AuthorizedUser(user)))
        } else {
            Err(eyre::eyre!("User is not an administrator").into())
        }
    }
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
        .infallible_unwrap();

    let current_user = if let Some(cookie) = cookie_jar.get(AUTH_COOKIE_NAME) {
        let decoding_key = DecodingKey::from_ref(&state);
        match validate_jwt(cookie.value(), &decoding_key) {
            // get_by_id returns None if no user is found, which means the JWT will be ignored
            Ok(user_id) => match crate::models::user::get_by_id(&state.db, user_id)
                .await
                .wrap_err("Failed to retrieve user from database")
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
                            .wrap_err("Session state has unexpected invalid data"),
                    )
                    .into_response();
                }
            },
        }
    } else {
        // There is no session cookie, so user is not logged in
        None
    };

    request.extensions_mut().insert(current_user);
    next.run(request).await
}

impl<S> OptionalFromRequestParts<S> for UnsafeLoggedInUser
where
    S: Send + Sync,
    DecodingKey: FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> Result<Option<Self>, Self::Rejection> {
        let user = parts
            .extensions
            .get::<Option<User>>()
            .ok_or_eyre("No user in request extensions")?
            .clone();
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

impl<S> OptionalFromRequestParts<S> for AuthorizedUser
where
    S: Send + Sync,
    DecodingKey: FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> Result<Option<Self>, Self::Rejection> {
        match parts
            .extract_with_state::<Option<UnsafeLoggedInUser>, S>(state)
            .await
        {
            Ok(Some(session)) => Ok(Some(
                session
                    .0
                    .try_into()
                    .wrap_err("Failed to convert to AuthenticatedUser")?,
            )),
            Ok(None) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

impl<S> FromRequestParts<S> for AuthorizedUser
where
    S: Send + Sync,
    DecodingKey: FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match parts
            .extract_with_state::<Option<AuthorizedUser>, S>(state)
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
        match parts.extract_with_state::<AuthorizedUser, S>(state).await {
            Ok(session) if session.role == UserRole::Administrator => Ok(Administrator(session)),
            _ => Err(eyre::eyre!("No administrator user available"))?,
        }
    }
}
