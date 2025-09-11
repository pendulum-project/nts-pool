use axum::{
    RequestPartsExt,
    extract::{FromRef, FromRequestParts, OptionalFromRequestParts},
    http::request::Parts,
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
    DbConnLike, InfallibleUnwrap,
    error::AppError,
    models::user::{User, UserId, UserRole},
};

const AUTH_COOKIE_NAME: &str = "auth";

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

pub fn generate_session_revoke_token() -> String {
    use rand::{Rng, distr::Alphanumeric};

    rand::rng()
        .sample_iter(&Alphanumeric)
        .take(22)
        .map(char::from)
        .collect()
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    exp: usize, // Required (validate_exp defaults to true in validation). Expiration time (as UTC timestamp)
    iat: usize, // Issued at (as UTC timestamp)
    nbf: usize, // Not Before (as UTC timestamp)
    pub sub: UserId, // Subject (whom token refers to)
    #[serde(rename = "sesrev")]
    pub session_revoke_token: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub parent: Option<UserId>, // Optional parent user id, for "login as" functionality
}

#[derive(Debug, derive_more::Display, derive_more::Error)]
#[display("User is not logged in")]
pub struct NotLoggedInError;

fn create_jwt(
    encoding_key: &EncodingKey,
    user_id: UserId,
    session_revoke_token: String,
    parent_user_id: Option<UserId>,
    valid_for: std::time::Duration,
) -> Result<String, AppError> {
    let claims = JwtClaims {
        exp: (chrono::Utc::now() + valid_for).timestamp() as usize,
        iat: chrono::Utc::now().timestamp() as usize,
        nbf: chrono::Utc::now().timestamp() as usize,
        sub: user_id,
        session_revoke_token,
        parent: parent_user_id,
    };
    Ok(encode(&Header::default(), &claims, encoding_key).wrap_err("Failed to encode JWT")?)
}

fn validate_jwt(token: &str, decoding_key: &DecodingKey) -> Result<JwtClaims, AppError> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    validation.validate_nbf = true;

    let token_data = decode::<JwtClaims>(token, decoding_key, &validation)
        .wrap_err("Failed to decode or validate JWT")?;
    Ok(token_data.claims)
}

fn create_session_cookie(
    user: &User,
    parent: Option<&Administrator>,
    valid_for: std::time::Duration,
    encoding_key: &EncodingKey,
) -> Result<Cookie<'static>, AppError> {
    let token = create_jwt(
        encoding_key,
        user.id,
        parent
            .map(|parent| parent.session_revoke_token.clone())
            .unwrap_or_else(|| user.session_revoke_token.clone()),
        parent.map(|a| a.id),
        valid_for,
    )?;
    let mut cookie = Cookie::new(AUTH_COOKIE_NAME, token);
    cookie.set_secure(true);
    cookie.set_http_only(true);
    cookie.set_same_site(SameSite::Strict);
    cookie.set_path("/");

    Ok(cookie)
}

pub fn login_into(
    user: &User,
    parent: Option<&Administrator>,
    valid_for: Option<std::time::Duration>,
    encoding_key: &EncodingKey,
    cookie_jar: CookieJar,
) -> Result<CookieJar, AppError> {
    let cookie = create_session_cookie(
        user,
        parent,
        valid_for.unwrap_or_else(|| std::time::Duration::from_secs(3600 * 24 * 14)),
        encoding_key,
    )?;
    Ok(cookie_jar.add(cookie))
}

pub async fn logout<'a>(
    user_id: UserId,
    conn: impl DbConnLike<'a>,
    cookie_jar: CookieJar,
) -> Result<CookieJar, AppError> {
    let cookie_jar = cookie_jar.remove(AUTH_COOKIE_NAME);
    crate::models::user::update_session_revoke_token(
        conn,
        user_id,
        generate_session_revoke_token(),
    )
    .await?;
    Ok(cookie_jar)
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
pub struct UnsafeLoggedInUser(pub User);

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

impl TryFrom<AuthorizedUser> for Administrator {
    type Error = AppError;

    fn try_from(user: AuthorizedUser) -> Result<Self, Self::Error> {
        user.0.try_into()
    }
}

/// A valid user session
///
/// This guarantees
///  - That the claims correspond to the user
///  - That the parent is filled in if present in the claims
///  - That the session revocation token is consistent between claims and user/parent.
#[derive(Debug, Clone)]
pub struct Session {
    claims: JwtClaims,
    user: UnsafeLoggedInUser,
    parent: Option<Administrator>,
}

impl Session {
    fn new(
        claims: JwtClaims,
        user: UnsafeLoggedInUser,
        parent: Option<Administrator>,
    ) -> Option<Session> {
        if parent
            .as_ref()
            .map(|admin| &admin.session_revoke_token)
            .unwrap_or(&user.session_revoke_token)
            == &claims.session_revoke_token
            && (claims.parent.is_some() == parent.is_some())
        {
            Some(Session {
                claims,
                user,
                parent,
            })
        } else {
            None
        }
    }

    pub fn claims(&self) -> &JwtClaims {
        &self.claims
    }

    pub fn user(&self) -> &UnsafeLoggedInUser {
        &self.user
    }

    pub fn parent(&self) -> Option<&Administrator> {
        self.parent.as_ref()
    }
}

async fn get_parent_user<S>(state: &S, parent_user_id: UserId) -> Result<Administrator, AppError>
where
    S: Sync + Send,
    sqlx::PgPool: FromRef<S>,
{
    let parent_user =
        crate::models::user::get_by_id(&sqlx::PgPool::from_ref(state), parent_user_id)
            .await
            .wrap_err("Failed to retrieve parent user from database")?
            .ok_or_eyre("Parent user not found")?;
    let admin = Administrator::try_from(
        AuthorizedUser::try_from(parent_user).wrap_err("Parent user is blocked or disabled")?,
    )
    .wrap_err("Parent user is not an administrator")?;
    Ok(admin)
}

impl<S> OptionalFromRequestParts<S> for Session
where
    S: Sync + Send,
    sqlx::PgPool: FromRef<S>,
    jsonwebtoken::DecodingKey: FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> Result<Option<Self>, Self::Rejection> {
        // Ensure we do the parsing only once
        if let Some(previous) = parts.extensions.get::<Option<Session>>() {
            return Ok(previous.clone());
        }

        let cookie_jar = parts.extract::<CookieJar>().await.infallible_unwrap();

        let Some(cookie) = cookie_jar.get(AUTH_COOKIE_NAME) else {
            parts.extensions.insert(None::<Option<Session>>);
            return Ok(None);
        };

        let Some(claims) = validate_jwt(cookie.value(), &DecodingKey::from_ref(state))
            .map(Some)
            .or_else(|e| match e.downcast_ref::<jsonwebtoken::errors::Error>() {
                Some(e) => {
                    if *e.kind() != jsonwebtoken::errors::ErrorKind::ExpiredSignature {
                        debug!("JWT validation error: {e}");
                    }
                    Ok(None)
                }
                _ => Err(e),
            })?
        else {
            parts.extensions.insert(None::<Option<Session>>);
            return Ok(None);
        };

        let db = sqlx::PgPool::from_ref(state);

        let Some(user) = crate::models::user::get_by_id(&db, claims.sub)
            .await
            .wrap_err("Failed to retrieve user from database")?
        else {
            parts.extensions.insert(None::<Option<Session>>);
            return Ok(None);
        };

        let parent = if let Some(parent_user_id) = claims.parent {
            Some(get_parent_user(state, parent_user_id).await?)
        } else {
            None
        };

        let session = Session::new(claims, UnsafeLoggedInUser(user), parent);

        parts.extensions.insert(session.clone());

        Ok(session)
    }
}

impl<S> OptionalFromRequestParts<S> for JwtClaims
where
    S: Sync + Send,
    sqlx::PgPool: FromRef<S>,
    jsonwebtoken::DecodingKey: FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> Result<Option<Self>, Self::Rejection> {
        let session = parts
            .extract_with_state::<Option<Session>, _>(state)
            .await?;
        Ok(session.map(|session| session.claims().clone()))
    }
}

impl<S> FromRequestParts<S> for JwtClaims
where
    S: Sync + Send,
    sqlx::PgPool: FromRef<S>,
    jsonwebtoken::DecodingKey: FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let claims = parts
            .extract_with_state::<Option<JwtClaims>, _>(state)
            .await?;
        Ok(claims.ok_or_eyre(NotLoggedInError)?)
    }
}

impl<S> OptionalFromRequestParts<S> for UnsafeLoggedInUser
where
    S: Sync + Send,
    sqlx::PgPool: FromRef<S>,
    jsonwebtoken::DecodingKey: FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> Result<Option<Self>, Self::Rejection> {
        let session = parts
            .extract_with_state::<Option<Session>, _>(state)
            .await?;
        Ok(session.map(|session| session.user().clone()))
    }
}

impl<S> FromRequestParts<S> for UnsafeLoggedInUser
where
    S: Sync + Send,
    sqlx::PgPool: FromRef<S>,
    jsonwebtoken::DecodingKey: FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match parts
            .extract_with_state::<Option<UnsafeLoggedInUser>, _>(state)
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
    S: Sync + Send,
    sqlx::PgPool: FromRef<S>,
    jsonwebtoken::DecodingKey: FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> Result<Option<Self>, Self::Rejection> {
        match parts
            .extract_with_state::<Option<UnsafeLoggedInUser>, _>(state)
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
    S: Sync + Send,
    sqlx::PgPool: FromRef<S>,
    jsonwebtoken::DecodingKey: FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match parts
            .extract_with_state::<Option<AuthorizedUser>, _>(state)
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
    S: Sync + Send,
    sqlx::PgPool: FromRef<S>,
    jsonwebtoken::DecodingKey: FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match parts.extract_with_state::<AuthorizedUser, _>(state).await {
            Ok(session) if session.role == UserRole::Administrator => Ok(Administrator(session)),
            _ => Err(eyre::eyre!("No administrator user available"))?,
        }
    }
}
