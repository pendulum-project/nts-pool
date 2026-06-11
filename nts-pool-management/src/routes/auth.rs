use std::str::FromStr;

use askama::Template;
use axum::{
    Form,
    extract::{Query, State},
    response::{IntoResponse, Redirect},
};
use axum_extra::extract::{CookieJar, PrivateCookieJar};
use eyre::{Context, OptionExt};
use jsonwebtoken::EncodingKey;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use crate::{
    AppState,
    auth::{
        JwtClaims, UnsafeLoggedInUser, generate_session_revoke_token, is_too_large_password,
        is_valid_password, login_into,
    },
    captcha,
    config::AppConfig,
    context::AppContext,
    email::Mailer,
    error::AppError,
    models::{
        authentication_method::{AuthenticationVariant, PasswordAuthentication},
        user::{NewUser, UserRole},
    },
    templates::{HtmlTemplate, filters},
};

#[derive(Template)]
#[template(path = "login/login.html.j2")]
struct LoginPageTemplate {
    app: AppContext,
    login_error: bool,
}

pub async fn login(user: Option<UnsafeLoggedInUser>, app: AppContext) -> impl IntoResponse {
    if let Some(user) = user {
        if !user.is_activated() {
            return Redirect::to("/register/activate").into_response();
        } else if user.is_disabled() {
            return Redirect::to("/logout").into_response();
        } else {
            return Redirect::to("/").into_response();
        }
    }

    HtmlTemplate(LoginPageTemplate {
        app,
        login_error: false,
    })
    .into_response()
}

#[derive(Debug, Deserialize)]
pub struct LoginData {
    email: String,
    password: String,
}

pub async fn login_submit(
    auth_user: Option<UnsafeLoggedInUser>,
    app: AppContext,
    cookie_jar: CookieJar,
    State(encoding_key): State<EncodingKey>,
    State(db): State<PgPool>,
    Form(data): Form<LoginData>,
) -> Result<impl IntoResponse, AppError> {
    match login_submit_internal(auth_user.clone(), cookie_jar, encoding_key, db, data).await {
        Ok(response) => Ok(response.into_response()),
        Err(e) if e.is::<InvalidCredentialsError>() => Ok(HtmlTemplate(LoginPageTemplate {
            app,
            login_error: true,
        })
        .into_response()),
        Err(e) => Err(e),
    }
}

#[derive(Debug, derive_more::Display, derive_more::Error)]
#[display("Failed to login, invalid credentials")]
struct InvalidCredentialsError;

async fn login_submit_internal(
    auth_user: Option<UnsafeLoggedInUser>,
    mut cookie_jar: CookieJar,
    encoding_key: EncodingKey,
    db: PgPool,
    data: LoginData,
) -> Result<impl IntoResponse, AppError> {
    if auth_user.is_some() {
        return Ok(Redirect::to("/logout").into_response());
    }

    let user = crate::models::user::get_by_email(&db, &data.email)
        .await
        .wrap_err("Failed to load user from database")?
        .ok_or_eyre(InvalidCredentialsError)?;
    let password_method =
        crate::models::authentication_method::get_password_authentication_method(&db, user.id)
            .await
            .wrap_err("Failed to load authentication method from database")?
            .ok_or_eyre(InvalidCredentialsError)?;

    // prevent too large password from being used
    if is_too_large_password(&data.password) {
        return Err(eyre::eyre!("Password provided is too large")
            .wrap_err(InvalidCredentialsError)
            .into());
    }

    if password_method
        .verify(&data.password)
        .wrap_err("Failed to run password verification")?
    {
        if user.is_disabled() {
            return Err(eyre::eyre!("User is disabled").into());
        }

        cookie_jar = login_into(&user, None, None, &encoding_key, cookie_jar)?;
        crate::models::user::update_last_login(&db, user.id)
            .await
            .wrap_err("Failed to update last login time")?;
    } else {
        return Err(eyre::eyre!("Password could not be verified")
            .wrap_err(InvalidCredentialsError)
            .into());
    }

    Ok((
        cookie_jar,
        Redirect::to(if user.is_activated() {
            "/"
        } else {
            "/register/activate"
        }),
    )
        .into_response())
}

pub async fn logout(
    cookie_jar: CookieJar,
    claims: JwtClaims,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    if let Some(parent_id) = claims.parent {
        let cookie_jar = login_into(
            &crate::models::user::get_by_id(&state.db, parent_id)
                .await?
                .ok_or_eyre("Parent user not found")?,
            None,
            None,
            &state.jwt_encoding_key,
            cookie_jar,
        )?;
        Ok((cookie_jar, Redirect::to("/admin/users")))
    } else {
        let cookie_jar = crate::common::auth::logout(claims.sub, &state.db, cookie_jar).await?;
        Ok((cookie_jar, Redirect::to("/")))
    }
}

#[derive(Template)]
#[template(path = "login/register.html.j2")]
struct RegisterPageTemplate {
    app: AppContext,
    fields_with_errors: Vec<&'static str>,
    data_email: Option<String>,
    captcha: captcha::Challenge,
}

pub async fn register(
    user: Option<UnsafeLoggedInUser>,
    app: AppContext,
    State(config): State<AppConfig>,
    captcha_jar: PrivateCookieJar,
) -> impl IntoResponse {
    if let Some(user) = user {
        if !user.is_activated() {
            return Redirect::to("/register/activate").into_response();
        } else if user.is_disabled() {
            return Redirect::to("/logout").into_response();
        } else {
            return Redirect::to("/").into_response();
        }
    }

    let (captcha_jar, challenge) = captcha::issue_challenge(captcha_jar, config.captcha_params);
    (
        captcha_jar,
        HtmlTemplate(RegisterPageTemplate {
            app,
            fields_with_errors: Vec::new(),
            data_email: None,
            captcha: challenge,
        }),
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
pub struct RegisterForm {
    email: String,
    password: String,
    confirm_password: String,
    accept_terms: bool,
    #[serde(default)]
    captcha_challenge: String,
    #[serde(default)]
    captcha_nonce: String,
    /// Honeypot, hidden from real users and must remain empty.
    #[serde(default)]
    website: String,
}

#[allow(clippy::too_many_arguments, reason = "every argument is an extractor")]
pub async fn register_submit(
    auth_user: Option<UnsafeLoggedInUser>,
    app: AppContext,
    State(pool): State<PgPool>,
    State(encoding_key): State<EncodingKey>,
    State(mailer): State<Mailer>,
    State(config): State<AppConfig>,
    cookie_jar: CookieJar,
    captcha_jar: PrivateCookieJar,
    Form(data): Form<RegisterForm>,
) -> Result<impl IntoResponse, AppError> {
    if auth_user.is_some() {
        return Ok(Redirect::to("/").into_response());
    }

    let mut fields_with_errors = Vec::new();

    // the challenge is always consumed, a failed attempt requires a new one
    let (captcha_jar, challenge) = captcha::take_challenge(captcha_jar);
    if !data.website.is_empty()
        || !challenge.is_some_and(|challenge| {
            captcha::verify_solution(&challenge, &data.captcha_challenge, &data.captcha_nonce)
        })
    {
        fields_with_errors.push("captcha");
    }

    if !data.email.contains('@') || lettre::Address::from_str(&data.email).is_err() {
        fields_with_errors.push("email");

    // check if email is already registered
    } else if crate::models::user::get_by_email(&pool, &data.email)
        .await
        .wrap_err("Failed to load user from database")?
        .is_some()
    {
        fields_with_errors.push("email");
    }

    if data.password != data.confirm_password {
        fields_with_errors.push("password");
        fields_with_errors.push("confirm_password");
    } else if !is_valid_password(&data.password) {
        fields_with_errors.push("password");
    }

    if !data.accept_terms {
        fields_with_errors.push("accept_terms");
    }

    if !fields_with_errors.is_empty() {
        let (captcha_jar, challenge) = captcha::issue_challenge(captcha_jar, config.captcha_params);
        Ok((
            captcha_jar,
            HtmlTemplate(RegisterPageTemplate {
                app,
                fields_with_errors,
                data_email: Some(data.email),
                captcha: challenge,
            }),
        )
            .into_response())
    } else {
        // we start by storing the new user in the database
        let (activation_token, activation_expires_at) = crate::auth::generate_activation_token();
        let session_revoke_token = crate::auth::generate_session_revoke_token();
        let mut tx = pool.begin().await?;
        let user = crate::models::user::create(
            &mut *tx,
            NewUser {
                email: data.email,
                role: UserRole::Manager,
                session_revoke_token,
                activation_token,
                activation_expires_at,
            },
        )
        .await
        .wrap_err("Failed to create user")?;

        crate::models::authentication_method::create(
            &mut *tx,
            user.id,
            AuthenticationVariant::Password(
                PasswordAuthentication::new(&data.password).wrap_err("Failed to hash password")?,
            ),
        )
        .await
        .wrap_err("Failed to create password authentication method")?;

        tx.commit().await.wrap_err("Transaction commit failed")?;

        // we send an activation email to the user
        crate::email::send_activation_email(&mailer, &user).await?;

        // we log the user in and send them to the confirmation page, waiting for them entering the activation token
        let cookie_jar = crate::auth::login_into(&user, None, None, &encoding_key, cookie_jar)?;

        Ok((captcha_jar, cookie_jar, Redirect::to("/register/activate")).into_response())
    }
}

#[derive(Template)]
#[template(path = "login/register_activate.html.j2")]
struct RegisterActivatePageTemplate {
    app: AppContext,
    has_code_error: bool,
    resend_reason: Option<ResendReason>,
}

pub async fn register_activate(
    user: UnsafeLoggedInUser,
    app: AppContext,
    Query(query): Query<RegisterActivateQuery>,
) -> impl IntoResponse {
    if user.is_disabled() {
        return Redirect::to("/logout").into_response();
    }

    if user.is_activated() {
        return Redirect::to("/").into_response();
    }

    HtmlTemplate(RegisterActivatePageTemplate {
        app,
        has_code_error: false,
        resend_reason: query.reason,
    })
    .into_response()
}

#[derive(Debug, Deserialize)]
pub struct RegisterActivateForm {
    activation_token: Option<String>,
    action: RegisterActivateAction,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RegisterActivateAction {
    Activate,
    Resend,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ResendReason {
    Requested,
    Expired,
    Invalid,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterActivateQuery {
    #[serde(default)]
    reason: Option<ResendReason>,
}

pub async fn register_activate_submit(
    auth_user: UnsafeLoggedInUser,
    app: AppContext,
    State(pool): State<PgPool>,
    State(mailer): State<Mailer>,
    Form(data): Form<RegisterActivateForm>,
) -> Result<impl IntoResponse, AppError> {
    if auth_user.is_disabled() {
        return Ok(Redirect::to("/logout").into_response());
    }

    if auth_user.is_activated() {
        return Ok(Redirect::to("/").into_response());
    }

    let user_has_token =
        auth_user.activation_token.is_some() && auth_user.activation_expires_at.is_some();
    let token_expired = auth_user
        .activation_expires_at
        .map(|exp| exp < chrono::Utc::now())
        .unwrap_or(true);
    let resend_requested = data.action == RegisterActivateAction::Resend;

    if resend_requested || !user_has_token || token_expired {
        let (activation_token, activation_expires_at) = crate::auth::generate_activation_token();
        let user = crate::models::user::set_activation_token(
            &pool,
            auth_user.id,
            activation_token,
            activation_expires_at,
        )
        .await
        .wrap_err("Failed to update activation token for user")?;
        crate::email::send_activation_email(&mailer, &user).await?;
        let resend_reason = if resend_requested {
            ResendReason::Requested
        } else if !user_has_token {
            ResendReason::Invalid
        } else {
            ResendReason::Expired
        };

        return Ok(Redirect::to(&format!(
            "/register/activate?{}",
            serde_qs::to_string(&RegisterActivateQuery {
                reason: Some(resend_reason),
            })
            .wrap_err("Failed to serialize redirect query parameters")?
        ))
        .into_response());
    }

    let token = auth_user
        .activation_token
        .as_ref()
        .expect("Failed to get activation token despite previous check");

    let activation_token_valid = data.activation_token.map(|t| t == *token).unwrap_or(false);

    // we previously checked that the token was not expired
    if activation_token_valid {
        crate::models::user::activate_user(&pool, auth_user.id).await?;
        Ok(Redirect::to("/").into_response())
    } else {
        Ok(HtmlTemplate(RegisterActivatePageTemplate {
            app,
            has_code_error: true,
            resend_reason: None,
        })
        .into_response())
    }
}

#[derive(Template)]
#[template(path = "login/forgot_password.html.j2")]
struct ForgotPasswordPageTemplate {
    app: AppContext,
    requested: bool,
    failed: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ForgotPasswordQuery {
    requested: Option<bool>,
    failed: Option<bool>,
}

pub async fn forgot_password(
    user: Option<UnsafeLoggedInUser>,
    app: AppContext,
    Query(query): Query<ForgotPasswordQuery>,
) -> impl IntoResponse {
    if let Some(user) = user {
        if user.is_disabled() {
            return Redirect::to("/logout").into_response();
        } else {
            return Redirect::to("/").into_response();
        }
    }

    HtmlTemplate(ForgotPasswordPageTemplate {
        app,
        requested: query.requested.unwrap_or_default(),
        failed: query.failed.unwrap_or_default(),
    })
    .into_response()
}

#[derive(Debug, Clone, Deserialize)]
pub struct ForgotPasswordSubmitForm {
    email: String,
}

pub async fn forgot_password_submit(
    user: Option<UnsafeLoggedInUser>,
    app: AppContext,
    State(pool): State<PgPool>,
    State(mailer): State<Mailer>,
    Form(form): Form<ForgotPasswordSubmitForm>,
) -> Result<impl IntoResponse, AppError> {
    if let Some(user) = user {
        if user.is_disabled() {
            return Ok(Redirect::to("/logout").into_response());
        } else {
            return Ok(Redirect::to("/").into_response());
        }
    }

    if let Some(user) = crate::models::user::get_by_email(&pool, &form.email).await?
        && let Some(mut password_auth) =
            crate::models::authentication_method::get_password_authentication_method_row(
                &pool, user.id,
            )
            .await?
        && let Some(password_variant_ref) = password_auth.as_password_variant_mut()
    {
        let (token, expires_at) = crate::auth::generate_password_reset_token();
        password_variant_ref.set_password_reset_token(&token, expires_at);
        crate::models::authentication_method::update_variant(
            &pool,
            password_auth.id,
            password_auth.variant.0,
        )
        .await?;

        crate::email::send_password_reset_email(&mailer, &user, &token, &app.base_url).await?;
    }
    // Implement forgot password logic here
    Ok(Redirect::to("/login/forgot-password?requested=true").into_response())
}

#[derive(Template)]
#[template(path = "login/password_reset.html.j2")]
struct PasswordResetPageTemplate {
    app: AppContext,
    password_error: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ResetPasswordQuery {
    pub token: String,
    pub email: String,
}

pub async fn reset_password(
    user: Option<UnsafeLoggedInUser>,
    app: AppContext,
    Query(query): Query<ResetPasswordQuery>,
    State(pool): State<PgPool>,
) -> Result<impl IntoResponse, AppError> {
    if let Some(user) = user {
        if user.is_disabled() {
            return Ok(Redirect::to("/logout").into_response());
        } else {
            return Ok(Redirect::to("/").into_response());
        }
    }

    let Some(user) = crate::models::user::get_by_email(&pool, &query.email).await? else {
        return Ok(Redirect::to("/").into_response());
    };

    let Some(password_auth) =
        crate::models::authentication_method::get_password_authentication_method(&pool, user.id)
            .await?
    else {
        return Ok(Redirect::to("/").into_response());
    };

    let (Some(password_reset_token), Some(password_reset_expires_at)) = (
        password_auth.password_reset_token,
        password_auth.password_reset_token_expires_at,
    ) else {
        return Ok(Redirect::to("/").into_response());
    };

    if password_reset_token != query.token || password_reset_expires_at < chrono::Utc::now() {
        return Ok(Redirect::to("/login/forgot-password?failed=true").into_response());
    }

    Ok(HtmlTemplate(PasswordResetPageTemplate {
        app,
        password_error: false,
    })
    .into_response())
}

#[derive(Debug, Deserialize)]
pub struct ResetPasswordForm {
    password: String,
    confirm_password: String,
}

pub async fn reset_password_submit(
    user: Option<UnsafeLoggedInUser>,
    app: AppContext,
    Query(query): Query<ResetPasswordQuery>,
    State(pool): State<PgPool>,
    Form(form): Form<ResetPasswordForm>,
) -> Result<impl IntoResponse, AppError> {
    if let Some(user) = user {
        if user.is_disabled() {
            return Ok(Redirect::to("/logout").into_response());
        } else {
            return Ok(Redirect::to("/").into_response());
        }
    }

    let Some(user) = crate::models::user::get_by_email(&pool, &query.email).await? else {
        return Ok(Redirect::to("/").into_response());
    };

    let Some(mut auth_row) =
        crate::models::authentication_method::get_password_authentication_method_row(
            &pool, user.id,
        )
        .await
        .wrap_err("Failed to load authentication method row")?
    else {
        return Ok(Redirect::to("/").into_response());
    };

    // this should never fail
    let password_auth = auth_row
        .as_password_variant_mut()
        .ok_or_eyre("Could not extract password auth variant")?;

    let (Some(password_reset_token), Some(password_reset_expires_at)) = (
        password_auth.password_reset_token.as_deref(),
        password_auth.password_reset_token_expires_at,
    ) else {
        return Ok(Redirect::to("/").into_response());
    };

    if password_reset_token != query.token || password_reset_expires_at < chrono::Utc::now() {
        return Ok(Redirect::to("/login/forgot-password?failed=true").into_response());
    }

    if form.password != form.confirm_password || !is_valid_password(&form.password) {
        return Ok(HtmlTemplate(PasswordResetPageTemplate {
            app,
            password_error: true,
        })
        .into_response());
    }

    password_auth
        .update_password(&form.password)
        .wrap_err("Could not update password")?;

    crate::models::authentication_method::update_variant(&pool, auth_row.id, auth_row.variant.0)
        .await
        .wrap_err("Failed to update authentication method variant")?;

    crate::models::user::update_session_revoke_token(
        &pool,
        user.id,
        generate_session_revoke_token(),
    )
    .await
    .wrap_err("Failed to reset session revocation token")?;

    Ok(Redirect::to("/login").into_response())
}

#[cfg(test)]
mod tests {
    use axum::{Form, extract::State, response::IntoResponse};
    use axum_extra::extract::{
        CookieJar, PrivateCookieJar,
        cookie::{Cookie, Key},
    };

    use crate::{
        captcha,
        config::AppConfig,
        context::AppContext,
        email::{MailTransport, Mailer},
        models::{
            authentication_method::{AuthenticationVariant, PasswordAuthentication},
            user::{NewUser, UserRole},
        },
        test::IntoHtml,
    };

    #[tokio::test]
    async fn test_login_page_success() {
        let response = crate::routes::auth::login(None, AppContext::default())
            .await
            .into_response();
        assert!(response.status().is_success());
    }

    #[tokio::test]
    async fn test_login_page_with_user_redirects() {
        let admin_user = crate::models::user::User::test_admin();

        let response = crate::routes::auth::login(
            Some(admin_user.clone().into()),
            AppContext::default().with_user(admin_user.clone()),
        )
        .await
        .into_response();
        assert_eq!(response.status(), axum::http::StatusCode::SEE_OTHER);
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::LOCATION)
                .unwrap(),
            "/"
        );

        let manager_user = crate::models::user::User::test_manager();
        let response = super::login(
            Some(manager_user.clone().into()),
            AppContext::default().with_user(manager_user.clone()),
        )
        .await
        .into_response();
        assert_eq!(response.status(), axum::http::StatusCode::SEE_OTHER);
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::LOCATION)
                .unwrap(),
            "/"
        );

        let manager_user = crate::models::user::User::test_disabled_manager();
        let response = super::login(
            Some(manager_user.clone().into()),
            AppContext::default().with_user(manager_user.clone()),
        )
        .await
        .into_response();
        assert_eq!(response.status(), axum::http::StatusCode::SEE_OTHER);
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::LOCATION)
                .unwrap(),
            "/logout"
        );

        let manager_user = crate::models::user::User::test_not_activated_manager();
        let response = super::login(
            Some(manager_user.clone().into()),
            AppContext::default().with_user(manager_user.clone()),
        )
        .await
        .into_response();
        assert_eq!(response.status(), axum::http::StatusCode::SEE_OTHER);
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::LOCATION)
                .unwrap(),
            "/register/activate"
        );
    }

    #[tokio::test]
    async fn test_login_submit_failed() {
        let (_db, pool) = crate::test::PostgresContainer::init().await;
        let encoding_key = State(jsonwebtoken::EncodingKey::from_secret(b"secret"));

        let response = crate::routes::auth::login_submit(
            None,
            AppContext::default(),
            CookieJar::new(),
            encoding_key.clone(),
            State(pool.clone()),
            Form(super::LoginData {
                email: "does-not-exist@example.com".into(),
                password: "invalid-password".into(),
            }),
        )
        .await
        .unwrap()
        .into_response();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let html = response.into_html().await;
        html.element("aside.error")
            .contains_text("Invalid username or password");
        html.elements("input[name=email]").exists();
        html.elements("input[name=password]").exists();
    }

    #[tokio::test]
    async fn test_login_submit_success() {
        let (_db, pool) = crate::test::PostgresContainer::init().await;
        let encoding_key = State(jsonwebtoken::EncodingKey::from_secret(b"secret"));

        let user = crate::models::user::create(
            &pool,
            NewUser {
                email: "my-user@example.com".into(),
                role: UserRole::Manager,
                session_revoke_token: "".into(),
                activation_token: "some-token".into(),
                activation_expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            },
        )
        .await
        .unwrap();
        crate::models::authentication_method::create(
            &pool,
            user.id,
            AuthenticationVariant::Password(PasswordAuthentication::new("valid-password").unwrap()),
        )
        .await
        .unwrap();

        crate::models::user::activate_user(&pool, user.id)
            .await
            .unwrap();

        let response = crate::routes::auth::login_submit(
            None,
            AppContext::default(),
            CookieJar::new(),
            encoding_key.clone(),
            State(pool.clone()),
            Form(super::LoginData {
                email: "my-user@example.com".into(),
                password: "valid-password".into(),
            }),
        )
        .await
        .unwrap()
        .into_response();
        assert_eq!(response.status(), axum::http::StatusCode::SEE_OTHER);
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::LOCATION)
                .unwrap(),
            "/"
        );
        assert!(
            response
                .headers()
                .get(axum::http::header::SET_COOKIE)
                .is_some()
        );
    }

    /// A mailer that is never used by the tests, but is required to call the
    /// register_submit handler.
    fn test_mailer() -> Mailer {
        Mailer::new(
            MailTransport::from_url("smtp://localhost:25")
                .unwrap()
                .build(),
            "noreply@example.com".parse().unwrap(),
        )
    }

    /// A database pool that connects lazily, for tests that never touch it.
    fn test_lazy_pool() -> sqlx::PgPool {
        sqlx::PgPool::connect_lazy("postgres://localhost:5432/unused").unwrap()
    }

    /// A register form that passes every check except the captcha related
    /// fields, without requiring a database (the invalid email short-circuits
    /// before the existence lookup).
    fn register_form_without_captcha() -> super::RegisterForm {
        super::RegisterForm {
            email: "not-an-email".into(),
            password: "some-password".into(),
            confirm_password: "some-password".into(),
            accept_terms: true,
            captcha_challenge: String::new(),
            captcha_nonce: String::new(),
            website: String::new(),
        }
    }

    async fn submit_register(
        config: AppConfig,
        captcha_jar: PrivateCookieJar,
        data: super::RegisterForm,
    ) -> axum::response::Response {
        crate::routes::auth::register_submit(
            None,
            AppContext::default(),
            State(test_lazy_pool()),
            State(jsonwebtoken::EncodingKey::from_secret(b"secret")),
            State(test_mailer()),
            State(config),
            CookieJar::new(),
            captcha_jar,
            Form(data),
        )
        .await
        .unwrap()
        .into_response()
    }

    fn captcha_cookie_header(response: &axum::response::Response) -> String {
        response
            .headers()
            .get_all(axum::http::header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap())
            .filter(|v| v.starts_with(&format!("{}=", captcha::CAPTCHA_COOKIE_NAME)))
            .collect()
    }

    #[tokio::test]
    async fn test_register_page_issues_challenge() {
        let response = crate::routes::auth::register(
            None,
            AppContext::default(),
            State(AppConfig::default()),
            PrivateCookieJar::new(Key::generate()),
        )
        .await
        .into_response();
        assert!(response.status().is_success());

        // a challenge cookie is set
        assert!(!captcha_cookie_header(&response).is_empty());

        let html = response.into_html().await;

        // the challenge and its parameters are embedded for the solver script
        let challenge_input = html.element("input[name=captcha_challenge]");
        assert_eq!(challenge_input[0].attr("value").unwrap().len(), 32);
        let form = html.element("form#register-form");
        assert_eq!(form[0].attr("data-captcha-difficulty"), Some("5"));
        assert_eq!(form[0].attr("data-captcha-mem"), Some("8192"));
        assert_eq!(form[0].attr("data-captcha-time"), Some("1"));
        html.element("input[name=captcha_nonce]").exists();
        html.element("input[name=website]").exists();
        html.element("script[src='/assets/captcha.js']").exists();
        html.element("script[src='/assets/argon2-bundled.min.js']")
            .exists();
    }

    #[tokio::test]
    async fn test_register_submit_rejects_missing_captcha() {
        let response = submit_register(
            AppConfig::default(),
            PrivateCookieJar::new(Key::generate()),
            register_form_without_captcha(),
        )
        .await;
        assert_eq!(response.status(), axum::http::StatusCode::OK);

        // a fresh challenge is issued for the retry
        assert!(!captcha_cookie_header(&response).is_empty());

        let html = response.into_html().await;
        html.element("aside.error").contains_text("anti-spam check");
    }

    #[tokio::test]
    async fn test_register_submit_rejects_replayed_challenge() {
        // a cookie jar that no longer contains the challenge, as after a
        // previous submission consumed it
        let jar = PrivateCookieJar::new(Key::generate());
        let (jar, challenge) = captcha::issue_challenge(jar, captcha::PowParams::default());
        let jar = jar.remove(Cookie::from(captcha::CAPTCHA_COOKIE_NAME));

        let response = submit_register(
            AppConfig::default(),
            jar,
            super::RegisterForm {
                captcha_challenge: challenge.challenge,
                captcha_nonce: "0".into(),
                ..register_form_without_captcha()
            },
        )
        .await;

        let html = response.into_html().await;
        html.element("aside.error").contains_text("anti-spam check");
    }

    #[tokio::test]
    async fn test_register_submit_rejects_filled_honeypot() {
        let mut config = AppConfig::default();
        config.captcha_params.difficulty = 0;

        let jar = PrivateCookieJar::new(Key::generate());
        let (jar, challenge) = captcha::issue_challenge(jar, config.captcha_params);

        let response = submit_register(
            config,
            jar,
            super::RegisterForm {
                captcha_challenge: challenge.challenge,
                captcha_nonce: "0".into(),
                website: "https://spam.example.com".into(),
                ..register_form_without_captcha()
            },
        )
        .await;

        let html = response.into_html().await;
        html.element("aside.error").contains_text("anti-spam check");
    }

    #[tokio::test]
    async fn test_register_submit_accepts_valid_captcha() {
        let mut config = AppConfig::default();
        config.captcha_params.difficulty = 0;

        let jar = PrivateCookieJar::new(Key::generate());
        let (jar, challenge) = captcha::issue_challenge(jar, config.captcha_params);

        // at difficulty 0 any nonce solves the challenge; the invalid email
        // still fails, proving the captcha check itself passed
        let response = submit_register(
            config,
            jar,
            super::RegisterForm {
                captcha_challenge: challenge.challenge,
                captcha_nonce: "0".into(),
                ..register_form_without_captcha()
            },
        )
        .await;
        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let html = response.into_html().await;
        html.element("aside.error")
            .contains_text("fix the invalid fields");
    }
}
