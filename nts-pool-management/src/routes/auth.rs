use std::str::FromStr;

use askama::Template;
use axum::{
    Form,
    extract::{Query, State},
    response::{IntoResponse, Redirect},
};
use axum_extra::extract::CookieJar;
use eyre::{Context, OptionExt};
use jsonwebtoken::EncodingKey;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use crate::{
    auth::{
        AUTH_COOKIE_NAME, UnsafeLoggedInUser, is_too_large_password, is_valid_password, login_into,
    },
    email::Mailer,
    error::AppError,
    models::{
        authentication_method::{AuthenticationVariant, PasswordAuthentication},
        user::{NewUser, UserRole},
    },
    templates::{AppVars, HtmlTemplate, filters},
};

#[derive(Template)]
#[template(path = "login/login.html.j2")]
struct LoginPageTemplate {
    app: AppVars,
    login_error: bool,
}

pub async fn login(user: Option<UnsafeLoggedInUser>) -> impl IntoResponse {
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
        app: AppVars::from_current_task(),
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
    cookie_jar: CookieJar,
    State(encoding_key): State<EncodingKey>,
    State(db): State<PgPool>,
    Form(data): Form<LoginData>,
) -> Result<impl IntoResponse, AppError> {
    match login_submit_internal(auth_user, cookie_jar, encoding_key, db, data).await {
        Ok(response) => Ok(response.into_response()),
        Err(e) if e.is::<InvalidCredentialsError>() => Ok(HtmlTemplate(LoginPageTemplate {
            app: AppVars::from_current_task(),
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
        .await?
        .ok_or_eyre(InvalidCredentialsError)?;
    let password_method =
        crate::models::authentication_method::get_password_authentication_method(&db, user.id)
            .await?
            .ok_or_eyre(InvalidCredentialsError)?;

    // prevent too large password from being used
    if is_too_large_password(&data.password) {
        return Err(InvalidCredentialsError.into());
    }

    if password_method.verify(&data.password)? {
        if user.is_disabled() {
            return Err(eyre::eyre!("User is disabled").into());
        }

        cookie_jar = login_into(&user, None, &encoding_key, cookie_jar)?;
        crate::models::user::update_last_login(&db, user.id).await?;
    } else {
        return Err(InvalidCredentialsError.into());
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

pub async fn logout(cookie_jar: CookieJar) -> Result<impl IntoResponse, AppError> {
    let cookie_jar = cookie_jar.remove(AUTH_COOKIE_NAME);
    Ok((cookie_jar, Redirect::to("/")))
}

#[derive(Template)]
#[template(path = "login/register.html.j2")]
struct RegisterPageTemplate {
    app: AppVars,
    fields_with_errors: Vec<&'static str>,
    data_email: Option<String>,
}

pub async fn register(user: Option<UnsafeLoggedInUser>) -> impl IntoResponse {
    if let Some(user) = user {
        if !user.is_activated() {
            return Redirect::to("/register/activate").into_response();
        } else if user.is_disabled() {
            return Redirect::to("/logout").into_response();
        } else {
            return Redirect::to("/").into_response();
        }
    }

    HtmlTemplate(RegisterPageTemplate {
        app: AppVars::from_current_task(),
        fields_with_errors: Vec::new(),
        data_email: None,
    })
    .into_response()
}

#[derive(Debug, Deserialize)]
pub struct RegisterForm {
    email: String,
    password: String,
    confirm_password: String,
    accept_terms: bool,
}

pub async fn register_submit(
    auth_user: Option<UnsafeLoggedInUser>,
    State(pool): State<PgPool>,
    State(encoding_key): State<EncodingKey>,
    State(mailer): State<Mailer>,
    cookie_jar: CookieJar,
    Form(data): Form<RegisterForm>,
) -> Result<impl IntoResponse, AppError> {
    if auth_user.is_some() {
        return Ok(Redirect::to("/").into_response());
    }

    let mut fields_with_errors = Vec::new();

    if !data.email.contains('@') || lettre::Address::from_str(&data.email).is_err() {
        fields_with_errors.push("email");

    // check if email is already registered
    } else if crate::models::user::get_by_email(&pool, &data.email)
        .await?
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
        Ok(HtmlTemplate(RegisterPageTemplate {
            app: AppVars::from_current_task(),
            fields_with_errors,
            data_email: Some(data.email),
        })
        .into_response())
    } else {
        // we start by storing the new user in the database
        let (activation_token, activation_expires_at) = crate::auth::generate_activation_token();
        let mut tx = pool.begin().await?;
        let user = crate::models::user::create(
            &mut *tx,
            NewUser {
                email: data.email,
                role: UserRole::Manager,
                activation_token,
                activation_expires_at,
            },
        )
        .await?;

        crate::models::authentication_method::create(
            &mut *tx,
            user.id,
            AuthenticationVariant::Password(PasswordAuthentication::new(&data.password)?),
        )
        .await?;

        tx.commit().await?;

        // we send an activation email to the user
        crate::email::send_activation_email(&mailer, &user).await?;

        // we log the user in and send them to the confirmation page, waiting for them entering the activation token
        let cookie_jar = crate::auth::login_into(&user, None, &encoding_key, cookie_jar)?;

        Ok((cookie_jar, Redirect::to("/register/activate")).into_response())
    }
}

#[derive(Template)]
#[template(path = "login/register_activate.html.j2")]
struct RegisterActivatePageTemplate {
    app: AppVars,
    has_code_error: bool,
    resend_reason: Option<ResendReason>,
}

pub async fn register_activate(
    user: UnsafeLoggedInUser,
    Query(query): Query<RegisterActivateQuery>,
) -> impl IntoResponse {
    if user.is_disabled() {
        return Redirect::to("/logout").into_response();
    }

    if user.is_activated() {
        return Redirect::to("/").into_response();
    }

    HtmlTemplate(RegisterActivatePageTemplate {
        app: AppVars::from_current_task(),
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
            app: AppVars::from_current_task(),
            has_code_error: true,
            resend_reason: None,
        })
        .into_response())
    }
}

#[derive(Template)]
#[template(path = "login/forgot_password.html.j2")]
struct ForgotPasswordPageTemplate {
    app: AppVars,
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
        app: AppVars::from_current_task(),
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

        crate::email::send_password_reset_email(&mailer, &user, &token).await?;
    }
    // Implement forgot password logic here
    Ok(Redirect::to("/login/forgot-password?requested=true").into_response())
}

#[derive(Template)]
#[template(path = "login/password_reset.html.j2")]
struct PasswordResetPageTemplate {
    app: AppVars,
    password_error: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ResetPasswordQuery {
    pub token: String,
    pub email: String,
}

pub async fn reset_password(
    user: Option<UnsafeLoggedInUser>,
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
        app: AppVars::from_current_task(),
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
        .await?
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
            app: AppVars::from_current_task(),
            password_error: true,
        })
        .into_response());
    }

    password_auth.update_password(&form.password)?;

    crate::models::authentication_method::update_variant(&pool, auth_row.id, auth_row.variant.0)
        .await?;

    Ok(Redirect::to("/login").into_response())
}
