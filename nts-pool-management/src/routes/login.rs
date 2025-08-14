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
    auth::{AUTH_COOKIE_NAME, UnsafeLoggedInUser, login_into},
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
    }

    // check if email is already registered
    if crate::models::user::get_by_email(&pool, &data.email)
        .await?
        .is_some()
    {
        fields_with_errors.push("email");
    }

    if data.password != data.confirm_password {
        fields_with_errors.push("password");
        fields_with_errors.push("confirm_password");
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
