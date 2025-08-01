use anyhow::anyhow;
use askama::Template;
use axum::{
    Form,
    extract::State,
    response::{IntoResponse, Redirect},
};
use axum_extra::extract::CookieJar;
use jsonwebtoken::EncodingKey;
use serde::Deserialize;
use sqlx::PgPool;

use crate::{
    auth::{AUTH_COOKIE_NAME, UserSession, login_into},
    error::AppError,
    templates::HtmlTemplate,
};

#[derive(Template)]
#[template(path = "login/login.html.j2")]
struct LoginPageTemplate {
    session: Option<UserSession>,
}

pub async fn login() -> impl IntoResponse {
    HtmlTemplate(LoginPageTemplate { session: None })
}

#[derive(Debug, Deserialize)]
pub struct LoginData {
    username: String,
    password: String,
}

pub async fn login_submit(
    mut cookie_jar: CookieJar,
    State(encoding_key): State<EncodingKey>,
    State(db): State<PgPool>,
    Form(data): Form<LoginData>,
) -> Result<impl IntoResponse, AppError> {
    let user = crate::models::user::get_by_email(&db, &data.username)
        .await?
        .ok_or(anyhow!("Failed to login"))?;
    let password_method =
        crate::models::authentication_method::get_password_authentication_method(&db, user.id)
            .await?
            .ok_or(anyhow!("Failed to login"))?;

    if password_method.verify(&data.password)? {
        cookie_jar = login_into(
            &user,
            std::time::Duration::from_secs(3600 * 24 * 14),
            &encoding_key,
            cookie_jar,
        )?;
    }

    Ok((cookie_jar, Redirect::to("/")))
}

pub async fn logout(cookie_jar: CookieJar) -> Result<impl IntoResponse, AppError> {
    let cookie_jar = cookie_jar.remove(AUTH_COOKIE_NAME);
    Ok((cookie_jar, Redirect::to("/")))
}
