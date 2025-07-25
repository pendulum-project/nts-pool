use anyhow::anyhow;
use askama::Template;
use axum::{
    Form, Router,
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::get,
};
use axum_extra::extract::CookieJar;
use jsonwebtoken::EncodingKey;
use serde::Deserialize;
use sqlx::PgPool;

use crate::{AppState, auth::login_into, error::AppError};

pub fn create_router() -> Router<AppState> {
    Router::new()
        .route("/", get(root))
        .route("/login", get(login_page).post(login_submit_page))
        .route("/servers", get(servers_page))
        .route("/dns-zones", get(dns_zones_page))
        .fallback(not_found_page)
}

pub struct HtmlTemplate<T>(T);
impl<T> IntoResponse for HtmlTemplate<T>
where
    T: Template,
{
    fn into_response(self) -> Response {
        match self.0.render() {
            Ok(html) => Html(html).into_response(),
            Err(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to render template. Error: {err}"),
            )
                .into_response(),
        }
    }
}

#[derive(Template)]
#[template(path = "index.html.j2")]
struct RootTemplate;

pub async fn root() -> impl IntoResponse {
    HtmlTemplate(RootTemplate)
}

#[derive(Template)]
#[template(path = "servers_page.html.j2")]
struct ServersPageTemplate {
    servers: Vec<String>,
}

pub async fn servers_page() -> impl IntoResponse {
    let servers = vec![
        "time.cikzh.nl".to_string(),
        "sth2.ntp.netnod.se".to_string(),
        "time.tweedegolf.nl".to_string(),
    ];
    HtmlTemplate(ServersPageTemplate { servers })
}

#[derive(Template)]
#[template(path = "dns_zones_page.html.j2")]
struct DnsZonesPageTemplate;

pub async fn dns_zones_page() -> impl IntoResponse {
    HtmlTemplate(DnsZonesPageTemplate)
}

#[derive(Template)]
#[template(path = "not_found_page.html.j2")]
struct NotFoundPageTemplate;

pub async fn not_found_page() -> impl IntoResponse {
    (StatusCode::NOT_FOUND, HtmlTemplate(NotFoundPageTemplate))
}

#[derive(Template)]
#[template(path = "login.html.j2")]
struct LoginPageTemplate;

pub async fn login_page() -> impl IntoResponse {
    HtmlTemplate(LoginPageTemplate)
}

#[derive(Debug, Deserialize)]
pub struct LoginData {
    username: String,
    password: String,
}

pub async fn login_submit_page(
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

    Ok((cookie_jar, HtmlTemplate(LoginPageTemplate)))
}
