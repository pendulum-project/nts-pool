use askama::Template;
use axum::{Router, response::IntoResponse, routing::get};

use crate::{
    AppState,
    auth::UserSession,
    templates::{HtmlTemplate, not_found_page},
};

mod login;
mod management;

pub fn create_router() -> Router<AppState> {
    Router::new()
        .route("/", get(index))
        .route("/login", get(login::login).post(login::login_submit))
        .route("/logout", get(login::logout))
        .route("/management/time-sources", get(management::time_sources))
        .route("/management/dns-zones", get(management::dns_zones))
        .route("/management", get(management::dashboard))
        .fallback(async |session: Option<UserSession>| not_found_page(session))
}

#[derive(Template)]
#[template(path = "index.html.j2")]
struct IndexTemplate {
    session: Option<UserSession>,
}

pub async fn index(session: Option<UserSession>) -> impl IntoResponse {
    HtmlTemplate(IndexTemplate { session })
}
