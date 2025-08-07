use askama::Template;
use axum::{Router, response::IntoResponse, routing::get};

use crate::{
    AppState,
    templates::{AppVars, HtmlTemplate, filters, not_found_page},
};

mod admin;
mod login;
mod management;

pub fn create_router() -> Router<AppState> {
    Router::new()
        .route("/", get(index))
        .route("/login", get(login::login).post(login::login_submit))
        .route("/logout", get(login::logout))
        .route("/admin", get(admin::overview))
        .route("/management/time-sources", get(management::time_sources).post(management::create_time_source))
        .route("/management/dns-zones", get(management::dns_zones))
        .route("/management", get(management::dashboard))
        .fallback(async || not_found_page())
}

#[derive(Template)]
#[template(path = "index.html.j2")]
struct IndexTemplate {
    app: AppVars,
}

pub async fn index() -> impl IntoResponse {
    HtmlTemplate(IndexTemplate {
        app: AppVars::from_current_task(),
    })
}
