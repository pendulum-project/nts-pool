use askama::Template;
use axum::{
    Router,
    response::IntoResponse,
    routing::{get, post},
};

use crate::{
    AppState,
    context::AppContext,
    templates::{HtmlTemplate, filters, not_found_page},
};

mod admin;
pub(crate) mod auth;
mod management;
mod monitoring;

pub fn create_router() -> Router<AppState> {
    Router::new()
        .route("/", get(index))
        .route("/login", get(auth::login).post(auth::login_submit))
        .route("/register", get(auth::register).post(auth::register_submit))
        .route(
            "/register/activate",
            get(auth::register_activate).post(auth::register_activate_submit),
        )
        .route(
            "/login/forgot-password",
            get(auth::forgot_password).post(auth::forgot_password_submit),
        )
        .route(
            "/login/reset-password",
            get(auth::reset_password).post(auth::reset_password_submit),
        )
        .route("/logout", get(auth::logout))
        .route("/admin", get(admin::overview))
        .route("/admin/users", get(admin::users))
        .route("/admin/users/{id}/block", post(admin::user_block))
        .route("/admin/users/{id}/unblock", post(admin::user_unblock))
        .route("/admin/users/{id}/login-as", post(admin::login_as))
        .route(
            "/management/time-sources",
            get(management::time_sources).post(management::create_time_source),
        )
        .route(
            "/management/time-sources/{id}/delete",
            // HTML form only supports GET and POST
            post(management::delete_time_source),
        )
        .route("/management/dns-zones", get(management::dns_zones))
        .route("/management", get(management::dashboard))
        .route("/monitoring/get_work", get(monitoring::get_work))
        .route("/monitoring/submit", post(monitoring::post_results))
        .fallback(async |app: AppContext| not_found_page(app))
}

#[derive(Template)]
#[template(path = "index.html.j2")]
struct IndexTemplate {
    app: AppContext,
}

pub async fn index(app: AppContext) -> impl IntoResponse {
    HtmlTemplate(IndexTemplate { app })
}
