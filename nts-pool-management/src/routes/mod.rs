use askama::Template;
use axum::{
    Form, Json, Router,
    extract::State,
    response::IntoResponse,
    routing::{get, post},
};
use management::TIME_SOURCES_ENDPOINT;
use nts_pool_shared::KeyExchangeServer;
use serde::Deserialize;

use crate::{
    AppState,
    auth::AuthenticatedInternal,
    context::AppContext,
    error::AppError,
    models,
    templates::{HtmlTemplate, filters, not_found_page},
};

mod admin;
pub(crate) mod auth;
mod management;
mod monitoring;

pub fn create_router() -> Router<AppState> {
    Router::new()
        .route("/", get(index))
        .route("/terms", get(terms))
        .route("/use", get(use_get))
        .route("/use", post(use_post))
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
        .route("/admin/monitors", get(admin::monitors))
        .route("/admin/monitors/new", post(admin::create_monitor))
        .route("/admin/monitors/{id}", get(admin::monitor))
        .route(
            "/admin/monitors/{id}/regenerate_key",
            post(admin::rekey_monitor),
        )
        .route(
            TIME_SOURCES_ENDPOINT,
            get(management::time_sources).post(management::create_time_source),
        )
        .route(
            "/management/time-sources/{id}/update",
            post(management::update_time_source), // HTML form only supports GET and POST
        )
        .route(
            "/management/time-sources/{id}/rekey",
            post(management::rekey_time_source),
        )
        .route(
            "/management/time-sources/{id}/delete",
            post(management::delete_time_source), // HTML form only supports GET and POST
        )
        .route("/management", get(management::dashboard))
        .route("/monitoring/get_work", get(monitoring::get_work))
        .route("/monitoring/submit", post(monitoring::post_results))
        .fallback(async |app: AppContext| not_found_page(app))
}

pub fn create_internal_router() -> Router<AppState> {
    Router::new()
        .route("/poolke_servers", get(poolke_servers))
        .route("/monitor_keys", get(monitor_keys))
}

#[derive(Template)]
#[template(path = "index.html.j2")]
struct IndexTemplate {
    app: AppContext,
}

pub async fn index(app: AppContext) -> impl IntoResponse {
    HtmlTemplate(IndexTemplate { app })
}

#[derive(Template)]
#[template(path = "terms.html.j2")]
struct TermsTemplate {
    app: AppContext,
}

pub async fn terms(app: AppContext) -> impl IntoResponse {
    HtmlTemplate(TermsTemplate { app })
}

#[derive(Template)]
#[template(path = "use.html.j2")]
struct UseTemplate {
    app: AppContext,
    accepts_terms: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct UseForm {
    pub accept: Option<String>,
}

pub async fn use_post(app: AppContext, Form(formdata): Form<UseForm>) -> impl IntoResponse {
    HtmlTemplate(UseTemplate {
        app,
        accepts_terms: formdata.accept == Some("true".into()),
    })
}

pub async fn use_get(app: AppContext) -> impl IntoResponse {
    HtmlTemplate(UseTemplate {
        app,
        accepts_terms: false,
    })
}

pub async fn poolke_servers(
    State(state): State<AppState>,
    _authentication: AuthenticatedInternal,
) -> Result<impl IntoResponse, AppError> {
    let timesources = models::time_source::not_deleted(&state.db).await?;
    Ok(Json(
        timesources
            .into_iter()
            .map(|ts| KeyExchangeServer {
                uuid: ts.id.to_string(),
                domain: ts.hostname,
                port: ts.port.map(|p| p.into()).unwrap_or(4460),
                base_key_index: 0,
                randomizer: ts.auth_token_randomizer,
                weight: Some(ts.weight.try_into().unwrap_or(1)),
                regions: vec![],
                ipv4_capable: Some(ts.ipv4_score > 10.0),
                ipv6_capable: Some(ts.ipv6_score > 10.0),
            })
            .collect::<Vec<_>>(),
    ))
}

pub async fn monitor_keys(
    State(state): State<AppState>,
    _authentication: AuthenticatedInternal,
) -> Result<impl IntoResponse, AppError> {
    Ok(Json(models::monitor::list_keys(&state.db).await?))
}
