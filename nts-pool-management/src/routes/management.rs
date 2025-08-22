use askama::Template;
use axum::{
    Form,
    extract::{Path, State},
    response::IntoResponse,
};

use crate::{
    AppState,
    auth::Manager,
    context::AppContext,
    error::AppError,
    models::time_source::{self, NewTimeSourceForm, TimeSource, TimeSourceId},
    templates::{HtmlTemplate, filters},
};

#[derive(Template)]
#[template(path = "management/dashboard.html.j2")]
struct DashboardTemplate {
    app: AppContext,
}

pub async fn dashboard(_user: Manager, app: AppContext) -> impl IntoResponse {
    HtmlTemplate(DashboardTemplate { app })
}

#[derive(Template)]
#[template(path = "management/time_sources_page.html.j2")]
struct TimeSourcesPageTemplate {
    app: AppContext,
    time_sources: Vec<TimeSource>,
}

pub async fn time_sources(
    user: Manager,
    app: AppContext,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    let time_sources = time_source::by_user(&state.db, user.id).await?;
    Ok(HtmlTemplate(TimeSourcesPageTemplate { app, time_sources }))
}

pub async fn create_time_source(
    user: Manager,
    app: AppContext,
    State(state): State<AppState>,
    Form(new_time_source): Form<NewTimeSourceForm>,
) -> Result<impl IntoResponse, AppError> {
    time_source::create(&state.db, user.id, new_time_source.try_into()?).await?;

    let time_sources = time_source::by_user(&state.db, user.id).await?;

    Ok(HtmlTemplate(TimeSourcesPageTemplate { app, time_sources }))
}

pub async fn delete_time_source(
    user: Manager,
    app: AppContext,
    Path(time_source_id): Path<TimeSourceId>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    time_source::delete(&state.db, user.id, time_source_id).await?;
    let time_sources = time_source::by_user(&state.db, user.id).await?;
    Ok(HtmlTemplate(TimeSourcesPageTemplate { app, time_sources }))
}

#[derive(Template)]
#[template(path = "management/dns_zones_page.html.j2")]
struct DnsZonesPageTemplate {
    app: AppContext,
}

pub async fn dns_zones(_user: Manager, app: AppContext) -> impl IntoResponse {
    HtmlTemplate(DnsZonesPageTemplate { app })
}
