use askama::Template;
use axum::{Form, extract::State, response::IntoResponse};

use crate::{
    AppState,
    auth::UserSession,
    error::AppError,
    models::time_source::{self, NewTimeSourceForm, TimeSource},
    templates::{AppVars, HtmlTemplate, filters},
};

#[derive(Template)]
#[template(path = "management/dashboard.html.j2")]
struct DashboardTemplate {
    app: AppVars,
}

pub async fn dashboard(_session: UserSession) -> impl IntoResponse {
    HtmlTemplate(DashboardTemplate {
        app: AppVars::from_current_task(),
    })
}

#[derive(Template)]
#[template(path = "management/time_sources_page.html.j2")]
struct TimeSourcesPageTemplate {
    app: AppVars,
    time_sources: Vec<TimeSource>,
}

pub async fn time_sources(
    session: UserSession,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    let time_sources = time_source::by_user(&state.db, session.user_id).await?;
    Ok(HtmlTemplate(TimeSourcesPageTemplate {
        app: AppVars::from_current_task(),
        time_sources,
    }))
}

pub async fn create_time_source(
    session: UserSession,
    State(state): State<AppState>,
    Form(new_time_source): Form<NewTimeSourceForm>,
) -> Result<impl IntoResponse, AppError> {
    time_source::create(&state.db, session.user_id, new_time_source.try_into()?)
        .await
        .unwrap();

    let time_sources = time_source::by_user(&state.db, session.user_id).await?;

    Ok(HtmlTemplate(TimeSourcesPageTemplate {
        app: AppVars::from_current_task(),
        time_sources,
    }))
}

#[derive(Template)]
#[template(path = "management/dns_zones_page.html.j2")]
struct DnsZonesPageTemplate {
    app: AppVars,
}

pub async fn dns_zones(_session: UserSession) -> impl IntoResponse {
    HtmlTemplate(DnsZonesPageTemplate {
        app: AppVars::from_current_task(),
    })
}
