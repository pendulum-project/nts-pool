use askama::Template;
use axum::{Form, extract::State, response::IntoResponse};

use crate::{
    auth::UserSession, error::AppError, models::time_source::{self, NewTimeSource}, templates::{filters, AppVars, HtmlTemplate}, AppState
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
    time_sources: Vec<String>,
}

pub async fn time_sources(_session: UserSession) -> impl IntoResponse {
    let time_sources = vec![
        "time.cikzh.nl".to_string(),
        "sth2.ntp.netnod.se".to_string(),
        "time.tweedegolf.nl".to_string(),
    ];
    HtmlTemplate(TimeSourcesPageTemplate {
        app: AppVars::from_current_task(),
        time_sources,
    })
}

pub async fn create_time_source(
    session: UserSession,
    State(state): State<AppState>,
    Form(new_time_source): Form<NewTimeSource>,
) -> Result<impl IntoResponse, AppError> {
    time_source::create(&state.db, session.user_id, new_time_source)
        .await
        .unwrap();
    Ok(())
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
