use askama::Template;
use axum::response::IntoResponse;

use crate::{
    auth::UserSession,
    templates::{HtmlTemplate, filters},
};

#[derive(Template)]
#[template(path = "management/dashboard.html.j2")]
struct DashboardTemplate {
    session: Option<UserSession>,
}

pub async fn dashboard(session: UserSession) -> impl IntoResponse {
    HtmlTemplate(DashboardTemplate {
        session: Some(session),
    })
}

#[derive(Template)]
#[template(path = "management/time_sources_page.html.j2")]
struct TimeSourcesPageTemplate {
    session: Option<UserSession>,
    time_sources: Vec<String>,
}

pub async fn time_sources(session: UserSession) -> impl IntoResponse {
    let time_sources = vec![
        "time.cikzh.nl".to_string(),
        "sth2.ntp.netnod.se".to_string(),
        "time.tweedegolf.nl".to_string(),
    ];
    HtmlTemplate(TimeSourcesPageTemplate {
        session: Some(session),
        time_sources,
    })
}

#[derive(Template)]
#[template(path = "management/dns_zones_page.html.j2")]
struct DnsZonesPageTemplate {
    session: Option<UserSession>,
}

pub async fn dns_zones(session: UserSession) -> impl IntoResponse {
    HtmlTemplate(DnsZonesPageTemplate {
        session: Some(session),
    })
}
