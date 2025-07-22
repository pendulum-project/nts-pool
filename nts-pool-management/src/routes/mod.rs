use askama::Template;
use axum::{
    Router,
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::get,
};

use crate::AppState;

pub fn create_router() -> Router<AppState> {
    Router::new()
        .route("/", get(root))
        .route("/servers", get(servers_page))
        .route("/dns_zones", get(dns_zones_page))
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
#[template(path = "index.html")]
struct RootTemplate;

pub async fn root() -> impl IntoResponse {
    HtmlTemplate(RootTemplate)
}

#[derive(Template)]
#[template(path = "servers_page.html")]
struct ServersPageTemplate {
    servers: Vec<String>,
}

pub async fn servers_page() -> impl IntoResponse {
    let servers = vec![
        "Server 1".to_string(),
        "Server 2".to_string(),
        "Server 3".to_string(),
    ];
    HtmlTemplate(ServersPageTemplate { servers })
}

#[derive(Template)]
#[template(path = "dns_zones_page.html")]
struct DnsZonesPageTemplate;

pub async fn dns_zones_page() -> impl IntoResponse {
    HtmlTemplate(DnsZonesPageTemplate)
}

#[derive(Template)]
#[template(path = "not_found_page.html")]
struct NotFoundPageTemplate;

pub async fn not_found_page() -> impl IntoResponse {
    (StatusCode::NOT_FOUND, HtmlTemplate(NotFoundPageTemplate))
}
