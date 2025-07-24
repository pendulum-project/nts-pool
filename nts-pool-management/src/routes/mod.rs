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
        .route("/login", get(login_page))
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
