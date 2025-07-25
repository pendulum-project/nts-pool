use askama::Template;
use axum::{
    Router,
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::get,
};
use nts_pool_management_shared::Servers;

#[derive(Template)]
#[template(path = "index.html")]
struct RootTemplate;

#[derive(Template)]
#[template(path = "servers_page.html")]
struct ServersPageTemplate {
    servers: Vec<String>,
}

#[derive(Template)]
#[template(path = "dns_zones_page.html")]
struct DnsZonesPageTemplate;

#[derive(Template)]
#[template(path = "not_found_page.html")]
struct NotFoundPageTemplate;

struct HtmlTemplate<T>(T);
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

async fn root() -> impl IntoResponse {
    HtmlTemplate(RootTemplate)
}

async fn servers_page() -> impl IntoResponse {
    let response: Servers = reqwest::get(
        std::env::var("POOL_UI_API_URL").unwrap_or("http://localhost:3033".to_string()),
    )
    .await
    .unwrap()
    .json::<Servers>()
    .await
    .unwrap();
    HtmlTemplate(ServersPageTemplate {
        servers: response.servers,
    })
}

async fn dns_zones_page() -> impl IntoResponse {
    HtmlTemplate(DnsZonesPageTemplate)
}

async fn not_found_page() -> impl IntoResponse {
    HtmlTemplate(NotFoundPageTemplate)
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install default crypto provider");
    let router = Router::new()
        .nest_service(
            "/assets",
            tower_http::services::ServeDir::new(
                std::env::var("POOL_UI_ASSETS_DIR").unwrap_or("./assets".into()),
            ),
        )
        .route("/", get(root))
        .route("/servers", get(servers_page))
        .route("/dns-zones", get(dns_zones_page))
        .fallback(not_found_page);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, router).await.unwrap();
}
