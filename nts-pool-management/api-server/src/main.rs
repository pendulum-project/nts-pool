use axum::{Json, Router, routing::get};
use nts_pool_management_shared::Servers;

async fn root() -> Json<Servers> {
    Json(Servers {
        servers: vec![
            "Server 1".to_string(),
            "Server 2".to_string(),
            "Server 3".to_string(),
        ],
    })
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let router = Router::new().route("/", get(root));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3033").await.unwrap();
    axum::serve(listener, router).await.unwrap();
}
