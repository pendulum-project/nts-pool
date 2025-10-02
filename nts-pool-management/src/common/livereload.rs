use axum::{
    Router,
    http::{
        StatusCode,
        header::{CONTENT_LENGTH, CONTENT_TYPE},
    },
    response::IntoResponse,
};

/// Livereload routes and handlers
pub(crate) fn livereload_router() -> Router {
    Router::new()
        .route("/livereload/poll.js", axum::routing::get(poll_js_handler))
        .route("/livereload/poll", axum::routing::get(poll_handler))
        .route("/livereload/healthy", axum::routing::get(healthy_handler))
}

/// Serves the poll.js script
async fn poll_js_handler() -> impl IntoResponse {
    let poll_js = include_str!("../../assets/poll.js");

    (
        [
            (CONTENT_TYPE, "text/javascript".to_string()),
            (CONTENT_LENGTH, poll_js.len().to_string()),
        ],
        poll_js,
    )
}

/// Health check endpoint for livereload, requested every 500ms by the livereload.js script when the backend is down
async fn healthy_handler() -> StatusCode {
    StatusCode::OK
}

/// Long-polling endpoint for livereload, requested once by the livereload.js script
async fn poll_handler() -> StatusCode {
    tokio::time::sleep(std::time::Duration::from_secs(30)).await;

    StatusCode::OK
}
