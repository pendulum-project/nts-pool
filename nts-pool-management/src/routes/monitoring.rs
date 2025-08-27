use std::time::Duration;

use axum::{
    Json,
    body::{Body, to_bytes},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct ProbeControlCommand {
    timesources: Vec<String>,
    poolke: String,
    result_endpoint: String,
    result_batchsize: usize,
    result_max_waittime: Duration,
    update_interval: Duration,
    probe_interval: Duration,
    nts_timeout: Duration,
    ntp_timeout: Duration,
}

pub async fn get_work() -> impl IntoResponse {
    Json(ProbeControlCommand {
        timesources: vec!["UUID-A".into(), "UUID-B".into()],
        poolke: "localhost".into(),
        result_endpoint: "http://localhost:3000/monitoring/submit".into(),
        result_batchsize: 4,
        result_max_waittime: Duration::from_secs(60),
        update_interval: Duration::from_secs(60),
        probe_interval: Duration::from_secs(4),
        nts_timeout: Duration::from_secs(1),
        ntp_timeout: Duration::from_secs(1),
    })
}

pub async fn post_results(data: Body) {
    let body_bytes = to_bytes(data, usize::MAX).await.unwrap_or_default();
    println!(
        "Received monitoring result: {}",
        std::str::from_utf8(&body_bytes).unwrap_or("invalid utf8")
    )
}
