use std::time::Duration;

use axum::{Json, response::IntoResponse};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct ProbeControlCommand {
    timesources: Vec<String>,
    poolke: String,
    update_interval: Duration,
    probe_interval: Duration,
    nts_timeout: Duration,
    ntp_timeout: Duration,
}

pub async fn get_work() -> impl IntoResponse {
    Json(ProbeControlCommand {
        timesources: vec!["UUID-A".into(), "UUID-B".into()],
        poolke: "localhost".into(),
        update_interval: Duration::from_secs(60),
        probe_interval: Duration::from_secs(4),
        nts_timeout: Duration::from_secs(1),
        ntp_timeout: Duration::from_secs(1),
    })
}
