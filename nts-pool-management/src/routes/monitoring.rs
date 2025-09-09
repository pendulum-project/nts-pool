use std::time::Duration;

use axum::{
    Json,
    body::{Body, to_bytes},
    extract::State,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};

use crate::{AppState, error::AppError, models};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
enum IpVersion {
    IpV4,
    IpV6,
}

#[derive(Serialize, Deserialize)]
struct ProbeControlCommand {
    timesources: Vec<(IpVersion, String)>,
    poolke: String,
    result_endpoint: String,
    result_batchsize: usize,
    result_max_waittime: Duration,
    update_interval: Duration,
    probe_interval: Duration,
    nts_timeout: Duration,
    ntp_timeout: Duration,
}

pub async fn get_work(State(state): State<AppState>) -> Result<impl IntoResponse, AppError> {
    let timesources = models::time_source::not_deleted(&state.db).await?;

    Ok(Json(ProbeControlCommand {
        timesources: timesources
            .iter()
            .flat_map(|ts| {
                [
                    (IpVersion::IpV4, ts.id.to_string()),
                    (IpVersion::IpV6, ts.id.to_string()),
                ]
                .into_iter()
            })
            .collect(),
        poolke: state.config.poolke_name,
        result_endpoint: format!("{}/monitoring/submit", state.config.base_url),
        result_batchsize: 4,
        result_max_waittime: Duration::from_secs(60),
        update_interval: Duration::from_secs(60),
        probe_interval: Duration::from_secs(4),
        nts_timeout: Duration::from_secs(1),
        ntp_timeout: Duration::from_secs(1),
    }))
}

pub async fn post_results(data: Body) {
    let body_bytes = to_bytes(data, usize::MAX).await.unwrap_or_default();
    println!(
        "Received monitoring result: {}",
        std::str::from_utf8(&body_bytes).unwrap_or("invalid utf8")
    )
}
