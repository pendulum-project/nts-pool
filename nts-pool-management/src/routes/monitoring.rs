use std::time::Duration;

use axum::{
    Json,
    body::{Body, to_bytes},
    extract::State,
    response::IntoResponse,
};
use nts_pool_shared::{IpVersion, ProbeControlCommand};

use crate::{
    AppState,
    auth::AuthenticatedMonitor,
    error::AppError,
    models::{self, monitor::Monitor},
};

pub async fn get_work(
    _monitor: AuthenticatedMonitor,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
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

pub async fn post_results(monitor: AuthenticatedMonitor, data: Body) {
    let body_bytes = to_bytes(data, usize::MAX).await.unwrap_or_default();
    let monitor: Monitor = monitor.into();
    println!(
        "Received monitoring result from {}: {}",
        monitor.name,
        std::str::from_utf8(&body_bytes).unwrap_or("invalid utf8")
    )
}
