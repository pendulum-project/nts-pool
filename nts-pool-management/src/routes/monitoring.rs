use axum::{Json, extract::State, response::IntoResponse};
use eyre::Context;
use nts_pool_shared::{IpVersion, ProbeControlCommand, ProbeResult};

use crate::{
    AppState,
    auth::AuthenticatedMonitor,
    error::AppError,
    models::{
        self,
        monitor::{Monitor, NewSample},
        time_source::TimeSourceId,
    },
    scoring::score_sample,
};

pub async fn get_work(
    _monitor: AuthenticatedMonitor,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    let timesources = models::time_source::list(&state.db).await?;

    Ok(Json(ProbeControlCommand {
        timesources: timesources
            .iter()
            .flat_map(|ts| {
                [
                    (IpVersion::Ipv4, ts.id.to_string()),
                    (IpVersion::Ipv6, ts.id.to_string()),
                ]
                .into_iter()
            })
            .collect(),
        poolke: state.config.poolke_name,
        result_endpoint: format!("{}/monitoring/submit", state.config.base_url),
        result_batchsize: state.config.monitor_result_batchsize,
        result_max_waittime: state.config.monitor_result_batchtime,
        update_interval: state.config.monitor_update_interval,
        probe_interval: state.config.monitor_probe_interval,
        nts_timeout: state.config.monitor_nts_timeout,
        ntp_timeout: state.config.monitor_ntp_timeout,
    }))
}

pub async fn post_results(
    monitor: AuthenticatedMonitor,
    State(state): State<AppState>,
    Json(samples): Json<Vec<((IpVersion, TimeSourceId), ProbeResult)>>,
) -> Result<(), AppError> {
    let monitor: Monitor = monitor.into();

    for ((protocol, time_source_id), probe_result) in samples {
        let scored_step = score_sample(&probe_result);

        models::monitor::add_sample(
            &state.db,
            NewSample {
                time_source_id,
                protocol,
                monitor_id: monitor.id,
                step: scored_step.step,
                max_score: scored_step.max_score,
                raw_sample: probe_result,
            },
        )
        .await
        .wrap_err("Could not store sample in database")?;
    }

    Ok(())
}
