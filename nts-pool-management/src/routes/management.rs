use std::collections::HashMap;

use askama::Template;
use axum::{
    Form,
    extract::{Path, Query, State},
    response::{IntoResponse, Redirect},
};
use chrono::{DateTime, Utc};
use nts_pool_shared::IpVersion;
use serde::Deserialize;
use serde_json::Value;

use crate::{
    AppState,
    auth::{self, AuthorizedUser},
    context::AppContext,
    cookies::CookieService,
    error::AppError,
    models::{
        monitor::MonitorId,
        time_source::{self, NewTimeSourceForm, TimeSource, TimeSourceId, UpdateTimeSourceForm},
    },
    templates::{HtmlTemplate, filters},
};

pub const TIME_SOURCES_ENDPOINT: &str = "/management/time-sources";

#[derive(Template)]
#[template(path = "management/time_sources_page.html.j2")]
struct TimeSourcesPageTemplate {
    app: AppContext,
    time_sources: Vec<TimeSource>,
}

pub async fn time_sources(
    user: AuthorizedUser,
    app: AppContext,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    let time_sources = time_source::by_user(&state.db, user.id).await?;
    Ok(HtmlTemplate(TimeSourcesPageTemplate { app, time_sources }))
}

#[derive(Debug)]
struct ScoreTableData {
    monitor: String,
    ipv4: f64,
    ipv6: f64,
}

struct DisplayLogRow {
    time: DateTime<Utc>,
    ke_status: String,
    ntp_from_ke_status: String,
    ntp_from_ntp_status: String,
    score: f64,
    raw_sample: Value,
}

#[derive(Template)]
#[template(path = "management/time_source_details.html.j2")]
struct TimeSourceInfoTemplate {
    app: AppContext,
    ts: TimeSource,
    log: Vec<DisplayLogRow>,
    scores: Vec<ScoreTableData>,
    monitors: Vec<String>,
    cur_monitor: Option<MonitorId>,
    cur_protocol: IpVersion,
}

#[derive(Deserialize)]
pub struct LogSelection {
    monitor: Option<MonitorId>,
    protocol: Option<IpVersion>,
}

fn extract_keyexchange_status(ke: &Value) -> Option<String> {
    ke.get("description")
        .and_then(|ke_status| ke_status.as_str())
        .and_then(|ke_status| {
            if !ke_status.is_empty() {
                Some(ke_status.to_owned())
            } else {
                None
            }
        })
        .or_else(|| {
            ke.get("status")
                .and_then(|ke_status| ke_status.as_str())
                .map(|ke_status| {
                    ke.get("exchange_duration")
                        .and_then(|v| v.as_f64())
                        .map(|v| format!("{} (duration: {:.1}ms)", ke_status, v * 1000.0))
                        .unwrap_or_else(|| ke_status.to_owned())
                })
        })
}

fn extract_ntp_status(ntp: &Value) -> Option<String> {
    ntp.get("status")
        .and_then(|ntp_status| ntp_status.as_str())
        .map(|ntp_status| {
            let rtt = ntp.get("roundtrip_duration").and_then(|v| v.as_f64());
            let offset = ntp.get("offset").and_then(|v| v.as_f64());

            match (rtt, offset) {
                (Some(rtt), Some(offset)) => format!(
                    "{} (RTT: {:.1}ms, offset: {:.1}ms)",
                    ntp_status,
                    rtt * 1000.0,
                    offset * 1000.0
                ),
                (Some(rtt), None) => format!("{} (RTT: {:.1}ms)", ntp_status, rtt * 1000.0),
                _ => ntp_status.to_owned(),
            }
        })
}

pub async fn time_source_info(
    Path(time_source_id): Path<TimeSourceId>,
    app: AppContext,
    State(state): State<AppState>,
    Query(log_choice): Query<LogSelection>,
) -> Result<impl IntoResponse, AppError> {
    let ts = time_source::details(&state.db, time_source_id).await?;
    let scores = time_source::scores(&state.db, time_source_id).await?;
    let cur_monitor = log_choice.monitor.or_else(|| scores.first().map(|v| v.id));
    let cur_protocol = log_choice.protocol.unwrap_or(IpVersion::Ipv4);
    let mut scoremap: HashMap<String, (f64, f64)> = HashMap::new();
    for score in scores {
        match score.protocol {
            IpVersion::Ipv4 => scoremap.entry(score.id.to_string()).or_default().0 = score.score,
            IpVersion::Ipv6 => scoremap.entry(score.id.to_string()).or_default().1 = score.score,
        }
    }
    let monitors: Vec<String> = scoremap.iter().map(|v| v.0.clone()).collect();
    let logs = if let Some(cur_monitor) = cur_monitor {
        time_source::logs(&state.db, time_source_id, cur_monitor, cur_protocol, 0, 200).await?
    } else {
        vec![]
    };

    Ok(HtmlTemplate(TimeSourceInfoTemplate {
        app,
        ts,
        scores: scoremap
            .into_iter()
            .map(|v| ScoreTableData {
                monitor: v.0,
                ipv4: v.1.0,
                ipv6: v.1.1,
            })
            .collect(),
        log: logs
            .into_iter()
            .map(|v| DisplayLogRow {
                time: v
                    .sample
                    .get("keyexchange")
                    .and_then(|ke| ke.get("exchange_start"))
                    .and_then(|start| start.as_i64())
                    .and_then(|start| DateTime::from_timestamp(start, 0))
                    .unwrap_or(v.received_at),
                ke_status: v
                    .sample
                    .get("keyexchange")
                    .and_then(extract_keyexchange_status)
                    .unwrap_or_default(),
                ntp_from_ke_status: v
                    .sample
                    .get("ntp_with_ke_cookie")
                    .and_then(extract_ntp_status)
                    .unwrap_or_default(),
                ntp_from_ntp_status: v
                    .sample
                    .get("ntp_with_ntp_cookie")
                    .and_then(extract_ntp_status)
                    .unwrap_or_default(),
                score: v.score,
                raw_sample: v.sample,
            })
            .collect(),
        monitors,
        cur_monitor,
        cur_protocol,
    }))
}

#[derive(Template)]
#[template(path = "management/time_source_key.html.j2")]
struct TimeSourceKeyTemplate {
    app: AppContext,
    hostname: Option<String>,
    auth_key: String,
}

pub async fn create_time_source(
    user: AuthorizedUser,
    app: AppContext,
    State(state): State<AppState>,
    mut cookies: CookieService,
    Form(new_time_source): Form<NewTimeSourceForm>,
) -> Result<impl IntoResponse, AppError> {
    let geodb = state.geodb.read().unwrap().clone();

    match time_source::create(
        &state.db,
        user.id,
        new_time_source.clone().try_into()?,
        state.config.base_secret_index,
        &geodb,
    )
    .await
    {
        Ok(id) => Ok(HtmlTemplate(TimeSourceKeyTemplate {
            app,
            hostname: Some(new_time_source.hostname),
            auth_key: time_source::calculate_auth_key(
                state.config.base_shared_secret.as_bytes(),
                id,
                "",
            ),
        })
        .into_response()),
        Err(_) => Ok((
            cookies.flash_error("Could not add time source".to_string()),
            Redirect::to(TIME_SOURCES_ENDPOINT),
        )
            .into_response()),
    }
}

pub async fn rekey_time_source(
    user: AuthorizedUser,
    Path(time_source_id): Path<TimeSourceId>,
    app: AppContext,
    State(state): State<AppState>,
    mut cookies: CookieService,
) -> Result<impl IntoResponse, AppError> {
    let new_randomizer = auth::generate_pool_token_randomizer();
    match time_source::update_auth_token_randomizer(
        &state.db,
        user.id,
        time_source_id,
        new_randomizer.clone(),
        state.config.base_secret_index,
    )
    .await
    {
        Ok(_) => Ok(HtmlTemplate(TimeSourceKeyTemplate {
            app,
            hostname: None,
            auth_key: time_source::calculate_auth_key(
                state.config.base_shared_secret.as_bytes(),
                time_source_id,
                new_randomizer,
            ),
        })
        .into_response()),
        Err(_) => Ok((
            cookies.flash_error("Could not rekey time source".to_string()),
            Redirect::to(TIME_SOURCES_ENDPOINT),
        )
            .into_response()),
    }
}

pub async fn update_time_source(
    user: AuthorizedUser,
    Path(time_source_id): Path<TimeSourceId>,
    State(state): State<AppState>,
    mut cookies: CookieService,
    Form(time_source): Form<UpdateTimeSourceForm>,
) -> Result<impl IntoResponse, AppError> {
    match time_source::update(&state.db, user.id, time_source_id, time_source).await {
        Ok(_) => cookies.flash_success("Time source updated successfully".to_string()),
        Err(_) => cookies.flash_error("Could not update time source".to_string()),
    };

    Ok((cookies, Redirect::to(TIME_SOURCES_ENDPOINT)))
}

pub async fn delete_time_source(
    user: AuthorizedUser,
    Path(time_source_id): Path<TimeSourceId>,
    State(state): State<AppState>,
    mut cookies: CookieService,
) -> Result<impl IntoResponse, AppError> {
    match time_source::delete(&state.db, user.id, time_source_id).await {
        Ok(_) => cookies.flash_success("Time source deleted successfully".to_string()),
        Err(_) => cookies.flash_error("Could not delete time source".to_string()),
    };

    Ok((cookies, Redirect::to(TIME_SOURCES_ENDPOINT)))
}
