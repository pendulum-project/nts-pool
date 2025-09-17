use askama::Template;
use axum::{
    Form,
    extract::{Path, State},
    response::{IntoResponse, Redirect},
};
use axum_extra::extract::CookieJar;
use eyre::{Context, OptionExt, eyre};
use serde::Deserialize;

use crate::{
    AppState,
    auth::{self, Administrator, JwtClaims, login_into},
    context::AppContext,
    error::AppError,
    models::{
        monitor::{self, Monitor, MonitorId, NewMonitor},
        user::{self, User, UserId},
    },
    templates::{HtmlTemplate, filters},
};

#[derive(Template)]
#[template(path = "admin/overview.html.j2")]
struct OverviewTemplate {
    app: AppContext,
}

pub async fn overview(
    _admin: Administrator,
    app: AppContext,
) -> Result<impl IntoResponse, AppError> {
    Ok(HtmlTemplate(OverviewTemplate { app }))
}

#[derive(Template)]
#[template(path = "admin/users.html.j2")]
struct UsersTemplate {
    app: AppContext,
    users: Vec<User>,
}

pub async fn users(
    _admin: Administrator,
    app: AppContext,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    let users = user::list(&state.db).await?;
    Ok(HtmlTemplate(UsersTemplate { app, users }))
}

#[derive(Template)]
#[template(path = "admin/monitors.html.j2")]
struct MonitorsTemplate {
    app: AppContext,
    monitors: Vec<Monitor>,
}

pub async fn monitors(
    _admin: Administrator,
    app: AppContext,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    let monitors = monitor::list(&state.db).await?;
    Ok(HtmlTemplate(MonitorsTemplate { app, monitors }))
}

#[derive(Template)]
#[template(path = "admin/monitor_key.html.j2")]
struct MonitorKeyTemplate {
    app: AppContext,
    name: String,
    key: String,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct NewMonitorForm {
    pub name: String,
}

pub async fn create_monitor(
    _admin: Administrator,
    app: AppContext,
    State(state): State<AppState>,
    Form(NewMonitorForm { name }): Form<NewMonitorForm>,
) -> Result<impl IntoResponse, AppError> {
    let authentication_key = auth::generate_monitor_token();
    monitor::create(
        &state.db,
        NewMonitor {
            name: name.clone(),
            authentication_key: authentication_key.clone(),
        },
    )
    .await?;

    Ok(HtmlTemplate(MonitorKeyTemplate {
        app,
        name,
        key: authentication_key,
    }))
}

pub async fn rekey_monitor(
    _admin: Administrator,
    app: AppContext,
    Path(monitor_id): Path<MonitorId>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    let authentication_key = auth::generate_monitor_token();
    let monitor =
        monitor::update_authentication_key(&state.db, monitor_id, authentication_key.clone())
            .await?;

    Ok(HtmlTemplate(MonitorKeyTemplate {
        app,
        name: monitor.name,
        key: authentication_key,
    }))
}

pub async fn user_block(
    admin: Administrator,
    Path(user_id): Path<UserId>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    // Prevent the admin from block themself
    if admin.id != user_id {
        user::block_user(&state.db, user_id).await?;
    }

    Ok(Redirect::to("/admin/users"))
}

pub async fn user_unblock(
    _admin: Administrator,
    Path(user_id): Path<UserId>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    user::unblock_user(&state.db, user_id).await?;

    Ok(Redirect::to("/admin/users"))
}

pub async fn login_as(
    claims: JwtClaims,
    admin: Administrator,
    cookie_jar: CookieJar,
    Path(user_id): Path<UserId>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    if claims.parent.is_some() {
        return Err(
            eyre!("Cannot login as another user when already logged in as another user").into(),
        );
    }
    let user = user::get_by_id(&state.db, user_id)
        .await?
        .ok_or_eyre("User not found")?;
    let cookie_jar = login_into(
        &user,
        Some(&admin),
        None,
        &state.jwt_encoding_key,
        cookie_jar,
    )
    .wrap_err("Failed to switch to user")?;
    Ok((cookie_jar, Redirect::to("/")))
}
