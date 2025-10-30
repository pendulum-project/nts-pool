use askama::Template;
use axum::{
    Form,
    extract::{Path, State},
    response::{IntoResponse, Redirect},
};

use crate::{
    AppState,
    auth::{self, AuthorizedUser},
    context::AppContext,
    cookies::CookieService,
    error::AppError,
    models::time_source::{
        self, LogRow, NewTimeSourceForm, TimeSource, TimeSourceId, UpdateTimeSourceForm,
    },
    templates::{HtmlTemplate, filters},
};

pub const TIME_SOURCES_ENDPOINT: &str = "/management/time-sources";

#[derive(Template)]
#[template(path = "management/dashboard.html.j2")]
struct DashboardTemplate {
    app: AppContext,
}

pub async fn dashboard(_user: AuthorizedUser, app: AppContext) -> impl IntoResponse {
    HtmlTemplate(DashboardTemplate { app })
}

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

#[derive(Template)]
#[template(path = "management/logs.html.j2")]
struct LogsTemplate {
    app: AppContext,
    name: String,
    log: Vec<LogRow>,
}

pub async fn time_source_logs(
    user: AuthorizedUser,
    Path(time_source_id): Path<TimeSourceId>,
    app: AppContext,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    let name = time_source::source_name(&state.db, user.id, time_source_id).await?;
    let log = time_source::logs(&state.db, user.id, time_source_id, 0, 200).await?;
    Ok(HtmlTemplate(LogsTemplate { app, name, log }))
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
