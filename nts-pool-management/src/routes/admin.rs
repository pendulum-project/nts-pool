use askama::Template;
use axum::response::IntoResponse;

use crate::{
    auth::Administrator,
    error::AppError,
    templates::{AppVars, HtmlTemplate, filters},
};

#[derive(Template)]
#[template(path = "admin/overview.html.j2")]
struct OverviewTemplate {
    app: AppVars,
}

pub async fn overview(_admin: Administrator) -> Result<impl IntoResponse, AppError> {
    Ok(HtmlTemplate(OverviewTemplate {
        app: AppVars::from_current_task(),
    }))
}
