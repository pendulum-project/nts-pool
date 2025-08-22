use askama::Template;
use axum::response::IntoResponse;

use crate::{
    auth::Administrator,
    context::AppContext,
    error::AppError,
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
