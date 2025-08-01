use askama::Template;
use axum::response::IntoResponse;

use crate::{
    auth::{Administrator, UserSession},
    error::AppError,
    templates::{HtmlTemplate, filters},
};

#[derive(Template)]
#[template(path = "admin/overview.html.j2")]
struct OverviewTemplate {
    session: Option<UserSession>,
}

pub async fn overview(admin: Administrator) -> Result<impl IntoResponse, AppError> {
    Ok(HtmlTemplate(OverviewTemplate {
        session: Some(admin.into()),
    }))
}
