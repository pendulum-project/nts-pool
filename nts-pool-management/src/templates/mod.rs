use askama::Template;
use axum::{
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};

use crate::{auth::CURRENT_USER, models::user::User};

pub mod filters;

pub struct HtmlTemplate<T>(pub T);
impl<T> IntoResponse for HtmlTemplate<T>
where
    T: Template,
{
    fn into_response(self) -> Response {
        match self.0.render() {
            Ok(html) => Html(html).into_response(),
            Err(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to render template. Error: {err}"),
            )
                .into_response(),
        }
    }
}

#[derive(Template)]
#[template(path = "not_found_page.html.j2")]
pub struct NotFoundPageTemplate {
    app: AppVars,
}

pub fn not_found_page() -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        HtmlTemplate(NotFoundPageTemplate {
            app: AppVars::from_current_task(),
        }),
    )
}

#[derive(Template)]
#[template(path = "unauthorized_page.html.j2")]
pub struct UnauthorizedTemplate {
    app: AppVars,
}

pub fn unauthorized_page() -> impl IntoResponse {
    (
        StatusCode::UNAUTHORIZED,
        HtmlTemplate(UnauthorizedTemplate {
            app: AppVars::from_current_task(),
        }),
    )
}

pub struct AppVars {
    pub user: Option<User>,
    pub base_url: String,
}

impl AppVars {
    pub fn from_current_task() -> Self {
        Self {
            user: CURRENT_USER.get(),
            base_url: crate::get_base_url(),
        }
    }
}
