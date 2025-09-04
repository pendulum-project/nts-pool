use askama::Template;
use axum::{
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};

use crate::context::AppContext;

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
    app: AppContext,
}

pub fn not_found_page(context: AppContext) -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        HtmlTemplate(NotFoundPageTemplate { app: context }),
    )
}

#[derive(Template)]
#[template(path = "unauthorized_page.html.j2")]
pub struct UnauthorizedTemplate {
    app: AppContext,
}

pub fn unauthorized_page(context: AppContext) -> impl IntoResponse {
    (
        StatusCode::UNAUTHORIZED,
        HtmlTemplate(UnauthorizedTemplate { app: context }),
    )
}

#[derive(Template)]
#[template(path = "error_page.html.j2")]
struct ErrorTemplate {
    app: AppContext,
    message: String,
}

pub fn error_page(context: AppContext, message: String) -> impl IntoResponse {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        HtmlTemplate(ErrorTemplate {
            app: context,
            message,
        }),
    )
}
