use askama::Template;
use axum::{
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};

use crate::auth::UserSession;

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
    session: Option<UserSession>,
}

pub fn not_found_page(session: Option<UserSession>) -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        HtmlTemplate(NotFoundPageTemplate { session }),
    )
}

#[derive(Template)]
#[template(path = "unauthorized_page.html.j2")]
pub struct UnauthorizedTemplate {
    session: Option<UserSession>,
}

pub fn unauthorized_page(session: Option<UserSession>) -> impl IntoResponse {
    (
        StatusCode::UNAUTHORIZED,
        HtmlTemplate(UnauthorizedTemplate { session }),
    )
}
