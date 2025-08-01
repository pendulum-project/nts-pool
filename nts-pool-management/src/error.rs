use std::ops::Deref;

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};

use crate::{
    auth::NotLoggedInError,
    templates::{not_found_page, unauthorized_page},
};

pub struct AppError(anyhow::Error);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        if let Some(sqlx::Error::RowNotFound) = self.0.downcast_ref::<sqlx::Error>() {
            not_found_page().into_response()
        } else if self.0.downcast_ref::<NotLoggedInError>().is_some() {
            unauthorized_page().into_response()
        } else {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Something went wrong: {}", self.0),
            )
                .into_response()
        }
    }
}

impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}

impl AppError {
    pub fn into_inner(self) -> anyhow::Error {
        self.0
    }
}

impl Deref for AppError {
    type Target = anyhow::Error;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
