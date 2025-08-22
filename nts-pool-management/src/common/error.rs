use std::{ops::Deref, sync::Arc};

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::{
    AppState,
    auth::NotLoggedInError,
    context::AppContext,
    templates::{not_found_page, unauthorized_page},
};

#[derive(Debug, derive_more::Display, derive_more::Error)]
pub struct AppError(eyre::Report);

impl AppError {
    pub fn into_inner(self) -> eyre::Report {
        self.0
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let mut response = (StatusCode::INTERNAL_SERVER_ERROR).into_response();
        response.extensions_mut().insert(Arc::new(self));
        response
    }
}

pub async fn error_middleware(
    State(_state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let response = next.run(request).await;
    if let Some(error) = response.extensions().get::<Arc<AppError>>() {
        let context = response
            .extensions()
            .get::<AppContext>()
            .cloned()
            .unwrap_or_default();
        if let Some(sqlx::Error::RowNotFound) = error.downcast_ref::<sqlx::Error>() {
            not_found_page(context).into_response()
        } else if error.downcast_ref::<NotLoggedInError>().is_some() {
            unauthorized_page(context).into_response()
        } else {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Something went wrong: {}", error),
            )
                .into_response()
        }
    } else {
        response
    }
}

impl Deref for AppError {
    type Target = eyre::Error;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

macro_rules! impl_from {
    ($($t:ty),+) => {
        $(
            impl From<$t> for AppError {
                fn from(err: $t) -> Self {
                    AppError(err.into())
                }
            }
        )+
    };
}

impl_from!(eyre::Report, sqlx::Error, NotLoggedInError);
