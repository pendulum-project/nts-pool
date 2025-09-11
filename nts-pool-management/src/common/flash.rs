use std::convert::Infallible;

use axum::{extract::FromRequestParts, http::request::Parts, response::IntoResponseParts};
use axum_extra::extract::{PrivateCookieJar, cookie::Cookie};

use crate::AppState;

enum MessageType {
    Success,
    Error,
}

pub struct FlashMessage(pub PrivateCookieJar);

impl FromRequestParts<AppState> for FlashMessage {
    type Rejection = Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let cookie_jar = PrivateCookieJar::from_request_parts(parts, &state.clone()).await?;
        Ok(Self(cookie_jar))
    }
}

impl FlashMessage {
    pub fn set(&self, message: String) -> Self {
        Self(self.0.clone().add(Cookie::new("flash", message)))
    }
}

impl IntoResponseParts for FlashMessage {
    type Error = Infallible;

    fn into_response_parts(
        self,
        res: axum::response::ResponseParts,
    ) -> Result<axum::response::ResponseParts, Self::Error> {
        self.0.into_response_parts(res)
    }
}
