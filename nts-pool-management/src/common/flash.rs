use std::{convert::Infallible, fmt::Display};

use axum::{extract::FromRequestParts, http::request::Parts, response::IntoResponseParts};
use axum_extra::extract::{PrivateCookieJar, cookie::Cookie};

use crate::AppState;

pub const FLASH_COOKIE_NAME: &str = "flash";

pub enum MessageType {
    Success,
    Error,
}

impl Display for MessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MessageType::Success => write!(f, "success"),
            MessageType::Error => write!(f, "error"),
        }
    }
}

pub struct FlashMessageService(pub PrivateCookieJar);

impl FromRequestParts<AppState> for FlashMessageService {
    type Rejection = Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let cookie_jar = PrivateCookieJar::from_request_parts(parts, &state.clone()).await?;
        Ok(Self(cookie_jar))
    }
}

impl FlashMessageService {
    pub fn set(&self, level: MessageType, message: String) -> Self {
        Self(self.0.clone().add(Cookie::new(
            FLASH_COOKIE_NAME,
            format!("{}|{}", level, message),
        )))
    }
}

impl IntoResponseParts for FlashMessageService {
    type Error = Infallible;

    fn into_response_parts(
        self,
        res: axum::response::ResponseParts,
    ) -> Result<axum::response::ResponseParts, Self::Error> {
        self.0.into_response_parts(res)
    }
}

pub fn extract_flash_message(cookie_jar: PrivateCookieJar) -> (PrivateCookieJar, Option<String>) {
    if let Some(flash) = cookie_jar.get(FLASH_COOKIE_NAME) {

        if let Some((msg_type, msg)) = flash.value().split_once("|") {
            (
                cookie_jar.remove(FLASH_COOKIE_NAME),
                Some(msg.to_string()),
            )
        } else {
            (
                cookie_jar.remove(FLASH_COOKIE_NAME),
                None,
            )
        }

    } else {
        (cookie_jar, None)
    }
}
