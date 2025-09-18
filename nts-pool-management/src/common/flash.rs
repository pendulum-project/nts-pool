use std::{convert::Infallible, fmt::Display};

use axum::{extract::FromRequestParts, http::request::Parts, response::IntoResponseParts};
use axum_extra::extract::{PrivateCookieJar, cookie::Cookie};

use crate::AppState;

use super::error::AppError;

pub const FLASH_COOKIE_NAME: &str = "flash";

#[derive(Debug, Clone)]
pub enum MessageType {
    Success,
    Error,
}

impl TryFrom<&str> for MessageType {
    type Error = eyre::Error;

    fn try_from(value: &str) -> Result<Self, <MessageType as TryFrom<&str>>::Error> {
        println!("{value}");
        match value {
            "success" => Ok(Self::Success),
            "error" => Ok(Self::Error),
            _ => Err(eyre::eyre!("unknown message type")),
        }
    }
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
    pub fn set(&self, level: MessageType, msg: String) -> Self {
        Self(
            self.0
                .clone()
                .add(Cookie::new(FLASH_COOKIE_NAME, format!("{}|{}", level, msg))),
        )
    }

    pub fn success(&self, msg: String) -> Self {
        self.set(MessageType::Success, msg)
    }

    pub fn error(&self, msg: String) -> Self {
        self.set(MessageType::Error, msg)
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

pub fn extract_flash_message(
    cookie_jar: PrivateCookieJar,
) -> Result<(PrivateCookieJar, Option<(MessageType, String)>), AppError> {
    if let Some(flash) = cookie_jar.get(FLASH_COOKIE_NAME) {
        if let Some((msg_type, msg)) = flash.value().split_once("|") {
            Ok((
                cookie_jar.remove(FLASH_COOKIE_NAME),
                Some((msg_type.try_into()?, msg.to_string())),
            ))
        } else {
            Ok((cookie_jar.remove(FLASH_COOKIE_NAME), None))
        }
    } else {
        Ok((cookie_jar, None))
    }
}
