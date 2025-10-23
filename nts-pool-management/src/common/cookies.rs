use std::{convert::Infallible, fmt::Display};

use axum::{extract::FromRequestParts, http::request::Parts, response::IntoResponseParts};
use axum_extra::extract::{PrivateCookieJar, cookie::Cookie};
use serde::{Deserialize, Serialize};

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

const USER_CONTEXT_COOKIE_NAME: &str = "uc";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UserContext {
    pub terms_accepted: bool,
}

#[derive(Debug)]
pub struct CookieService(PrivateCookieJar);

impl FromRequestParts<AppState> for CookieService {
    type Rejection = Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let cookie_jar = PrivateCookieJar::from_request_parts(parts, &state.clone()).await?;
        Ok(Self(cookie_jar))
    }
}

impl CookieService {
    pub fn jar(self) -> PrivateCookieJar {
        self.0
    }

    pub fn set_flash_message(&mut self, level: MessageType, msg: String) {
        self.0 = self
            .0
            .clone()
            .add(Cookie::new(FLASH_COOKIE_NAME, format!("{}|{}", level, msg)))
    }

    pub fn flash_success(&mut self, msg: String) {
        self.set_flash_message(MessageType::Success, msg);
    }

    pub fn flash_error(&mut self, msg: String) {
        self.set_flash_message(MessageType::Error, msg);
    }

    pub fn flash_message(&mut self) -> Result<Option<(MessageType, String)>, AppError> {
        if let Some(flash) = self.0.get(FLASH_COOKIE_NAME) {
            if let Some((msg_type, msg)) = flash.value().split_once("|") {
                self.0 = self.0.clone().remove(FLASH_COOKIE_NAME);
                Ok(Some((msg_type.try_into()?, msg.to_string())))
            } else {
                self.0 = self.0.clone().remove(FLASH_COOKIE_NAME);
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    pub fn user_context(&self) -> UserContext {
        if let Some(c) = self.0.get(USER_CONTEXT_COOKIE_NAME) {
            serde_json::from_str(c.value()).unwrap_or_default()
        } else {
            UserContext::default()
        }
    }

    pub fn set_user_context(&mut self, user_context: &UserContext) {
        self.0 = self.0.clone().add(Cookie::new(
            USER_CONTEXT_COOKIE_NAME,
            serde_json::to_string(user_context).unwrap(),
        ));
    }

    pub fn accept_terms(&mut self) {
        let mut uc = self.user_context();
        uc.terms_accepted = true;
        self.set_user_context(&uc);
    }
}

impl IntoResponseParts for CookieService {
    type Error = Infallible;

    fn into_response_parts(
        self,
        res: axum::response::ResponseParts,
    ) -> Result<axum::response::ResponseParts, Self::Error> {
        self.0.into_response_parts(res)
    }
}
