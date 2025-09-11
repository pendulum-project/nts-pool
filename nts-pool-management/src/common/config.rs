use std::ops::Deref;

use crate::error::AppError;
use eyre::Context;

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub base_url: BaseUrl,
    pub poolke_name: String,
    pub database_url: String,
    pub database_run_migrations: bool,
    pub jwt_secret: String,
    pub cookie_secret: String,
    pub mail_from_address: String,
    pub mail_smtp_url: String,
    pub assets_path: String,
}

impl AppConfig {
    pub fn from_env() -> Result<Self, AppError> {
        let base_url = BaseUrl::new(
            std::env::var("NTSPOOL_BASE_URL")
                .wrap_err("NTSPOOL_BASE_URL not set in environment")?,
        );

        let poolke_name = std::env::var("NTSPOOL_POOLKE_NAME")
            .wrap_err("NTSPOOL_POOLKE_NAME not set in environment")?;

        let database_url = std::env::var("NTSPOOL_DATABASE_URL")
            .or_else(|_| std::env::var("DATABASE_URL"))
            .wrap_err("Missing NTSPOOL_DATABASE_URL/DATABASE_URL environment variable")?;

        let database_run_migrations = std::env::var("NTSPOOL_DATABASE_RUN_MIGRATIONS")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(true);

        let jwt_secret = std::env::var("NTSPOOL_JWT_SECRET")
            .wrap_err("Missing NTSPOOL_JWT_SECRET environment variable")?;

        let cookie_secret = std::env::var("NTSPOOL_COOKIE_SECRET")
            .wrap_err("Missing NTSPOOL_COOKIE_SECRET environment variable")?;
        println!("SECRET OMG");
        println!("{}", cookie_secret);
        let mail_from_address = std::env::var("NTSPOOL_MAIL_FROM_ADDRESS")
            .wrap_err("NTSPOOL_MAIL_FROM_ADDRESS not set")?;

        let mail_smtp_url = std::env::var("NTSPOOL_SMTP_URL")
            .wrap_err("NTSPOOL_SMTP_URL not set in environment")?;

        let assets_path = std::env::var("NTSPOOL_ASSETS_DIR").unwrap_or("./assets".into());

        Ok(Self {
            base_url,
            poolke_name,
            database_url,
            database_run_migrations,
            jwt_secret,
            cookie_secret,
            mail_from_address,
            mail_smtp_url,
            assets_path,
        })
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            base_url: BaseUrl::new("http://localhost:3000"),
            poolke_name: "localhost:4460".into(),
            database_url: "postgres://nts-pool@localhost:5432/nts-pool".into(),
            database_run_migrations: true,
            jwt_secret: "UNSAFE_SECRET".into(),
            cookie_secret: "UNSAFE_SECRET".into(),
            mail_from_address: "noreply@example.com".into(),
            mail_smtp_url: "smtp://localhost:25".into(),
            assets_path: "./assets".into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, derive_more::Display, derive_more::From)]
#[from(String, &'static str)]
pub struct BaseUrl(String);

impl BaseUrl {
    pub fn new(url: impl Into<String>) -> Self {
        Self(url.into())
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl Deref for BaseUrl {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
