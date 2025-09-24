use std::{ops::Deref, time::Duration};

use crate::error::AppError;
use eyre::Context;

#[derive(Debug, Clone)]
pub struct AppConfig {
    // Base website configuration
    pub base_url: BaseUrl,
    pub assets_path: String,
    // Database config
    pub database_url: String,
    pub database_run_migrations: RunDatabaseMigrations,
    // Secrets for authentication and cookies
    pub jwt_secret: String,
    pub cookie_secret: String,
    // Email configuration
    pub mail_from_address: String,
    pub mail_smtp_url: String,
    // Monitoring configuration
    pub poolke_name: String,
    pub monitor_result_batchsize: usize,
    pub monitor_result_batchtime: Duration,
    pub monitor_update_interval: Duration,
    pub monitor_probe_interval: Duration,
    pub monitor_nts_timeout: Duration,
    pub monitor_ntp_timeout: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunDatabaseMigrations {
    Yes,
    No,
    OnlyMigrate,
}

impl AppConfig {
    pub fn from_env() -> Result<Self, AppError> {
        // Base website configuration
        let base_url = BaseUrl::new(
            std::env::var("NTSPOOL_BASE_URL")
                .wrap_err("NTSPOOL_BASE_URL not set in environment")?,
        );
        let assets_path = std::env::var("NTSPOOL_ASSETS_DIR").unwrap_or("./assets".into());

        // Database configuration
        let database_url = std::env::var("NTSPOOL_DATABASE_URL")
            .or_else(|_| std::env::var("DATABASE_URL"))
            .wrap_err("Missing NTSPOOL_DATABASE_URL/DATABASE_URL environment variable")?;
        let database_run_migrations = std::env::var("NTSPOOL_DATABASE_RUN_MIGRATIONS")
            .map(|v| match v.to_lowercase().as_str() {
                "1" | "true" | "yes" => RunDatabaseMigrations::Yes,
                "only-migrate" => RunDatabaseMigrations::OnlyMigrate,
                _ => RunDatabaseMigrations::No,
            })
            .unwrap_or(RunDatabaseMigrations::No);

        // Secrets
        let jwt_secret = std::env::var("NTSPOOL_JWT_SECRET")
            .wrap_err("Missing NTSPOOL_JWT_SECRET environment variable")?;
        let cookie_secret = std::env::var("NTSPOOL_COOKIE_SECRET")
            .wrap_err("Missing NTSPOOL_COOKIE_SECRET environment variable")?;

        // Email configuration
        let mail_from_address = std::env::var("NTSPOOL_MAIL_FROM_ADDRESS")
            .wrap_err("NTSPOOL_MAIL_FROM_ADDRESS not set")?;
        let mail_smtp_url = std::env::var("NTSPOOL_SMTP_URL")
            .wrap_err("NTSPOOL_SMTP_URL not set in environment")?;

        // Monitoring configuration
        let poolke_name = std::env::var("NTSPOOL_POOLKE_NAME")
            .wrap_err("NTSPOOL_POOLKE_NAME not set in environment")?;
        let monitor_result_batchsize = std::env::var("NTSPOOL_MONITOR_RESULT_BATCHSIZE")
            .wrap_err("Missing NTSPOOL_MONITOR_RESULT_BATCHSIZE environment variable")?
            .parse()
            .wrap_err("NTSPOOL_MONITOR_RESULT_BATCHSIZE should be a valid size")?;
        let monitor_result_batchtime = Duration::from_secs(
            std::env::var("NTSPOOL_MONITOR_RESULT_BATCHTIME")
                .wrap_err("Missing NTSPOOL_MONITOR_RESULT_BATCHTIME environment variable")?
                .parse()
                .wrap_err("NTS_POOL_MONITOR_RESULT_BATCHTIME should be number of seconds")?,
        );
        let monitor_update_interval = Duration::from_secs(
            std::env::var("NTSPOOL_MONITOR_UPDATE_INTERVAL")
                .wrap_err("Missing NTSPOOL_MONITOR_UPDATE_INTERVAL environment variable")?
                .parse()
                .wrap_err("NTSPOOL_MONITOR_UPDATE_INTERVAL should be number of seconds")?,
        );
        let monitor_probe_interval = Duration::from_secs(
            std::env::var("NTSPOOL_MONITOR_PROBE_INTERVAL")
                .wrap_err("Missing NTSPOOL_MONITOR_PROBE_INTERVAL environment variable")?
                .parse()
                .wrap_err("NTSPOOL_MONITOR_PROBE_INTERVAL should be number of seconds")?,
        );
        let monitor_nts_timeout = Duration::from_millis(
            std::env::var("NTSPOOL_MONITOR_NTS_TIMEOUT")
                .wrap_err("Missing NTSPOOL_MONITOR_NTS_TIMEOUT environment variable")?
                .parse()
                .wrap_err("NTSPOOL_MONITOR_NTS_TIMEOUT shoudl be number of milliseconds")?,
        );
        let monitor_ntp_timeout = Duration::from_millis(
            std::env::var("NTSPOOL_MONITOR_NTP_TIMEOUT")
                .wrap_err("Missing NTSPOOL_MONITOR_NTP_TIMEOUT environment variable")?
                .parse()
                .wrap_err("NTSPOOL_MONITOR_NTP_TIMEOUT should be number off milliseconds")?,
        );

        Ok(Self {
            base_url,
            assets_path,
            database_url,
            database_run_migrations,
            jwt_secret,
            cookie_secret,
            mail_from_address,
            mail_smtp_url,
            poolke_name,
            monitor_result_batchsize,
            monitor_result_batchtime,
            monitor_update_interval,
            monitor_probe_interval,
            monitor_nts_timeout,
            monitor_ntp_timeout,
        })
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            base_url: BaseUrl::new("http://localhost:3000"),
            poolke_name: "localhost:4460".into(),
            database_url: "postgres://nts-pool@localhost:5432/nts-pool".into(),
            database_run_migrations: RunDatabaseMigrations::No,
            jwt_secret: "UNSAFE_SECRET".into(),
            cookie_secret: "UNSAFE_SECRET".into(),
            mail_from_address: "noreply@example.com".into(),
            mail_smtp_url: "smtp://localhost:25".into(),
            assets_path: "./assets".into(),
            monitor_result_batchsize: 4,
            monitor_result_batchtime: Duration::from_secs(60),
            monitor_update_interval: Duration::from_secs(60),
            monitor_probe_interval: Duration::from_secs(4),
            monitor_nts_timeout: Duration::from_millis(1000),
            monitor_ntp_timeout: Duration::from_millis(1000),
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
