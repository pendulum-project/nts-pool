use std::str::FromStr;

use axum::{extract::FromRef, middleware};
use axum_extra::extract::cookie;
use sqlx::PgPool;
use tracing::info;

use crate::{
    config::AppConfig,
    email::{MailTransport, Mailer},
};

pub use common::*;

mod common;
pub mod models;
pub mod routes;
mod scoring;
pub mod templates;
#[cfg(test)]
pub mod test;

#[derive(Clone, FromRef)]
pub struct AppState {
    db: PgPool,
    jwt_encoding_key: jsonwebtoken::EncodingKey,
    jwt_decoding_key: jsonwebtoken::DecodingKey,
    private_cookie_key: cookie::Key,
    mailer: Mailer,
    config: AppConfig,
}

pub trait DbConnLike<'a>:
    sqlx::Acquire<'a, Database = sqlx::Postgres> + sqlx::Executor<'a, Database = sqlx::Postgres>
{
}

impl<'a, T> DbConnLike<'a> for T where
    T: sqlx::Acquire<'a, Database = sqlx::Postgres> + sqlx::Executor<'a, Database = sqlx::Postgres>
{
}

/// Connect to the database, retrying if necessary. Once connected, run
/// migrations to update the database schema to the latest version.
pub async fn pool_conn(
    db_conn_str: &str,
    mut remaining_tries: u32,
    retry_interval: std::time::Duration,
    run_migrations: bool,
) -> Result<PgPool, sqlx::Error> {
    loop {
        let db = sqlx::postgres::PgPoolOptions::new()
            .max_connections(5)
            .connect(db_conn_str)
            .await;
        match db {
            Ok(db) => {
                // run migrations to update the database schema to the latest version
                if run_migrations {
                    sqlx::migrate!("./migrations").run(&db).await?;
                }
                break Ok(db);
            }
            Err(err) => {
                remaining_tries -= 1;
                if remaining_tries == 0 {
                    break Err(err);
                }

                info!("Failed to connect to the database, {remaining_tries} retries remaining...");
                tokio::time::sleep(retry_interval).await;
            }
        }
    }
}

#[tokio::main]
async fn main() {
    let config = AppConfig::from_env().expect("Failed to load configuration");

    tracing_subscriber::fmt::init();

    // Workaround because ring is also in our dependencies: install aws-lc-rs default crypto provider
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install default crypto provider");

    // Setup database connection
    let db_retry_interval = std::time::Duration::from_millis(1000);
    let db = pool_conn(
        &config.database_url,
        5,
        db_retry_interval,
        config.database_run_migrations,
    )
    .await
    .expect("Error initializing database connection");

    // Setup JWT encoding and decoding keys
    let jwt_encoding_key = jsonwebtoken::EncodingKey::from_secret(config.jwt_secret.as_bytes());
    let jwt_decoding_key = jsonwebtoken::DecodingKey::from_secret(config.jwt_secret.as_bytes());

    // Setup private cookie key
    let private_cookie_key = cookie::Key::derive_from(config.cookie_secret.as_bytes());

    // Setup mail transport for sending mails
    let mail_transport = MailTransport::from_url(&config.mail_smtp_url)
        .expect("Failed to create mail transport")
        .build();
    let mail_from_address = lettre::message::Mailbox::from_str(&config.mail_from_address)
        .expect("Failed to create mail from address");
    let mailer = Mailer::new(mail_transport, mail_from_address);

    let serve_dir_service = tower_http::services::ServeDir::new(&config.assets_path);

    // construct the application state
    let state = AppState {
        db,
        jwt_encoding_key,
        jwt_decoding_key,
        private_cookie_key,
        mailer,
        config,
    };

    // setup routes
    let router = routes::create_router()
        .with_state(state.clone())
        .layer(middleware::from_fn_with_state(
            state.clone(),
            context::context_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            error::error_middleware,
        ))
        .nest_service("/assets", serve_dir_service);

    // start listening for incoming connections
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, router).await.unwrap();
}
