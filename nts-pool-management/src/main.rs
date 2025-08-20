use std::str::FromStr;

use axum::{extract::FromRef, middleware};
use sqlx::PgPool;
use tracing::info;

use crate::email::{MailTransport, Mailer};

pub mod auth;
pub mod email;
pub mod error;
pub mod models;
pub mod routes;
pub mod templates;

#[derive(Clone, FromRef)]
pub struct AppState {
    db: PgPool,
    jwt_encoding_key: jsonwebtoken::EncodingKey,
    jwt_decoding_key: jsonwebtoken::DecodingKey,
    mailer: Mailer,
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
async fn pool_conn(
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

fn get_base_url() -> String {
    std::env::var("NTSPOOL_BASE_URL").expect("NTSPOOL_BASE_URL not set")
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // Workaround because ring is also in our dependencies: install aws-lc-rs default crypto provider
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install default crypto provider");

    // Setup database connection
    let db_conn_str = std::env::var("NTSPOOL_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .expect("Missing NTSPOOL_DATABASE_URL/DATABASE_URL environment variable");
    let db_run_migrations = std::env::var("NTSPOOL_DATABASE_RUN_MIGRATIONS")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(true);
    let db_retry_interval = std::time::Duration::from_millis(1000);
    let db = pool_conn(&db_conn_str, 5, db_retry_interval, db_run_migrations)
        .await
        .expect("Error initializing database connection");

    // Setup JWT encoding and decoding keys
    let jwt_secret = std::env::var("NTSPOOL_JWT_SECRET")
        .expect("Missing NTSPOOL_JWT_SECRET environment variable");
    let jwt_encoding_key = jsonwebtoken::EncodingKey::from_secret(jwt_secret.as_bytes());
    let jwt_decoding_key = jsonwebtoken::DecodingKey::from_secret(jwt_secret.as_bytes());

    // Get the base URL for the application to make sure it is set correctly
    get_base_url();

    // Setup mail transport for sending mails
    let mail_transport_url = std::env::var("NTSPOOL_SMTP_URL").expect("NTSPOOL_SMTP_URL not set");
    let mail_transport = MailTransport::from_url(&mail_transport_url)
        .expect("Failed to create mail transport")
        .build();
    let mail_from_address = lettre::message::Mailbox::from_str(
        &std::env::var("NTSPOOL_MAIL_FROM_ADDRESS").expect("NTSPOOL_MAIL_FROM_ADDRESS not set"),
    )
    .expect("Failed to create mail from address");
    let mailer = Mailer::new(mail_transport, mail_from_address);

    // construct the application state
    let state = AppState {
        db,
        jwt_encoding_key,
        jwt_decoding_key,
        mailer,
    };

    // setup routes
    let router = routes::create_router()
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::auth_middleware,
        ))
        .with_state(state)
        .nest_service(
            "/assets",
            tower_http::services::ServeDir::new(
                std::env::var("NTSPOOL_ASSETS_DIR").unwrap_or("./assets".into()),
            ),
        );

    // start listening for incoming connections
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, router).await.unwrap();
}
