#![forbid(unsafe_code)]

use std::{
    str::FromStr,
    sync::{Arc, RwLock},
};

use axum::{extract::FromRef, middleware};
use axum_extra::extract::cookie;
use eyre::Context;
use notify::Watcher;
use sqlx::PgPool;
use tracing::info;

use crate::{
    common::config::RunDatabaseMigrations,
    common::error::AppError,
    config::AppConfig,
    email::{MailTransport, Mailer},
};

pub use common::*;

mod common;
#[cfg(feature = "dev-database")]
pub mod fixtures;
pub mod geo;
pub mod models;
mod pagination;
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
    geodb: Arc<RwLock<Arc<maxminddb::Reader<Vec<u8>>>>>,
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
    run_migrations: RunDatabaseMigrations,
) -> Result<PgPool, sqlx::Error> {
    loop {
        let db = sqlx::postgres::PgPoolOptions::new()
            .max_connections(5)
            .connect(db_conn_str)
            .await;
        match db {
            Ok(db) => {
                // run migrations to update the database schema to the latest version
                if run_migrations == RunDatabaseMigrations::Yes
                    || run_migrations == RunDatabaseMigrations::OnlyMigrate
                {
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

async fn manage_geodb(
    geodb_path: impl AsRef<std::path::Path> + Send + 'static,
) -> Result<Arc<RwLock<Arc<maxminddb::Reader<Vec<u8>>>>>, AppError> {
    let (change_sender, mut change_receiver) = tokio::sync::mpsc::unbounded_channel::<()>();
    // Use a poll watcher here as INotify can be unreliable in many ways and I don't want to deal with that.
    let mut watcher = notify::poll::PollWatcher::new(
        move |event: notify::Result<notify::Event>| {
            if event.is_ok() {
                let _ = change_sender.send(());
            }
        },
        notify::Config::default()
            .with_poll_interval(std::time::Duration::from_secs(60))
            .with_compare_contents(true),
    )
    .wrap_err("Could not setup watcher for changes in geolocation database")?;

    watcher
        .watch(geodb_path.as_ref(), notify::RecursiveMode::NonRecursive)
        .wrap_err("Could not watch geolocation database for changes")?;

    let geodb = Arc::new(RwLock::new(geo::load_geodb(geodb_path.as_ref()).await?));
    let geodb_cloned = geodb.clone();

    tokio::spawn(async move {
        // keep the watcher alive
        let _w = watcher;
        loop {
            change_receiver.recv().await;
            match geo::load_geodb(geodb_path.as_ref()).await {
                Ok(new_geodb) => {
                    *geodb.write().unwrap() = new_geodb;
                }
                Err(e) => {
                    tracing::error!("Could not refresh geolocation database: {e}");
                }
            }
        }
    });

    Ok(geodb_cloned)
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

    // early exit if we were only asked to run migrations
    if config.database_run_migrations == RunDatabaseMigrations::OnlyMigrate {
        info!("Migrations applied, exiting as requested.");
        return;
    } else {
        info!("Database connection established, migrated to latest version.");
    }

    #[cfg(feature = "dev-database")]
    if crate::models::user::count(&db)
        .await
        .expect("Failed to load user count")
        > 0
    {
        info!("Database already contains data, skipping fixture loading.");
    } else {
        info!("Loading fixtures into the database...");
        let mut tx = db
            .begin()
            .await
            .expect("Failed to start database transaction for fixtures");
        fixtures::default_fixture(&mut *tx)
            .await
            .expect("Failed to load default fixture");
        tx.commit().await.expect("Failed to load fixtures");
        info!("Fixtures loaded successfully.");
    }

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

    let geodb = manage_geodb(config.geolocation_db.clone())
        .await
        .expect("Unable to initialize geolocation database");

    // construct the application state
    let state = AppState {
        db,
        jwt_encoding_key,
        jwt_decoding_key,
        private_cookie_key,
        mailer,
        config,
        geodb,
    };

    // setup routes
    let router_external = routes::create_router()
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
    let router_internal = routes::create_internal_router()
        .with_state(state.clone())
        .layer(middleware::from_fn_with_state(
            state.clone(),
            context::context_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            error::error_middleware,
        ));

    #[cfg(feature = "livereload")]
    let router_external = router_external.merge(common::livereload::livereload_router());

    // start listening for incoming connections
    let listener_external = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    let listener_internal = tokio::net::TcpListener::bind("0.0.0.0:3001").await.unwrap();
    tokio::try_join!(
        axum::serve(listener_external, router_external),
        axum::serve(listener_internal, router_internal)
    )
    .unwrap();
}
