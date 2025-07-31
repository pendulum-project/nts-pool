use axum::extract::FromRef;
use sqlx::PgPool;
use tracing::info;

pub mod auth;
pub mod error;
pub mod models;
pub mod routes;

#[derive(Clone, FromRef)]
pub struct AppState {
    db: PgPool,
    jwt_encoding_key: jsonwebtoken::EncodingKey,
    jwt_decoding_key: jsonwebtoken::DecodingKey,
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
    let db_retry_interval = std::time::Duration::from_millis(1000);
    let db = pool_conn(&db_conn_str, 5, db_retry_interval, true)
        .await
        .expect("Error initializing database connection");

    let jwt_secret = std::env::var("NTSPOOL_JWT_SECRET")
        .expect("Missing NTSPOOL_JWT_SECRET environment variable");
    let jwt_encoding_key = jsonwebtoken::EncodingKey::from_secret(jwt_secret.as_bytes());
    let jwt_decoding_key = jsonwebtoken::DecodingKey::from_secret(jwt_secret.as_bytes());

    // // Insert an administrator account and set an 'admin' password
    // let user = crate::models::user::create(
    //     &db,
    //     crate::models::user::NewUser {
    //         email: "admin@example.com".into(),
    //         role: user::UserRole::Administrator,
    //     },
    // )
    // .await
    // .expect("Created admin user");
    // crate::models::authentication_method::create(
    //     &db,
    //     user.id,
    //     crate::models::authentication_method::AuthenticationVariant::Password(
    //         crate::models::authentication_method::PasswordAuthentication::new("admin").expect("Failed to create password hash"),
    //     ),
    // )
    // .await
    // .expect("Failed to create authentication method");

    // construct the application state
    let state = AppState {
        db,
        jwt_encoding_key,
        jwt_decoding_key,
    };

    // setup routes
    let router = routes::create_router().with_state(state).nest_service(
        "/assets",
        tower_http::services::ServeDir::new(
            std::env::var("NTSPOOL_ASSETS_DIR").unwrap_or("./assets".into()),
        ),
    );

    // start listening for incoming connections
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, router).await.unwrap();
}
