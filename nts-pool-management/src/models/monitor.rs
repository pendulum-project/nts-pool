use chrono::{DateTime, Utc};

use crate::{DbConnLike, models::util::uuid};

uuid!(MonitorId);

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Monitor {
    pub id: MonitorId,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct NewMonitor {
    pub name: String,
    pub authentication_key: String,
}

pub async fn create(
    conn: impl DbConnLike<'_>,
    monitor: NewMonitor,
) -> Result<Monitor, sqlx::Error> {
    sqlx::query_as!(
        Monitor,
        r#"
            INSERT INTO monitors (name, authentication_key)
            VALUES ($1, $2)
            RETURNING id, name, created_at, updated_at
        "#,
        monitor.name,
        monitor.authentication_key,
    )
    .fetch_one(conn)
    .await
}

/// List all the users in the database
pub async fn list(conn: impl DbConnLike<'_>) -> Result<Vec<Monitor>, sqlx::Error> {
    sqlx::query_as!(
        Monitor,
        r#"
            SELECT id, name, created_at, updated_at
            FROM monitors
            ORDER BY created_at DESC
        "#
    )
    .fetch_all(conn)
    .await
}

#[allow(unused)]
pub async fn get_by_authentication_key(
    conn: impl DbConnLike<'_>,
    authentication_key: String,
) -> Result<Monitor, sqlx::Error> {
    sqlx::query_as!(
        Monitor,
        r#"
            SELECT id, name, created_at, updated_at
            FROM monitors
            WHERE authentication_key = $1
        "#,
        authentication_key
    )
    .fetch_one(conn)
    .await
}

pub async fn update_authentication_key(
    conn: impl DbConnLike<'_>,
    id: MonitorId,
    authentication_key: String,
) -> Result<Monitor, sqlx::Error> {
    sqlx::query_as!(
        Monitor,
        r#"
            UPDATE monitors
            SET authentication_key = $2
            WHERE id = $1
            RETURNING id, name, created_at, updated_at
        "#,
        id as _,
        authentication_key,
    )
    .fetch_one(conn)
    .await
}
