use chrono::{DateTime, Utc};
use nts_pool_shared::{IpVersion, ProbeResult};

use crate::{
    DbConnLike,
    models::{time_source::TimeSourceId, util::uuid},
};

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

pub struct NewSample {
    pub time_source_id: TimeSourceId,
    pub protocol: IpVersion,
    pub monitor_id: MonitorId,
    pub step: f64,
    pub max_score: Option<f64>,
    pub raw_sample: ProbeResult,
}

pub async fn add_sample(conn: impl DbConnLike<'_>, sample: NewSample) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
            INSERT INTO monitor_samples (time_source_id, protocol, monitor_id, score, raw_sample)
            SELECT 
                $1 AS time_source_id, 
                $2 AS protocol, 
                $3 AS monitor_id, 
                LEAST(score * 0.95 + $4, $5) AS score,
                $6 AS raw_sample
            FROM (
                (
                    SELECT score, 0 AS query_idx
                    FROM monitor_samples 
                    WHERE
                        time_source_id = $1 AND
                        protocol = $2 AND
                        monitor_id = $3
                    ORDER BY received_at DESC
                    LIMIT 1
                ) UNION ALL (
                    SELECT 0 AS score, 1 AS query_idx
                )
                ORDER BY query_idx ASC
                LIMIT 1
            )
        "#,
        sample.time_source_id as _,
        sample.protocol as _,
        sample.monitor_id as _,
        sample.step,
        sample.max_score,
        sqlx::types::Json(sample.raw_sample) as _,
    )
    .execute(conn)
    .await?;
    Ok(())
}
