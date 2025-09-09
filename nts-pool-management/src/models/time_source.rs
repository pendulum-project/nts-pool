use eyre::Context;
use serde::Deserialize;

use crate::{
    DbConnLike,
    error::AppError,
    models::{
        user::UserId,
        util::{port::Port, uuid},
    },
};

uuid!(TimeSourceId);

#[derive(Debug, Clone, Deserialize, sqlx::FromRow)]
pub struct TimeSource {
    pub id: TimeSourceId,
    pub owner: UserId,
    pub hostname: String,
    pub port: Option<Port>,
    pub countries: Vec<String>,
    pub weight: i32,
}

#[derive(Debug, Deserialize, Clone)]
pub struct NewTimeSource {
    pub hostname: String,
    pub port: Option<Port>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct NewTimeSourceForm {
    pub hostname: String,
    pub port: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct UpdateTimeSourceForm {
    pub weight: i32,
}

impl TryFrom<NewTimeSourceForm> for NewTimeSource {
    type Error = AppError;

    fn try_from(form: NewTimeSourceForm) -> Result<Self, Self::Error> {
        let port = if form.port.is_empty() {
            None
        } else {
            Some(
                form.port
                    .parse::<u16>()
                    .wrap_err("Could not parse into port number")?
                    .into(),
            )
        };

        Ok(Self {
            hostname: form.hostname,
            port,
        })
    }
}

pub async fn create(
    conn: impl DbConnLike<'_>,
    owner: UserId,
    new_time_source: NewTimeSource,
) -> Result<TimeSource, sqlx::Error> {
    sqlx::query_as!(
        TimeSource,
        r#"
            INSERT INTO time_sources (owner, hostname, port)
            VALUES ($1, $2, $3)
            RETURNING id, owner, hostname, port AS "port: _", countries, weight
        "#,
        owner as _,
        new_time_source.hostname,
        new_time_source.port as _,
    )
    .fetch_one(conn)
    .await
}

pub async fn update(
    conn: impl DbConnLike<'_>,
    owner: UserId,
    time_source_id: TimeSourceId,
    time_source: UpdateTimeSourceForm,
) -> Result<TimeSource, sqlx::Error> {
    sqlx::query_as!(
        TimeSource,
        r#"
            UPDATE time_sources
            SET weight = $3
            WHERE id = $1 AND owner = $2
            RETURNING id, owner, hostname, port as "port: _", countries, weight
        "#,
        time_source_id as _,
        owner as _,
        time_source.weight
    )
    .fetch_one(conn)
    .await
}

pub async fn delete(
    conn: impl DbConnLike<'_>,
    owner: UserId,
    time_source_id: TimeSourceId,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
             UPDATE time_sources
             SET deleted = true
             WHERE id = $1 AND owner = $2;
        "#,
        time_source_id as _,
        owner as _,
    )
    .execute(conn)
    .await?;

    Ok(())
}

pub async fn by_user(
    conn: impl DbConnLike<'_>,
    owner: UserId,
) -> Result<Vec<TimeSource>, sqlx::Error> {
    sqlx::query_as!(
        TimeSource,
        r#"
            SELECT id, owner, hostname, port AS "port: _", countries, weight
            FROM time_sources
            WHERE owner = $1 AND deleted = false;
        "#,
        owner as _,
    )
    .fetch_all(conn)
    .await
}

pub async fn not_deleted(conn: impl DbConnLike<'_>) -> Result<Vec<TimeSource>, sqlx::Error> {
    sqlx::query_as!(
        TimeSource,
        r#"
            SELECT id, owner, hostname, port AS "port: _", countries, weight
            FROM time_sources
            WHERE deleted = false;
        "#,
    )
    .fetch_all(conn)
    .await
}
