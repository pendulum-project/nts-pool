use serde::Deserialize;

use crate::{
    DbConnLike,
    models::{
        user::UserId,
        util::{port::Port, uuid},
    },
};

uuid!(TimeSourceId);

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TimeSource {
    pub id: TimeSourceId,
    pub owner: UserId,
    pub hostname: String,
    pub port: Option<Port>,
    pub countries: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct NewTimeSource {
    pub hostname: String,
    pub port: Option<Port>,
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
            RETURNING id, owner, hostname, port AS "port: _", countries
        "#,
        owner as _,
        new_time_source.hostname,
        new_time_source.port as _,
    )
    .fetch_one(conn)
    .await
}
