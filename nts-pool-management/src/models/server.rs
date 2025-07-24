use sqlx::{Acquire, Postgres};

use crate::models::{
    user::UserId,
    util::{port::Port, uuid},
};

uuid!(ServerId);

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Server {
    id: ServerId,
    owner: UserId,
    hostname: String,
    port: Option<Port>,
    countries: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct NewServer {
    hostname: String,
    port: Option<Port>,
    countries: Vec<String>,
}

pub async fn create(
    conn: impl Acquire<'_, Database = Postgres>,
    owner: UserId,
    new_server: NewServer,
) -> Result<Server, sqlx::Error> {
    let mut conn = conn.acquire().await?;

    sqlx::query_as!(
        Server,
        r#"
            INSERT INTO servers (owner, hostname, port, countries)
            VALUES ($1, $2, $3, $4)
            RETURNING id, owner, hostname, port AS "port: _", countries
        "#,
        owner as _,
        new_server.hostname,
        new_server.port as _,
        new_server.countries as _,
    )
    .fetch_one(&mut *conn)
    .await
}
