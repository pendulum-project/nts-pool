use crate::{
    DbConnLike,
    models::{
        user::UserId,
        util::{port::Port, uuid},
    },
};

uuid!(ServerId);

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Server {
    pub id: ServerId,
    pub owner: UserId,
    pub hostname: String,
    pub port: Option<Port>,
    pub countries: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct NewServer {
    pub hostname: String,
    pub port: Option<Port>,
    pub countries: Vec<String>,
}

pub async fn create(
    conn: impl DbConnLike<'_>,
    owner: UserId,
    new_server: NewServer,
) -> Result<Server, sqlx::Error> {
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
    .fetch_one(conn)
    .await
}
