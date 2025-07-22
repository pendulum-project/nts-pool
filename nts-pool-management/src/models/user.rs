use chrono::{DateTime, Utc};
use sqlx::{Acquire, Postgres};
use uuid::Uuid;

pub struct User {
    pub id: Uuid,
    pub email: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Create a new user with the given email
pub async fn create(
    conn: impl Acquire<'_, Database = Postgres>,
    email: &str,
) -> Result<User, sqlx::Error> {
    let mut conn = conn.acquire().await?;

    sqlx::query_as!(
        User,
        r#"
            INSERT INTO users (email)
            VALUES ($1)
            RETURNING id, email, created_at, updated_at
        "#,
        email,
    )
    .fetch_one(&mut *conn)
    .await
}

/// List all the users in the database
pub async fn list(conn: impl Acquire<'_, Database = Postgres>) -> Result<Vec<User>, sqlx::Error> {
    let mut conn = conn.acquire().await?;

    sqlx::query_as!(
        User,
        r#"
            SELECT id, email, created_at, updated_at
            FROM users
        "#
    )
    .fetch_all(&mut *conn)
    .await
}

/// Retrieve a user by their email address
pub async fn get_by_email(
    conn: impl Acquire<'_, Database = Postgres>,
    email: &str,
) -> Result<Option<User>, sqlx::Error> {
    let mut conn = conn.acquire().await?;

    sqlx::query_as!(
        User,
        r#"
            SELECT id, email, created_at, updated_at
            FROM users
            WHERE email = $1
        "#,
        email,
    )
    .fetch_optional(&mut *conn)
    .await
}
