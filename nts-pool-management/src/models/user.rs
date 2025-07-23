use chrono::{DateTime, Utc};
use sqlx::{Acquire, Postgres};

use crate::models::util::uuid;

uuid!(UserId);

#[derive(Debug, Clone)]
pub struct User {
    pub id: UserId,
    pub email: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct NewUser {
    email: String,
}

/// Create a new user with the given email
pub async fn create(
    conn: impl Acquire<'_, Database = Postgres>,
    new_user: NewUser,
) -> Result<User, sqlx::Error> {
    let mut conn = conn.acquire().await?;

    sqlx::query_as!(
        User,
        r#"
            INSERT INTO users (email)
            VALUES ($1)
            RETURNING id, email, created_at, updated_at
        "#,
        new_user.email,
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
