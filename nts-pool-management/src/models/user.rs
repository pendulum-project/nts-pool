use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{Acquire, Postgres};

use crate::models::util::uuid;

uuid!(UserId);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[serde(rename_all = "kebab-case")]
#[sqlx(type_name = "user_role")]
#[sqlx(rename_all = "kebab-case")]
pub enum UserRole {
    Administrator,
    ServerManager,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct User {
    pub id: UserId,
    pub email: String,
    pub role: UserRole,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct NewUser {
    pub email: String,
    pub role: UserRole,
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
            INSERT INTO users (email, role)
            VALUES ($1, $2)
            RETURNING id, email, role AS "role: _", created_at, updated_at
        "#,
        new_user.email,
        new_user.role as _,
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
            SELECT id, email, role AS "role: _", created_at, updated_at
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
            SELECT id, email, role AS "role: _", created_at, updated_at
            FROM users
            WHERE email = $1
        "#,
        email,
    )
    .fetch_optional(&mut *conn)
    .await
}
