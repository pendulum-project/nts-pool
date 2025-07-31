use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{DbConnLike, models::util::uuid};

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
pub async fn create(conn: impl DbConnLike<'_>, new_user: NewUser) -> Result<User, sqlx::Error> {
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
    .fetch_one(conn)
    .await
}

/// List all the users in the database
pub async fn list(conn: impl DbConnLike<'_>) -> Result<Vec<User>, sqlx::Error> {
    sqlx::query_as!(
        User,
        r#"
            SELECT id, email, role AS "role: _", created_at, updated_at
            FROM users
        "#
    )
    .fetch_all(conn)
    .await
}

/// Retrieve a user by their email address
pub async fn get_by_email(
    conn: impl DbConnLike<'_>,
    email: &str,
) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as!(
        User,
        r#"
            SELECT id, email, role AS "role: _", created_at, updated_at
            FROM users
            WHERE email = $1
        "#,
        email,
    )
    .fetch_optional(conn)
    .await
}
