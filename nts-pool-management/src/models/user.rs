use chrono::{DateTime, Utc};
use derive_more::Display;
use serde::{Deserialize, Serialize};

use crate::{DbConnLike, models::util::uuid, pagination::SortDirection};

uuid!(UserId);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Display, sqlx::Type)]
#[serde(rename_all = "kebab-case")]
#[sqlx(type_name = "user_role")]
#[sqlx(rename_all = "kebab-case")]
pub enum UserRole {
    Administrator,
    Manager,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct User {
    pub id: UserId,
    pub email: String,
    pub role: UserRole,
    pub session_revoke_token: String,
    pub activation_token: Option<String>,
    pub activation_expires_at: Option<DateTime<Utc>>,
    pub activated_since: Option<DateTime<Utc>>,
    pub last_login_at: DateTime<Utc>,
    pub disabled_since: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl User {
    pub fn is_activated(&self) -> bool {
        self.activated_since
            .map(|since| Utc::now() > since)
            .unwrap_or(false)
    }

    pub fn is_disabled(&self) -> bool {
        self.disabled_since
            .map(|since| Utc::now() > since)
            .unwrap_or(false)
    }

    #[cfg(test)]
    pub fn test_admin() -> Self {
        use uuid::Uuid;

        Self {
            id: Uuid::new_v4().into(),
            email: "admin@example.com".to_string(),
            role: UserRole::Administrator,
            session_revoke_token: "".into(),
            activation_token: None,
            activation_expires_at: None,
            activated_since: Some(chrono::Utc::now() - chrono::TimeDelta::seconds(10)),
            last_login_at: chrono::Utc::now(),
            disabled_since: None,
            created_at: chrono::Utc::now() - chrono::TimeDelta::seconds(20),
            updated_at: chrono::Utc::now(),
        }
    }

    #[cfg(test)]
    pub fn test_manager() -> Self {
        use uuid::Uuid;
        Self {
            id: Uuid::new_v4().into(),
            email: "manager@example.com".to_string(),
            role: UserRole::Manager,
            session_revoke_token: "".into(),
            activation_token: None,
            activation_expires_at: None,
            activated_since: Some(chrono::Utc::now() - chrono::TimeDelta::seconds(10)),
            last_login_at: chrono::Utc::now(),
            disabled_since: None,
            created_at: chrono::Utc::now() - chrono::TimeDelta::seconds(20),
            updated_at: chrono::Utc::now(),
        }
    }

    #[cfg(test)]
    pub fn test_disabled_manager() -> Self {
        use uuid::Uuid;
        Self {
            id: Uuid::new_v4().into(),
            email: "manager+disabled@example.com".to_string(),
            role: UserRole::Manager,
            session_revoke_token: "".into(),
            activation_token: None,
            activation_expires_at: None,
            activated_since: Some(chrono::Utc::now() - chrono::TimeDelta::seconds(100)),
            last_login_at: chrono::Utc::now(),
            disabled_since: Some(chrono::Utc::now() - chrono::TimeDelta::seconds(60)),
            created_at: chrono::Utc::now() - chrono::TimeDelta::seconds(120),
            updated_at: chrono::Utc::now(),
        }
    }

    #[cfg(test)]
    pub fn test_not_activated_manager() -> Self {
        use uuid::Uuid;
        Self {
            id: Uuid::new_v4().into(),
            email: "manager+not-activated@example.com".to_string(),
            role: UserRole::Manager,
            session_revoke_token: "".into(),
            activation_token: Some("some-token".to_string()),
            activation_expires_at: Some(chrono::Utc::now() + chrono::TimeDelta::seconds(3600)),
            activated_since: None,
            last_login_at: chrono::Utc::now(),
            disabled_since: None,
            created_at: chrono::Utc::now() - chrono::TimeDelta::seconds(120),
            updated_at: chrono::Utc::now(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct NewUser {
    pub email: String,
    pub role: UserRole,
    pub session_revoke_token: String,
    pub activation_token: String,
    pub activation_expires_at: DateTime<Utc>,
}

#[derive(Default, Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserSort {
    #[default]
    CreatedAt,
    Email,
    DisabledSince,
    LastLoginAt,
    Role,
}

impl AsRef<str> for UserSort {
    fn as_ref(&self) -> &str {
        match self {
            UserSort::CreatedAt => "created_at",
            UserSort::Email => "email",
            UserSort::DisabledSince => "disabled_since",
            UserSort::LastLoginAt => "last_login_at",
            UserSort::Role => "role",
        }
    }
}

/// Create a new user with the given email
pub async fn create(conn: impl DbConnLike<'_>, new_user: NewUser) -> Result<User, sqlx::Error> {
    sqlx::query_as!(
        User,
        r#"
            INSERT INTO users (email, role, session_revoke_token, activation_token, activation_expires_at)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id, email, role AS "role: _", session_revoke_token, activation_token, activation_expires_at, activated_since, last_login_at, disabled_since, created_at, updated_at
        "#,
        new_user.email,
        new_user.role as _,
        new_user.session_revoke_token,
        new_user.activation_token,
        new_user.activation_expires_at,
    )
    .fetch_one(conn)
    .await
}

/// List all the users in the database
pub async fn list(
    conn: impl DbConnLike<'_>,
    limit: i64,
    offset: i64,
    sort_field: &UserSort,
    sort_direction: &SortDirection,
) -> Result<Vec<User>, sqlx::Error> {
    dbg!(limit, offset);
    sqlx::query_as!(
        User,
        r#"
            SELECT id, email, role AS "role: _", session_revoke_token, activation_token, activation_expires_at, activated_since, last_login_at, disabled_since, created_at, updated_at
            FROM users
            ORDER BY
              CASE WHEN $3 = 'email' AND $4 = 'asc' THEN email END ASC,
              CASE WHEN $3 = 'email' AND $4 = 'desc' THEN email END DESC,
              CASE WHEN $3 = 'last_login_at' AND $4 = 'asc' THEN last_login_at END ASC,
              CASE WHEN $3 = 'last_login_at' AND $4 = 'desc' THEN last_login_at END DESC,
              CASE WHEN $3 = 'disabled_since' AND $4 = 'asc' THEN disabled_since END ASC,
              CASE WHEN $3 = 'disabled_since' AND $4 = 'desc' THEN disabled_since END DESC,
              CASE WHEN $3 = 'role' AND $4 = 'asc' THEN role END ASC,
              CASE WHEN $3 = 'role' AND $4 = 'desc' THEN role END DESC,
              created_at DESC
            LIMIT $1
            OFFSET $2
        "#,
        limit,
        offset,
        sort_field.as_ref(),
        sort_direction.as_ref(),
    )
    .fetch_all(conn)
    .await
}

pub async fn count(conn: impl DbConnLike<'_>) -> Result<i64, sqlx::Error> {
    Ok(sqlx::query!(
        r#"
        SELECT COUNT(*) as "count!"
        FROM users
        "#
    )
    .fetch_one(conn)
    .await?
    .count)
}

/// Retrieve a user by their email address
pub async fn get_by_email(
    conn: impl DbConnLike<'_>,
    email: &str,
) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as!(
        User,
        r#"
            SELECT id, email, role AS "role: _", session_revoke_token, activation_token, activation_expires_at, activated_since, last_login_at, disabled_since, created_at, updated_at
            FROM users
            WHERE email = $1
        "#,
        email,
    )
    .fetch_optional(conn)
    .await
}

pub async fn get_by_id(conn: impl DbConnLike<'_>, id: UserId) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as!(
        User,
        r#"
            SELECT id, email, role AS "role: _", session_revoke_token, activation_token, activation_expires_at, activated_since, last_login_at, disabled_since, created_at, updated_at
            FROM users
            WHERE id = $1
        "#,
        id as _,
    )
    .fetch_optional(conn)
    .await
}

pub async fn set_activation_token(
    conn: impl DbConnLike<'_>,
    id: UserId,
    activation_token: String,
    expires: DateTime<Utc>,
) -> Result<User, sqlx::Error> {
    sqlx::query_as!(
        User,
        r#"
            UPDATE users
            SET activation_token = $1, activation_expires_at = $2
            WHERE id = $3
            RETURNING id, email, role AS "role: _", session_revoke_token, activation_token, activation_expires_at, activated_since, last_login_at, disabled_since, created_at, updated_at
        "#,
        activation_token,
        expires,
        id as _,
    )
    .fetch_one(conn)
    .await
}

pub async fn activate_user(conn: impl DbConnLike<'_>, id: UserId) -> Result<User, sqlx::Error> {
    sqlx::query_as!(
        User,
        r#"
            UPDATE users
            SET activated_since = NOW(), activation_token = NULL, activation_expires_at = NULL
            WHERE id = $1
            RETURNING id, email, role AS "role: _", session_revoke_token, activation_token, activation_expires_at, activated_since, last_login_at, disabled_since, created_at, updated_at
        "#,
        id as _,
    )
    .fetch_one(conn)
    .await
}

pub async fn block_user(conn: impl DbConnLike<'_>, id: UserId) -> Result<User, sqlx::Error> {
    sqlx::query_as!(
        User,
        r#"
            UPDATE users
            SET disabled_since = NOW()
            WHERE id = $1
            RETURNING id, email, role AS "role: _", session_revoke_token, activation_token, activation_expires_at, activated_since, last_login_at, disabled_since, created_at, updated_at
        "#,
        id as _,
    )
    .fetch_one(conn)
    .await
}

pub async fn unblock_user(conn: impl DbConnLike<'_>, id: UserId) -> Result<User, sqlx::Error> {
    sqlx::query_as!(
        User,
        r#"
            UPDATE users
            SET disabled_since = NULL
            WHERE id = $1
            RETURNING id, email, role AS "role: _", session_revoke_token, activation_token, activation_expires_at, activated_since, last_login_at, disabled_since, created_at, updated_at
        "#,
        id as _,
    )
    .fetch_one(conn)
    .await
}

pub async fn update_last_login(conn: impl DbConnLike<'_>, id: UserId) -> Result<User, sqlx::Error> {
    sqlx::query_as!(
        User,
        r#"
            UPDATE users
            SET last_login_at = NOW()
            WHERE id = $1
            RETURNING id, email, role AS "role: _", session_revoke_token, activation_token, activation_expires_at, activated_since, last_login_at, disabled_since, created_at, updated_at
        "#,
        id as _,
    )
    .fetch_one(conn)
    .await
}

pub async fn update_session_revoke_token(
    conn: impl DbConnLike<'_>,
    id: UserId,
    session_revoke_token: String,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
            UPDATE users
            SET session_revoke_token = $1
            WHERE id = $2
        "#,
        session_revoke_token,
        id as _,
    )
    .fetch_optional(conn)
    .await?;
    Ok(())
}
