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
    Manager,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct User {
    pub id: UserId,
    pub email: String,
    pub role: UserRole,
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
    pub activation_token: String,
    pub activation_expires_at: DateTime<Utc>,
}

/// Create a new user with the given email
pub async fn create(conn: impl DbConnLike<'_>, new_user: NewUser) -> Result<User, sqlx::Error> {
    sqlx::query_as!(
        User,
        r#"
            INSERT INTO users (email, role, activation_token, activation_expires_at)
            VALUES ($1, $2, $3, $4)
            RETURNING id, email, role AS "role: _", activation_token, activation_expires_at, activated_since, last_login_at, disabled_since, created_at, updated_at
        "#,
        new_user.email,
        new_user.role as _,
        new_user.activation_token,
        new_user.activation_expires_at,
    )
    .fetch_one(conn)
    .await
}

/// List all the users in the database
pub async fn list(conn: impl DbConnLike<'_>) -> Result<Vec<User>, sqlx::Error> {
    sqlx::query_as!(
        User,
        r#"
            SELECT id, email, role AS "role: _", activation_token, activation_expires_at, activated_since, last_login_at, disabled_since, created_at, updated_at
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
            SELECT id, email, role AS "role: _", activation_token, activation_expires_at, activated_since, last_login_at, disabled_since, created_at, updated_at
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
            SELECT id, email, role AS "role: _", activation_token, activation_expires_at, activated_since, last_login_at, disabled_since, created_at, updated_at
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
            RETURNING id, email, role AS "role: _", activation_token, activation_expires_at, activated_since, last_login_at, disabled_since, created_at, updated_at
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
            RETURNING id, email, role AS "role: _", activation_token, activation_expires_at, activated_since, last_login_at, disabled_since, created_at, updated_at
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
            RETURNING id, email, role AS "role: _", activation_token, activation_expires_at, activated_since, last_login_at, disabled_since, created_at, updated_at
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
            RETURNING id, email, role AS "role: _", activation_token, activation_expires_at, activated_since, last_login_at, disabled_since, created_at, updated_at
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
            RETURNING id, email, role AS "role: _", activation_token, activation_expires_at, activated_since, last_login_at, disabled_since, created_at, updated_at
        "#,
        id as _,
    )
    .fetch_one(conn)
    .await
}
