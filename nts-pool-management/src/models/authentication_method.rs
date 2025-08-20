use argon2::{
    Argon2, PasswordHash,
    password_hash::{SaltString, rand_core::OsRng},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::types::Json;

use crate::{
    DbConnLike,
    models::{user::UserId, util::uuid},
};

uuid!(AuthenticationMethodId);

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AuthenticationMethod {
    pub id: AuthenticationMethodId,
    pub user_id: UserId,
    pub variant: Json<AuthenticationVariant>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl AuthenticationMethod {
    pub fn as_password_variant(&self) -> Option<&PasswordAuthentication> {
        match self.variant.as_ref() {
            AuthenticationVariant::Password(password) => Some(password),
        }
    }

    pub fn as_password_variant_mut(&mut self) -> Option<&mut PasswordAuthentication> {
        match self.variant.as_mut() {
            AuthenticationVariant::Password(password) => Some(password),
        }
    }

    pub fn into_password_variant(self) -> Option<PasswordAuthentication> {
        match self.variant.0 {
            AuthenticationVariant::Password(password) => Some(password),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum AuthenticationVariant {
    Password(PasswordAuthentication),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordAuthentication {
    /// See https://github.com/P-H-C/phc-string-format for format details
    phc_string: String,
    pub password_reset_token: Option<String>,
    pub password_reset_token_expires_at: Option<DateTime<Utc>>,
}

impl PasswordAuthentication {
    pub fn new(password: &str) -> Result<Self, argon2::password_hash::Error> {
        let password_hash = hash_password(password)?;
        Ok(Self {
            phc_string: password_hash,
            password_reset_token: None,
            password_reset_token_expires_at: None,
        })
    }

    pub fn update_password(
        &mut self,
        new_password: &str,
    ) -> Result<(), argon2::password_hash::Error> {
        self.phc_string = hash_password(new_password)?;
        self.password_reset_token = None;
        self.password_reset_token_expires_at = None;
        Ok(())
    }

    pub fn verify(&self, password: &str) -> Result<bool, argon2::password_hash::Error> {
        use argon2::PasswordVerifier;

        let parsed_hash = PasswordHash::new(&self.phc_string)?;
        Ok(Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok())
    }

    pub(crate) fn set_password_reset_token(&mut self, token: &str, expires_at: DateTime<Utc>) {
        self.password_reset_token = Some(token.to_string());
        self.password_reset_token_expires_at = Some(expires_at);
    }
}

fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    use argon2::PasswordHasher;

    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    Ok(argon2
        .hash_password(password.as_bytes(), &salt)?
        .to_string())
}

pub async fn get_password_authentication_method_row(
    conn: impl DbConnLike<'_>,
    user_id: UserId,
) -> Result<Option<AuthenticationMethod>, sqlx::Error> {
    sqlx::query_as!(
        AuthenticationMethod,
        r#"
            SELECT id, user_id, variant AS "variant: _", created_at, updated_at
            FROM authentication_methods
            WHERE user_id = $1 AND variant_type = 'password'
        "#,
        user_id as _
    )
    .fetch_optional(conn)
    .await
}

pub async fn get_password_authentication_method(
    conn: impl DbConnLike<'_>,
    user_id: UserId,
) -> Result<Option<PasswordAuthentication>, sqlx::Error> {
    Ok(get_password_authentication_method_row(conn, user_id)
        .await?
        .and_then(|auth_method| auth_method.into_password_variant()))
}

pub async fn update_variant(
    conn: impl DbConnLike<'_>,
    auth_id: AuthenticationMethodId,
    variant: AuthenticationVariant,
) -> Result<AuthenticationMethod, sqlx::Error> {
    sqlx::query_as!(
        AuthenticationMethod,
        r#"
            UPDATE authentication_methods
            SET variant = $1, updated_at = NOW()
            WHERE id = $2
            RETURNING id, user_id, variant AS "variant: _", created_at, updated_at
        "#,
        Json(variant) as _,
        auth_id as _
    )
    .fetch_one(conn)
    .await
}

pub async fn create(
    conn: impl DbConnLike<'_>,
    user_id: UserId,
    variant: AuthenticationVariant,
) -> Result<AuthenticationMethod, sqlx::Error> {
    sqlx::query_as!(
        AuthenticationMethod,
        r#"
            INSERT INTO authentication_methods (user_id, variant)
            VALUES ($1, $2)
            RETURNING id, user_id, variant AS "variant: _", created_at, updated_at
        "#,
        user_id as _,
        Json(variant) as _,
    )
    .fetch_one(conn)
    .await
}
