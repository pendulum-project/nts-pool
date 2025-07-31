use argon2::{
    Argon2, PasswordHash,
    password_hash::{SaltString, rand_core::OsRng},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{Acquire, Postgres, types::Json};

use crate::models::{user::UserId, util::uuid};

uuid!(AuthenticationMethodId);

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AuthenticationMethod {
    pub id: AuthenticationMethodId,
    pub user_id: UserId,
    pub variant: Json<AuthenticationVariant>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
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
}

impl PasswordAuthentication {
    pub fn new(password: &str) -> Result<Self, argon2::password_hash::Error> {
        let password_hash = hash_password(password)?;
        Ok(Self {
            phc_string: password_hash,
        })
    }

    pub fn update_password(
        &mut self,
        new_password: &str,
    ) -> Result<(), argon2::password_hash::Error> {
        self.phc_string = hash_password(new_password)?;
        Ok(())
    }

    pub fn verify(&self, password: &str) -> Result<bool, argon2::password_hash::Error> {
        use argon2::PasswordVerifier;

        let parsed_hash = PasswordHash::new(&self.phc_string)?;
        Ok(Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok())
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

pub async fn get_password_authentication_method(
    conn: impl Acquire<'_, Database = Postgres>,
    user_id: UserId,
) -> Result<Option<PasswordAuthentication>, sqlx::Error> {
    let mut conn = conn.acquire().await?;

    let auth_method = sqlx::query_as!(
        AuthenticationMethod,
        r#"
            SELECT id, user_id, variant AS "variant: _", created_at, updated_at
            FROM authentication_methods
            WHERE user_id = $1 AND variant_type = 'password'
        "#,
        user_id as _
    )
    .fetch_optional(&mut *conn)
    .await?;

    if let Some(auth_method) = auth_method {
        // TODO: remove when multiple authentication variants are supported
        #[allow(irrefutable_let_patterns)]
        if let Json(AuthenticationVariant::Password(p)) = auth_method.variant {
            return Ok(Some(p));
        }
    }

    Ok(None)
}

pub async fn create(
    conn: impl Acquire<'_, Database = Postgres>,
    user_id: UserId,
    variant: AuthenticationVariant,
) -> Result<AuthenticationMethod, sqlx::Error> {
    let mut conn = conn.acquire().await?;

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
    .fetch_one(&mut *conn)
    .await
}
