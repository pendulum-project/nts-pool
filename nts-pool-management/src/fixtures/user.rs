use eyre::Context as _;
use sqlx::PgConnection;

use crate::{
    fixtures::{FixtureContext, FixtureError},
    models::{
        authentication_method::{self, AuthenticationVariant, PasswordAuthentication},
        user::{self, NewUser, UserRole},
    },
};

async fn administrator(
    conn: &mut PgConnection,
    context: FixtureContext,
) -> Result<FixtureContext, FixtureError> {
    let email = context.get_clone_or_else("admin-email", || "admin@example.com".to_string());
    let administrator = NewUser {
        email,
        role: UserRole::Administrator,
        session_revoke_token: crate::auth::generate_session_revoke_token(),
        activation_token: "test".into(),
        activation_expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
    };
    let administrator = user::create(&mut *conn, administrator).await?;
    user::activate_user(&mut *conn, administrator.id).await?;

    authentication_method::create(
        &mut *conn,
        administrator.id,
        AuthenticationVariant::Password(
            PasswordAuthentication::new("admin").wrap_err("Password hashing failed")?,
        ),
    )
    .await?;

    Ok(context.with("admin", administrator.id))
}

async fn manager(
    conn: &mut PgConnection,
    context: FixtureContext,
) -> Result<FixtureContext, FixtureError> {
    let email = context.get_clone_or_else("manager-email", || "manager@example.com".to_string());
    let manager = NewUser {
        email,
        role: UserRole::Manager,
        session_revoke_token: crate::auth::generate_session_revoke_token(),
        activation_token: "test".into(),
        activation_expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
    };
    let manager = user::create(&mut *conn, manager).await?;
    user::activate_user(&mut *conn, manager.id).await?;

    authentication_method::create(
        &mut *conn,
        manager.id,
        AuthenticationVariant::Password(
            PasswordAuthentication::new("manager").wrap_err("Password hashing failed")?,
        ),
    )
    .await?;

    Ok(context.with("manager", manager.id))
}

async fn blocked_manager(
    conn: &mut PgConnection,
    context: FixtureContext,
) -> Result<FixtureContext, FixtureError> {
    let email = context.get_clone_or_else("blocked-manager-email", || {
        "blocked_manager@example.com".to_string()
    });
    let blocked_manager = NewUser {
        email,
        role: UserRole::Manager,
        session_revoke_token: crate::auth::generate_session_revoke_token(),
        activation_token: "test".into(),
        activation_expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
    };
    let blocked_manager = user::create(&mut *conn, blocked_manager).await?;
    user::activate_user(&mut *conn, blocked_manager.id).await?;
    user::block_user(&mut *conn, blocked_manager.id).await?;

    authentication_method::create(
        &mut *conn,
        blocked_manager.id,
        AuthenticationVariant::Password(
            PasswordAuthentication::new("blocked").wrap_err("Password hashing failed")?,
        ),
    )
    .await?;

    Ok(context.with("blocked_manager", blocked_manager.id))
}

async fn not_activated_manager(
    conn: &mut PgConnection,
    context: FixtureContext,
) -> Result<FixtureContext, FixtureError> {
    let email = context.get_clone_or_else("not-activated-manager-email", || {
        "not_activated_manager@example.com".to_string()
    });

    let not_activated_manager = NewUser {
        email,
        role: UserRole::Manager,
        session_revoke_token: crate::auth::generate_session_revoke_token(),
        activation_token: "test".into(),
        activation_expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
    };
    let not_activated_manager = user::create(&mut *conn, not_activated_manager).await?;

    authentication_method::create(
        &mut *conn,
        not_activated_manager.id,
        AuthenticationVariant::Password(
            PasswordAuthentication::new("not-activated").wrap_err("Password hashing failed")?,
        ),
    )
    .await?;

    Ok(context.with("not_activated_manager", not_activated_manager.id))
}

pub async fn fixture(
    conn: &mut PgConnection,
    mut context: FixtureContext,
) -> Result<FixtureContext, FixtureError> {
    context = administrator(conn, context).await?;
    context = manager(conn, context).await?;
    context = blocked_manager(conn, context).await?;
    context = not_activated_manager(conn, context).await?;

    Ok(context)
}
