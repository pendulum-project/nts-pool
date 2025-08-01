use crate::{auth::UserSession, models::user::UserRole};

pub fn is_logged_in(session: &Option<UserSession>, _: &dyn askama::Values) -> askama::Result<bool> {
    Ok(session.is_some())
}

pub fn is_administrator(
    session: &Option<UserSession>,
    _: &dyn askama::Values,
) -> askama::Result<bool> {
    Ok(session
        .as_ref()
        .map(|session| session.role == UserRole::Administrator)
        .unwrap_or(false))
}

pub fn is_server_manager(
    session: &Option<UserSession>,
    _: &dyn askama::Values,
) -> askama::Result<bool> {
    Ok(session
        .as_ref()
        .map(|session| session.role == UserRole::ServerManager)
        .unwrap_or(false))
}
