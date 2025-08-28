use crate::models::user::{User, UserRole};

pub fn is_logged_in(user: &Option<User>, _: &dyn askama::Values) -> askama::Result<bool> {
    Ok(user
        .as_ref()
        .map(|user| user.is_activated() && !user.is_disabled())
        .unwrap_or(false))
}

pub fn is_administrator(user: &Option<User>, _: &dyn askama::Values) -> askama::Result<bool> {
    Ok(user
        .as_ref()
        .map(|user| {
            user.is_activated() && !user.is_disabled() && user.role == UserRole::Administrator
        })
        .unwrap_or(false))
}

pub fn is_manager(user: &Option<User>, _: &dyn askama::Values) -> askama::Result<bool> {
    Ok(user
        .as_ref()
        .map(|user| user.is_activated() && !user.is_disabled() && user.role == UserRole::Manager)
        .unwrap_or(false))
}

pub fn is_me(
    current_user: &Option<User>,
    _: &dyn askama::Values,
    user: &User,
) -> askama::Result<bool> {
    Ok(current_user
        .as_ref()
        .map(|u| u.id == user.id)
        .unwrap_or(false))
}
