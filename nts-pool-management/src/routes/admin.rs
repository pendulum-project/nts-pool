use askama::Template;
use axum::{
    extract::{Path, State},
    response::{IntoResponse, Redirect},
};
use axum_extra::extract::CookieJar;
use eyre::{Context, OptionExt, eyre};

use crate::{
    AppState,
    auth::{Administrator, JwtClaims, login_into},
    context::AppContext,
    error::AppError,
    models::user::{self, User, UserId},
    templates::{HtmlTemplate, filters},
};

#[derive(Template)]
#[template(path = "admin/overview.html.j2")]
struct OverviewTemplate {
    app: AppContext,
}

pub async fn overview(
    _admin: Administrator,
    app: AppContext,
) -> Result<impl IntoResponse, AppError> {
    Ok(HtmlTemplate(OverviewTemplate { app }))
}

#[derive(Template)]
#[template(path = "admin/users.html.j2")]
struct UsersTemplate {
    app: AppContext,
    users: Vec<User>,
}

pub async fn users(
    _admin: Administrator,
    app: AppContext,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    let users = user::list(&state.db).await?;
    Ok(HtmlTemplate(UsersTemplate { app, users }))
}

pub async fn user_block(
    admin: Administrator,
    Path(user_id): Path<UserId>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    // Prevent the admin from block themself
    if admin.id != user_id {
        user::block_user(&state.db, user_id).await?;
    }

    Ok(Redirect::to("/admin/users"))
}

pub async fn user_unblock(
    _admin: Administrator,
    Path(user_id): Path<UserId>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    user::unblock_user(&state.db, user_id).await?;

    Ok(Redirect::to("/admin/users"))
}

pub async fn login_as(
    claims: JwtClaims,
    admin: Administrator,
    cookie_jar: CookieJar,
    Path(user_id): Path<UserId>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    if claims.parent.is_some() {
        return Err(
            eyre!("Cannot login as another user when already logged in as another user").into(),
        );
    }
    let user = user::get_by_id(&state.db, user_id)
        .await?
        .ok_or_eyre("User not found")?;
    let cookie_jar = login_into(
        &user,
        Some(&admin),
        None,
        &state.jwt_encoding_key,
        cookie_jar,
    )
    .wrap_err("Failed to switch to user")?;
    Ok((cookie_jar, Redirect::to("/")))
}
