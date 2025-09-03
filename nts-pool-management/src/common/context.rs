use axum::{
    extract::{FromRequestParts, OriginalUri, Request, State},
    http::request::Parts,
    middleware::Next,
    response::{IntoResponse, Response},
};
use eyre::{Context, OptionExt};

use crate::{
    AppState,
    auth::{Administrator, IntoUserOption, Session, UnsafeLoggedInUser},
    config::BaseUrl,
    error::AppError,
};

#[derive(Clone, Debug)]
pub struct AppContext {
    pub path: String,
    pub user: Option<UnsafeLoggedInUser>,
    pub parent_user: Option<Administrator>,
    pub base_url: BaseUrl,
}

impl Default for AppContext {
    fn default() -> Self {
        Self {
            path: "/".to_string(),
            user: Default::default(),
            parent_user: Default::default(),
            base_url: "http://localhost:3000".into(),
        }
    }
}

impl AppContext {
    pub fn with_user(mut self, user: impl IntoUserOption) -> Self {
        self.user = user.into_user_option().map(UnsafeLoggedInUser);
        self
    }

    pub fn with_base_url(mut self, base_url: impl Into<BaseUrl>) -> Self {
        self.base_url = base_url.into();
        self
    }
}

pub async fn context_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let (mut parts, body) = request.into_parts();
    let context = match extract_context(&mut parts, &state).await {
        Ok(ctx) => ctx,
        Err(err) => {
            return err.into_response();
        }
    };
    let mut request = Request::from_parts(parts, body);

    request.extensions_mut().insert(context.clone());
    let mut response = next.run(request).await;
    response.extensions_mut().insert(context);
    response
}

async fn extract_context(parts: &mut Parts, state: &AppState) -> Result<AppContext, AppError> {
    let uri = OriginalUri::from_request_parts(parts, state)
        .await
        .wrap_err("Cannot extract original URI")?;
    let path = uri.path().to_string();

    let (user, parent_user) = parts
        .extensions
        .get::<Option<Session>>()
        .and_then(|outer| {
            outer
                .as_ref()
                .map(|session| (session.user().clone(), session.parent().cloned()))
        })
        .unzip();
    let parent_user = parent_user.flatten();

    Ok(AppContext {
        path,
        user,
        parent_user,
        base_url: state.config.base_url.clone(),
    })
}

impl FromRequestParts<AppState> for AppContext {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        Ok(parts
            .extensions
            .get::<Self>()
            .cloned()
            .ok_or_eyre("AppContext not found in request extensions, might not be initialized")?)
    }
}
