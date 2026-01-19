use axum::{extract::State, Extension, Json};
use std::sync::Arc;
use validator::Validate;

use crate::error::{AppError, Result};
use crate::middleware::AuthenticatedUser;
use crate::models::{UpdateUserRequest, UserProfile};
use crate::services::{TokenService, UserService};

#[derive(Clone)]
pub struct UserHandlerState {
    pub user_service: Arc<UserService>,
    pub token_service: Arc<TokenService>,
}

pub async fn get_profile(
    State(state): State<UserHandlerState>,
    Extension(user): Extension<AuthenticatedUser>,
) -> Result<Json<UserProfile>> {
    let profile = state.user_service.get_profile(&user.user_id).await?;
    Ok(Json(profile))
}

pub async fn update_profile(
    State(state): State<UserHandlerState>,
    Extension(user): Extension<AuthenticatedUser>,
    Json(request): Json<UpdateUserRequest>,
) -> Result<Json<UserProfile>> {
    request
        .validate()
        .map_err(|e| AppError::ValidationError(e.to_string()))?;

    let profile = state
        .user_service
        .update_profile(&user.user_id, &request)
        .await?;

    Ok(Json(profile))
}

pub async fn delete_account(
    State(state): State<UserHandlerState>,
    Extension(user): Extension<AuthenticatedUser>,
) -> Result<Json<serde_json::Value>> {
    state.token_service.revoke_all_user_tokens(&user.user_id);

    state.user_service.delete_account(&user.user_id).await?;

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Account has been deleted"
    })))
}
