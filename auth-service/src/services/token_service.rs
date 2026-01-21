use chrono::Utc;
use dashmap::DashMap;
use std::sync::Arc;

use crate::db::UserRepository;
use crate::error::{AppError, Result};
use crate::models::{DeviceInfo, RefreshTokenFamily, TokenPair, ValidateTokenResponse};
use crate::security::JwtService;

pub struct TokenService {
    jwt_service: Arc<JwtService>,
    user_repository: Arc<UserRepository>,
    refresh_token_families: Arc<DashMap<String, RefreshTokenFamily>>,
    revoked_families: Arc<DashMap<String, ()>>,
}

impl TokenService {
    #[must_use]
    pub fn new(jwt_service: Arc<JwtService>, user_repository: Arc<UserRepository>) -> Self {
        Self {
            jwt_service,
            user_repository,
            refresh_token_families: Arc::new(DashMap::new()),
            revoked_families: Arc::new(DashMap::new()),
        }
    }

    pub async fn refresh_token(
        &self,
        refresh_token: &str,
        client_project: Option<&str>,
        device_info: Option<&DeviceInfo>,
    ) -> Result<TokenPair> {
        let claims = self.jwt_service.verify_refresh_token(refresh_token)?;

        if self.revoked_families.contains_key(&claims.family_id) {
            tracing::warn!(
                family_id = %claims.family_id,
                user_id = %claims.sub,
                "Attempted to use refresh token from revoked family - possible token reuse attack"
            );
            self.revoke_all_user_tokens(&claims.sub);
            return Err(AppError::InvalidToken);
        }

        // Verify device binding if present in the token
        if let (Some(token_device_hash), Some(current_device)) = (&claims.device_hash, device_info)
        {
            let current_hash = current_device.compute_hash();
            if &current_hash != token_device_hash {
                tracing::warn!(
                    family_id = %claims.family_id,
                    user_id = %claims.sub,
                    "Device mismatch detected during token refresh - possible token theft"
                );
                // Revoke this token family but don't revoke all user tokens
                // (user might have legitimately changed devices)
                self.revoked_families.insert(claims.family_id.clone(), ());
                return Err(AppError::DeviceMismatch);
            }
        }

        if let Some(family) = self.refresh_token_families.get(&claims.family_id) {
            if family.is_revoked {
                tracing::warn!(
                    family_id = %claims.family_id,
                    user_id = %claims.sub,
                    "Attempted to use revoked refresh token family"
                );
                return Err(AppError::InvalidToken);
            }

            if claims.generation < family.current_generation {
                tracing::warn!(
                    family_id = %claims.family_id,
                    user_id = %claims.sub,
                    claimed_gen = claims.generation,
                    current_gen = family.current_generation,
                    "Token reuse attack detected - revoking all tokens for user"
                );
                drop(family);
                self.revoke_all_user_tokens(&claims.sub);
                return Err(AppError::InvalidToken);
            }
        }

        let user = self
            .user_repository
            .find_by_id(&claims.sub)
            .await?
            .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

        if !user.is_active {
            return Err(AppError::Forbidden);
        }

        let new_generation = claims.generation + 1;

        // Compute device hash for the new token
        let device_hash = device_info.map(DeviceInfo::compute_hash);

        let now = Utc::now().to_rfc3339();
        self.refresh_token_families.insert(
            claims.family_id.clone(),
            RefreshTokenFamily {
                family_id: claims.family_id.clone(),
                user_id: claims.sub.clone(),
                current_generation: new_generation,
                created_at: now.clone(),
                last_used_at: now,
                is_revoked: false,
            },
        );

        let token_pair = self.jwt_service.create_token_pair(
            &user.id,
            &user.email,
            client_project,
            Some(&claims.family_id),
            new_generation,
            device_hash.as_deref(),
        )?;

        tracing::info!(
            user_id = %user.id,
            family_id = %claims.family_id,
            generation = new_generation,
            device_bound = device_hash.is_some(),
            "Refresh token rotated"
        );

        Ok(token_pair)
    }

    pub fn validate_access_token(&self, token: &str) -> Result<ValidateTokenResponse> {
        match self.jwt_service.verify_access_token(token) {
            Ok(claims) => Ok(ValidateTokenResponse {
                valid: true,
                user_id: Some(claims.sub),
                email: Some(claims.email),
                expires_at: Some(claims.exp),
            }),
            Err(AppError::TokenExpired) | Err(_) => Ok(ValidateTokenResponse {
                valid: false,
                user_id: None,
                email: None,
                expires_at: None,
            }),
        }
    }

    pub fn revoke_refresh_token(&self, refresh_token: &str) -> Result<()> {
        let claims = self.jwt_service.verify_refresh_token(refresh_token)?;

        self.revoked_families.insert(claims.family_id.clone(), ());

        if let Some(mut family) = self.refresh_token_families.get_mut(&claims.family_id) {
            family.is_revoked = true;
        }

        tracing::info!(
            family_id = %claims.family_id,
            user_id = %claims.sub,
            "Refresh token family revoked"
        );

        Ok(())
    }

    pub fn revoke_all_user_tokens(&self, user_id: &str) {
        let families_to_revoke: Vec<String> = self
            .refresh_token_families
            .iter()
            .filter(|entry| entry.user_id == user_id)
            .map(|entry| entry.family_id.clone())
            .collect();

        for family_id in families_to_revoke {
            self.revoked_families.insert(family_id.clone(), ());
            if let Some(mut family) = self.refresh_token_families.get_mut(&family_id) {
                family.is_revoked = true;
            }
        }

        tracing::info!(
            user_id = %user_id,
            "All refresh token families revoked for user"
        );
    }

    pub fn cleanup_expired_families(&self) {
        let now = Utc::now();
        self.refresh_token_families.retain(|_, family| {
            if let Ok(created) = chrono::DateTime::parse_from_rfc3339(&family.created_at) {
                let expiry = created + chrono::Duration::days(30);
                return now < expiry;
            }
            true
        });

        self.revoked_families
            .retain(|family_id, ()| self.refresh_token_families.contains_key(family_id));
    }
}

impl Clone for TokenService {
    fn clone(&self) -> Self {
        Self {
            jwt_service: Arc::clone(&self.jwt_service),
            user_repository: Arc::clone(&self.user_repository),
            refresh_token_families: Arc::clone(&self.refresh_token_families),
            revoked_families: Arc::clone(&self.revoked_families),
        }
    }
}
