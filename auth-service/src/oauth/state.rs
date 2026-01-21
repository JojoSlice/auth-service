use chrono::{DateTime, Duration, Utc};
use dashmap::DashMap;
use std::sync::Arc;

use crate::error::{AppError, Result};
use crate::security::generate_csrf_state;

const STATE_EXPIRY_MINUTES: i64 = 10;

#[derive(Debug, Clone)]
pub struct OAuthStateData {
    pub state: String,
    pub client_project: String,
    pub redirect_uri: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl OAuthStateData {
    #[must_use]
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.created_at + Duration::minutes(STATE_EXPIRY_MINUTES)
    }
}

#[derive(Clone)]
pub struct OAuthStateManager {
    states: Arc<DashMap<String, OAuthStateData>>,
}

impl OAuthStateManager {
    #[must_use]
    pub fn new() -> Self {
        Self {
            states: Arc::new(DashMap::new()),
        }
    }

    #[must_use]
    pub fn create_state(&self, client_project: &str, redirect_uri: Option<String>) -> String {
        let state = generate_csrf_state();
        let data = OAuthStateData {
            state: state.clone(),
            client_project: client_project.to_string(),
            redirect_uri,
            created_at: Utc::now(),
        };

        self.states.insert(state.clone(), data);
        self.cleanup_expired();

        state
    }

    pub fn validate_and_consume(&self, state: &str) -> Result<OAuthStateData> {
        let data = self
            .states
            .remove(state)
            .map(|(_, v)| v)
            .ok_or_else(|| AppError::OAuth("Invalid or expired state".to_string()))?;

        if data.is_expired() {
            return Err(AppError::OAuth("State has expired".to_string()));
        }

        Ok(data)
    }

    pub fn validate(&self, state: &str) -> Result<OAuthStateData> {
        let data = self
            .states
            .get(state)
            .map(|v| v.clone())
            .ok_or_else(|| AppError::OAuth("Invalid or expired state".to_string()))?;

        if data.is_expired() {
            self.states.remove(state);
            return Err(AppError::OAuth("State has expired".to_string()));
        }

        Ok(data)
    }

    fn cleanup_expired(&self) {
        let now = Utc::now();
        self.states
            .retain(|_, v| now <= v.created_at + Duration::minutes(STATE_EXPIRY_MINUTES));
    }

    pub fn remove(&self, state: &str) {
        self.states.remove(state);
    }
}

impl Default for OAuthStateManager {
    fn default() -> Self {
        Self::new()
    }
}
