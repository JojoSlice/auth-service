use std::sync::Arc;

use crate::config::AppConfig;
use crate::db::{
    ApiKeyRepository, AuditLogRepository, DbPool, IpFilterRepository, OAuthProviderRepository,
    UserRepository,
};
use crate::error::Result;
use crate::handlers::{AdminHandlerState, OAuthHandlerState, TokenHandlerState, UserHandlerState};
use crate::middleware::{ApiKeyState, AuditState, AuthState, IpFilterState, RateLimiter};
use crate::oauth::{GitHubOAuthProvider, GoogleOAuthProvider, OAuthStateManager};
use crate::security::{ApiKeyService, EncryptionService, JwtService};
use crate::services::{AnomalyConfig, AnomalyDetectionService, AuthService, TokenService, UserService};

#[derive(Clone)]
pub struct AppState {
    pub pool: DbPool,
    pub config: Arc<AppConfig>,

    pub user_repository: Arc<UserRepository>,
    pub oauth_provider_repository: Arc<OAuthProviderRepository>,
    pub api_key_repository: Arc<ApiKeyRepository>,
    pub audit_log_repository: Arc<AuditLogRepository>,
    pub ip_filter_repository: Arc<IpFilterRepository>,

    pub jwt_service: Arc<JwtService>,
    pub encryption_service: Arc<EncryptionService>,
    pub api_key_service: Arc<ApiKeyService>,

    pub google_provider: Arc<GoogleOAuthProvider>,
    pub github_provider: Arc<GitHubOAuthProvider>,
    pub oauth_state_manager: Arc<OAuthStateManager>,

    pub auth_service: Arc<AuthService>,
    pub user_service: Arc<UserService>,
    pub token_service: Arc<TokenService>,
    pub anomaly_detection_service: Arc<AnomalyDetectionService>,

    pub rate_limiter: RateLimiter,
}

impl AppState {
    pub fn new(pool: DbPool, config: AppConfig) -> Result<Self> {
        let config = Arc::new(config);

        let user_repository = Arc::new(UserRepository::new(pool.clone()));
        let oauth_provider_repository = Arc::new(OAuthProviderRepository::new(pool.clone()));
        let api_key_repository = Arc::new(ApiKeyRepository::new(pool.clone()));
        let audit_log_repository = Arc::new(AuditLogRepository::new(pool.clone()));
        let ip_filter_repository = Arc::new(IpFilterRepository::new(pool.clone()));

        let jwt_service = Arc::new(JwtService::new(&config.jwt)?);
        let encryption_service = Arc::new(EncryptionService::new(&config.security.encryption_key)?);
        let api_key_service = Arc::new(ApiKeyService::new());

        let google_provider = Arc::new(GoogleOAuthProvider::new(&config.oauth.google)?);
        let github_provider = Arc::new(GitHubOAuthProvider::new(&config.oauth.github)?);
        let oauth_state_manager = Arc::new(OAuthStateManager::new());

        let auth_service = Arc::new(AuthService::new(
            Arc::clone(&user_repository),
            Arc::clone(&oauth_provider_repository),
            Arc::clone(&jwt_service),
            Arc::clone(&encryption_service),
            Arc::clone(&oauth_state_manager),
        ));

        let user_service = Arc::new(UserService::new(
            Arc::clone(&user_repository),
            Arc::clone(&oauth_provider_repository),
        ));

        let token_service = Arc::new(TokenService::new(
            Arc::clone(&jwt_service),
            Arc::clone(&user_repository),
        ));

        let anomaly_detection_service = Arc::new(AnomalyDetectionService::new(AnomalyConfig::default()));

        let rate_limiter = RateLimiter::new(config.rate_limit.clone());

        Ok(Self {
            pool,
            config,
            user_repository,
            oauth_provider_repository,
            api_key_repository,
            audit_log_repository,
            ip_filter_repository,
            jwt_service,
            encryption_service,
            api_key_service,
            google_provider,
            github_provider,
            oauth_state_manager,
            auth_service,
            user_service,
            token_service,
            anomaly_detection_service,
            rate_limiter,
        })
    }

    pub fn ip_filter_state(&self) -> IpFilterState {
        IpFilterState {
            repository: Arc::clone(&self.ip_filter_repository),
        }
    }

    pub fn api_key_state(&self) -> ApiKeyState {
        ApiKeyState {
            repository: Arc::clone(&self.api_key_repository),
            service: Arc::clone(&self.api_key_service),
        }
    }

    pub fn auth_state(&self) -> AuthState {
        AuthState {
            jwt_service: Arc::clone(&self.jwt_service),
        }
    }

    pub fn audit_state(&self) -> AuditState {
        AuditState {
            repository: Arc::clone(&self.audit_log_repository),
        }
    }

    pub fn oauth_handler_state(&self) -> OAuthHandlerState {
        OAuthHandlerState {
            auth_service: Arc::clone(&self.auth_service),
            google_provider: Arc::clone(&self.google_provider),
            github_provider: Arc::clone(&self.github_provider),
            anomaly_detection_service: Arc::clone(&self.anomaly_detection_service),
            audit_log_repository: Arc::clone(&self.audit_log_repository),
        }
    }

    pub fn token_handler_state(&self) -> TokenHandlerState {
        TokenHandlerState {
            token_service: Arc::clone(&self.token_service),
        }
    }

    pub fn user_handler_state(&self) -> UserHandlerState {
        UserHandlerState {
            user_service: Arc::clone(&self.user_service),
            token_service: Arc::clone(&self.token_service),
        }
    }

    pub fn admin_handler_state(&self) -> AdminHandlerState {
        let admin_ip_whitelist: Vec<String> = self
            .config
            .ip_filter
            .admin_ip_whitelist
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        AdminHandlerState {
            api_key_repository: Arc::clone(&self.api_key_repository),
            api_key_service: Arc::clone(&self.api_key_service),
            audit_log_repository: Arc::clone(&self.audit_log_repository),
            ip_filter_repository: Arc::clone(&self.ip_filter_repository),
            admin_ip_whitelist,
        }
    }
}
