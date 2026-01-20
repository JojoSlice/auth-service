use config::{Config, ConfigError, Environment, File};
use secrecy::Secret;
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub jwt: JwtConfig,
    pub oauth: OAuthConfig,
    pub security: SecurityConfig,
    pub rate_limit: RateLimitConfig,
    pub logging: LoggingConfig,
    pub cors: CorsConfig,
    pub ip_filter: IpFilterConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub environment: String,
    #[serde(default = "default_request_timeout")]
    pub request_timeout_seconds: u64,
}

fn default_request_timeout() -> u64 {
    30
}

#[derive(Debug, Deserialize, Clone)]
pub struct DatabaseConfig {
    pub url: String,
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
    #[serde(default = "default_min_connections")]
    pub min_connections: u32,
    #[serde(default = "default_connection_timeout")]
    pub connection_timeout_seconds: u64,
}

fn default_max_connections() -> u32 {
    5
}

fn default_min_connections() -> u32 {
    1
}

fn default_connection_timeout() -> u64 {
    5
}

#[derive(Debug, Deserialize, Clone)]
pub struct JwtConfig {
    pub private_key: Secret<String>,
    pub public_key: String,
    /// Previous public key for key rotation - allows validation during transition period
    #[serde(default)]
    pub previous_public_key: Option<String>,
    /// Key ID for the current key (used in JWKS)
    #[serde(default = "default_key_id")]
    pub key_id: String,
    #[serde(default = "default_access_token_expiration")]
    pub access_token_expiration_minutes: i64,
    #[serde(default = "default_refresh_token_expiration")]
    pub refresh_token_expiration_days: i64,
    pub issuer: String,
}

fn default_key_id() -> String {
    "key-1".to_string()
}

fn default_access_token_expiration() -> i64 {
    15
}

fn default_refresh_token_expiration() -> i64 {
    30
}

#[derive(Debug, Deserialize, Clone)]
pub struct OAuthConfig {
    pub google: GoogleOAuthConfig,
    pub github: GitHubOAuthConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct GoogleOAuthConfig {
    pub client_id: Secret<String>,
    pub client_secret: Secret<String>,
    pub redirect_uri: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct GitHubOAuthConfig {
    pub client_id: Secret<String>,
    pub client_secret: Secret<String>,
    pub redirect_uri: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SecurityConfig {
    pub encryption_key: Secret<String>,
    pub api_key_salt: Secret<String>,
    #[serde(default = "default_require_https")]
    pub require_https: bool,
}

fn default_require_https() -> bool {
    false
}

#[derive(Debug, Deserialize, Clone)]
pub struct RateLimitConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default = "default_global_per_minute")]
    pub global_per_minute: u32,
    #[serde(default = "default_oauth_init_per_minute")]
    pub oauth_init_per_minute: u32,
}

fn default_enabled() -> bool {
    true
}

fn default_global_per_minute() -> u32 {
    100
}

fn default_oauth_init_per_minute() -> u32 {
    10
}

#[derive(Debug, Deserialize, Clone)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default = "default_log_format")]
    pub format: String,
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_format() -> String {
    "pretty".to_string()
}

#[derive(Debug, Deserialize, Clone)]
pub struct CorsConfig {
    pub default_allowed_origins: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct IpFilterConfig {
    #[serde(default)]
    pub enable_ip_whitelist: bool,
    #[serde(default = "default_admin_ip_whitelist")]
    pub admin_ip_whitelist: String,
}

fn default_admin_ip_whitelist() -> String {
    "127.0.0.1,::1".to_string()
}

impl AppConfig {
    pub fn load() -> Result<Self, ConfigError> {
        dotenvy::dotenv().ok();

        let environment = std::env::var("ENVIRONMENT")
            .unwrap_or_else(|_| "development".into());

        let config = Config::builder()
            .add_source(File::with_name("config/default").required(false))
            .add_source(
                File::with_name(&format!("config/{}", environment))
                    .required(false)
            )
            .add_source(
                Environment::default()
                    .prefix("AUTH")
                    .separator("__")
                    .try_parsing(true)
            )
            .add_source(
                Environment::default()
                    .separator("_")
                    .try_parsing(true)
                    .list_separator(",")
            )
            .set_override("server.environment", environment)?
            .set_override_option("database.url", std::env::var("DATABASE_URL").ok())?
            .set_override_option("jwt.private_key", std::env::var("JWT_PRIVATE_KEY").ok())?
            .set_override_option("jwt.public_key", std::env::var("JWT_PUBLIC_KEY").ok())?
            .set_override_option("jwt.issuer", std::env::var("JWT_ISSUER").ok())?
            .set_override_option("oauth.google.client_id", std::env::var("GOOGLE_CLIENT_ID").ok())?
            .set_override_option("oauth.google.client_secret", std::env::var("GOOGLE_CLIENT_SECRET").ok())?
            .set_override_option("oauth.google.redirect_uri", std::env::var("GOOGLE_REDIRECT_URI").ok())?
            .set_override_option("oauth.github.client_id", std::env::var("GITHUB_CLIENT_ID").ok())?
            .set_override_option("oauth.github.client_secret", std::env::var("GITHUB_CLIENT_SECRET").ok())?
            .set_override_option("oauth.github.redirect_uri", std::env::var("GITHUB_REDIRECT_URI").ok())?
            .set_override_option("security.encryption_key", std::env::var("ENCRYPTION_KEY").ok())?
            .set_override_option("security.api_key_salt", std::env::var("API_KEY_SALT").ok())?
            .set_override_option("cors.default_allowed_origins", std::env::var("DEFAULT_ALLOWED_ORIGINS").ok())?
            .build()?;

        config.try_deserialize()
    }
}
