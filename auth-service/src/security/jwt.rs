use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use secrecy::ExposeSecret;
use uuid::Uuid;

use crate::config::JwtConfig;
use crate::error::{AppError, Result};
use crate::models::{AccessTokenClaims, RefreshTokenClaims, TokenPair};

pub struct JwtService {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    previous_decoding_key: Option<DecodingKey>,
    key_id: String,
    issuer: String,
    access_token_expiration_minutes: i64,
    refresh_token_expiration_days: i64,
}

/// Decode a PEM key that may be base64 encoded or contain literal \n
fn decode_pem_key(key: &str) -> String {
    // If it starts with base64 chars and doesn't look like PEM, try to decode
    if !key.starts_with("-----") {
        if let Ok(decoded) = STANDARD.decode(key.trim()) {
            if let Ok(pem_str) = String::from_utf8(decoded) {
                return pem_str;
            }
        }
    }
    // Otherwise, just replace literal \n with actual newlines
    key.replace("\\n", "\n")
}

impl JwtService {
    pub fn new(config: &JwtConfig) -> Result<Self> {
        let private_key_pem = decode_pem_key(config.private_key.expose_secret());
        let public_key_pem = decode_pem_key(&config.public_key);

        let encoding_key = EncodingKey::from_ec_pem(private_key_pem.as_bytes())
            .map_err(|e| AppError::InternalServerError(format!("Invalid JWT private key: {e}")))?;

        let decoding_key = DecodingKey::from_ec_pem(public_key_pem.as_bytes())
            .map_err(|e| AppError::InternalServerError(format!("Invalid JWT public key: {e}")))?;

        // Load previous key if configured (for key rotation)
        let previous_decoding_key = if let Some(ref prev_key) = config.previous_public_key {
            let prev_key_pem = decode_pem_key(prev_key);
            Some(
                DecodingKey::from_ec_pem(prev_key_pem.as_bytes()).map_err(|e| {
                    AppError::InternalServerError(format!("Invalid previous JWT public key: {e}"))
                })?,
            )
        } else {
            None
        };

        if previous_decoding_key.is_some() {
            tracing::info!(
                "JWT key rotation enabled - validating against current and previous keys"
            );
        }

        Ok(Self {
            encoding_key,
            decoding_key,
            previous_decoding_key,
            key_id: config.key_id.clone(),
            issuer: config.issuer.clone(),
            access_token_expiration_minutes: config.access_token_expiration_minutes,
            refresh_token_expiration_days: config.refresh_token_expiration_days,
        })
    }

    pub fn create_token_pair(
        &self,
        user_id: &str,
        email: &str,
        client_project: Option<&str>,
        family_id: Option<&str>,
        generation: u32,
        device_hash: Option<&str>,
    ) -> Result<TokenPair> {
        let access_token = self.create_access_token(user_id, email, client_project)?;
        let refresh_token = self.create_refresh_token(
            user_id,
            client_project,
            family_id.unwrap_or(&Uuid::new_v4().to_string()),
            generation,
            device_hash,
        )?;

        Ok(TokenPair::new(
            access_token,
            refresh_token,
            self.access_token_expiration_minutes * 60,
        ))
    }

    pub fn create_access_token(
        &self,
        user_id: &str,
        email: &str,
        client_project: Option<&str>,
    ) -> Result<String> {
        let now = Utc::now();
        let exp = now + Duration::minutes(self.access_token_expiration_minutes);

        let claims = AccessTokenClaims {
            sub: user_id.to_string(),
            email: email.to_string(),
            iss: self.issuer.clone(),
            aud: "auth-service".to_string(),
            exp: exp.timestamp(),
            iat: now.timestamp(),
            jti: Uuid::new_v4().to_string(),
            client_project: client_project.map(String::from),
        };

        let mut header = Header::new(jsonwebtoken::Algorithm::ES256);
        header.kid = Some(self.key_id.clone());
        let token = encode(&header, &claims, &self.encoding_key)?;

        Ok(token)
    }

    pub fn create_refresh_token(
        &self,
        user_id: &str,
        client_project: Option<&str>,
        family_id: &str,
        generation: u32,
        device_hash: Option<&str>,
    ) -> Result<String> {
        let now = Utc::now();
        let exp = now + Duration::days(self.refresh_token_expiration_days);

        let claims = RefreshTokenClaims {
            sub: user_id.to_string(),
            iss: self.issuer.clone(),
            aud: "auth-service-refresh".to_string(),
            exp: exp.timestamp(),
            iat: now.timestamp(),
            jti: Uuid::new_v4().to_string(),
            family_id: family_id.to_string(),
            generation,
            client_project: client_project.map(String::from),
            device_hash: device_hash.map(String::from),
        };

        let mut header = Header::new(jsonwebtoken::Algorithm::ES256);
        header.kid = Some(self.key_id.clone());
        let token = encode(&header, &claims, &self.encoding_key)?;

        Ok(token)
    }

    pub fn verify_access_token(&self, token: &str) -> Result<AccessTokenClaims> {
        let mut validation = Validation::new(jsonwebtoken::Algorithm::ES256);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&["auth-service"]);

        // Try current key first
        match decode::<AccessTokenClaims>(token, &self.decoding_key, &validation) {
            Ok(token_data) => Ok(token_data.claims),
            Err(e) => {
                // If we have a previous key and the error isn't expiration, try it
                if let Some(ref prev_key) = self.previous_decoding_key {
                    if !matches!(e.kind(), jsonwebtoken::errors::ErrorKind::ExpiredSignature) {
                        if let Ok(token_data) =
                            decode::<AccessTokenClaims>(token, prev_key, &validation)
                        {
                            tracing::debug!("Token validated with previous key");
                            return Ok(token_data.claims);
                        }
                    }
                }
                // Return the original error
                Err(match e.kind() {
                    jsonwebtoken::errors::ErrorKind::ExpiredSignature => AppError::TokenExpired,
                    _ => AppError::InvalidToken,
                })
            }
        }
    }

    pub fn verify_refresh_token(&self, token: &str) -> Result<RefreshTokenClaims> {
        let mut validation = Validation::new(jsonwebtoken::Algorithm::ES256);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&["auth-service-refresh"]);

        // Try current key first
        match decode::<RefreshTokenClaims>(token, &self.decoding_key, &validation) {
            Ok(token_data) => Ok(token_data.claims),
            Err(e) => {
                // If we have a previous key and the error isn't expiration, try it
                if let Some(ref prev_key) = self.previous_decoding_key {
                    if !matches!(e.kind(), jsonwebtoken::errors::ErrorKind::ExpiredSignature) {
                        if let Ok(token_data) =
                            decode::<RefreshTokenClaims>(token, prev_key, &validation)
                        {
                            tracing::debug!("Refresh token validated with previous key");
                            return Ok(token_data.claims);
                        }
                    }
                }
                // Return the original error
                Err(match e.kind() {
                    jsonwebtoken::errors::ErrorKind::ExpiredSignature => AppError::TokenExpired,
                    _ => AppError::InvalidToken,
                })
            }
        }
    }

    #[must_use]
    pub fn get_access_token_expiration_seconds(&self) -> i64 {
        self.access_token_expiration_minutes * 60
    }
}

impl Clone for JwtService {
    fn clone(&self) -> Self {
        Self {
            encoding_key: self.encoding_key.clone(),
            decoding_key: self.decoding_key.clone(),
            previous_decoding_key: self.previous_decoding_key.clone(),
            key_id: self.key_id.clone(),
            issuer: self.issuer.clone(),
            access_token_expiration_minutes: self.access_token_expiration_minutes,
            refresh_token_expiration_days: self.refresh_token_expiration_days,
        }
    }
}
