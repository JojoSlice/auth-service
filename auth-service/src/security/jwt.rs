use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, TokenData, Validation};
use secrecy::ExposeSecret;
use uuid::Uuid;

use crate::config::JwtConfig;
use crate::error::{AppError, Result};
use crate::models::{AccessTokenClaims, RefreshTokenClaims, TokenPair};

pub struct JwtService {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    issuer: String,
    access_token_expiration_minutes: i64,
    refresh_token_expiration_days: i64,
}

impl JwtService {
    pub fn new(config: &JwtConfig) -> Result<Self> {
        let private_key_pem = config.private_key.expose_secret();
        let public_key_pem = &config.public_key;

        let encoding_key = EncodingKey::from_ec_pem(private_key_pem.as_bytes())
            .map_err(|e| AppError::InternalServerError(format!("Invalid JWT private key: {}", e)))?;

        let decoding_key = DecodingKey::from_ec_pem(public_key_pem.as_bytes())
            .map_err(|e| AppError::InternalServerError(format!("Invalid JWT public key: {}", e)))?;

        Ok(Self {
            encoding_key,
            decoding_key,
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
    ) -> Result<TokenPair> {
        let access_token = self.create_access_token(user_id, email, client_project)?;
        let refresh_token = self.create_refresh_token(
            user_id,
            client_project,
            family_id.unwrap_or(&Uuid::new_v4().to_string()),
            generation,
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

        let header = Header::new(jsonwebtoken::Algorithm::ES256);
        let token = encode(&header, &claims, &self.encoding_key)?;

        Ok(token)
    }

    pub fn create_refresh_token(
        &self,
        user_id: &str,
        client_project: Option<&str>,
        family_id: &str,
        generation: u32,
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
        };

        let header = Header::new(jsonwebtoken::Algorithm::ES256);
        let token = encode(&header, &claims, &self.encoding_key)?;

        Ok(token)
    }

    pub fn verify_access_token(&self, token: &str) -> Result<AccessTokenClaims> {
        let mut validation = Validation::new(jsonwebtoken::Algorithm::ES256);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&["auth-service"]);

        let token_data: TokenData<AccessTokenClaims> =
            decode(token, &self.decoding_key, &validation).map_err(|e| {
                match e.kind() {
                    jsonwebtoken::errors::ErrorKind::ExpiredSignature => AppError::TokenExpired,
                    _ => AppError::InvalidToken,
                }
            })?;

        Ok(token_data.claims)
    }

    pub fn verify_refresh_token(&self, token: &str) -> Result<RefreshTokenClaims> {
        let mut validation = Validation::new(jsonwebtoken::Algorithm::ES256);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&["auth-service-refresh"]);

        let token_data: TokenData<RefreshTokenClaims> =
            decode(token, &self.decoding_key, &validation).map_err(|e| {
                match e.kind() {
                    jsonwebtoken::errors::ErrorKind::ExpiredSignature => AppError::TokenExpired,
                    _ => AppError::InvalidToken,
                }
            })?;

        Ok(token_data.claims)
    }

    pub fn get_access_token_expiration_seconds(&self) -> i64 {
        self.access_token_expiration_minutes * 60
    }
}

impl Clone for JwtService {
    fn clone(&self) -> Self {
        Self {
            encoding_key: self.encoding_key.clone(),
            decoding_key: self.decoding_key.clone(),
            issuer: self.issuer.clone(),
            access_token_expiration_minutes: self.access_token_expiration_minutes,
            refresh_token_expiration_days: self.refresh_token_expiration_days,
        }
    }
}
