use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use rand::RngCore;
use secrecy::{ExposeSecret, SecretString};

use crate::error::{AppError, Result};

const NONCE_SIZE: usize = 12;

pub struct EncryptionService {
    cipher: Aes256Gcm,
}

impl EncryptionService {
    pub fn new(key: &SecretString) -> Result<Self> {
        let key_bytes = Self::derive_key(key.expose_secret())?;
        let cipher = Aes256Gcm::new_from_slice(&key_bytes)
            .map_err(|e| AppError::InternalServerError(format!("Invalid encryption key: {e}")))?;

        Ok(Self { cipher })
    }

    fn derive_key(key_str: &str) -> Result<[u8; 32]> {
        let decoded = BASE64.decode(key_str).map_err(|e| {
            AppError::InternalServerError(format!("Invalid encryption key encoding: {e}"))
        })?;

        if decoded.len() < 32 {
            return Err(AppError::InternalServerError(
                "Encryption key must be at least 32 bytes when decoded".to_string(),
            ));
        }

        let mut key = [0u8; 32];
        let key_slice = decoded
            .get(..32)
            .ok_or_else(|| AppError::InternalServerError("Failed to get key bytes".to_string()))?;
        key.copy_from_slice(key_slice);
        Ok(key)
    }

    pub fn encrypt(&self, plaintext: &str) -> Result<String> {
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        rand::rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext.as_bytes())
            .map_err(|e| AppError::InternalServerError(format!("Encryption failed: {e}")))?;

        let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(BASE64.encode(&result))
    }

    pub fn decrypt(&self, encrypted: &str) -> Result<String> {
        let data = BASE64.decode(encrypted).map_err(|e| {
            AppError::InternalServerError(format!("Invalid encrypted data encoding: {e}"))
        })?;

        if data.len() < NONCE_SIZE {
            return Err(AppError::InternalServerError(
                "Encrypted data too short".to_string(),
            ));
        }

        let (nonce_bytes, ciphertext) = data.split_at(NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = self
            .cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| AppError::InternalServerError("Decryption failed".to_string()))?;

        String::from_utf8(plaintext).map_err(|e| {
            AppError::InternalServerError(format!("Invalid UTF-8 in decrypted data: {e}"))
        })
    }
}

impl Clone for EncryptionService {
    fn clone(&self) -> Self {
        Self {
            cipher: self.cipher.clone(),
        }
    }
}

#[must_use]
pub fn generate_encryption_key() -> String {
    let mut key = [0u8; 32];
    rand::rng().fill_bytes(&mut key);
    BASE64.encode(key)
}
