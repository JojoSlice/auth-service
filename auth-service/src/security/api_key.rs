use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL, Engine};
use rand::RngCore;

const API_KEY_LENGTH: usize = 32;
const PREFIX_LENGTH: usize = 8;

pub struct ApiKeyService {
    argon2: Argon2<'static>,
}

impl ApiKeyService {
    #[must_use]
    pub fn new() -> Self {
        Self {
            argon2: Argon2::default(),
        }
    }

    #[must_use]
    pub fn generate_api_key(&self) -> (String, String, String) {
        let mut key_bytes = [0u8; API_KEY_LENGTH];
        rand::rng().fill_bytes(&mut key_bytes);

        let key = format!("bib_{}", BASE64_URL.encode(key_bytes));
        let prefix = key[..PREFIX_LENGTH.min(key.len())].to_string();
        let hash = self.hash_api_key(&key);

        (key, prefix, hash)
    }

    /// Hashes an API key using Argon2.
    ///
    /// # Panics
    /// Panics if the password hashing algorithm fails, which should not occur
    /// with valid input and default Argon2 parameters.
    pub fn hash_api_key(&self, key: &str) -> String {
        let salt = SaltString::generate(&mut OsRng);
        self.argon2
            .hash_password(key.as_bytes(), &salt)
            .expect("Failed to hash API key")
            .to_string()
    }

    #[must_use]
    pub fn verify_api_key(&self, key: &str, hash: &str) -> bool {
        let Ok(parsed_hash) = PasswordHash::new(hash) else {
            return false;
        };

        self.argon2
            .verify_password(key.as_bytes(), &parsed_hash)
            .is_ok()
    }

    #[must_use]
    pub fn get_prefix(key: &str) -> String {
        key[..PREFIX_LENGTH.min(key.len())].to_string()
    }
}

impl Default for ApiKeyService {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for ApiKeyService {
    fn clone(&self) -> Self {
        Self::new()
    }
}

#[must_use]
pub fn generate_random_string(length: usize) -> String {
    let mut bytes = vec![0u8; length];
    rand::rng().fill_bytes(&mut bytes);
    BASE64_URL.encode(&bytes)
}

#[must_use]
pub fn generate_csrf_state() -> String {
    generate_random_string(32)
}
