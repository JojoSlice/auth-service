use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub sub: String,
    pub email: String,
    pub iss: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub jti: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_project: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenClaims {
    pub sub: String,
    pub iss: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub jti: String,
    pub family_id: String,
    pub generation: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_project: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64,
}

impl TokenPair {
    pub fn new(access_token: String, refresh_token: String, expires_in: i64) -> Self {
        Self {
            access_token,
            refresh_token,
            token_type: "Bearer".to_string(),
            expires_in,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RefreshTokenFamily {
    pub family_id: String,
    pub user_id: String,
    pub current_generation: u32,
    pub created_at: String,
    pub last_used_at: String,
    pub is_revoked: bool,
}

#[derive(Debug, Deserialize)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

#[derive(Debug, Deserialize)]
pub struct ValidateTokenRequest {
    pub token: String,
}

#[derive(Debug, Deserialize)]
pub struct RevokeTokenRequest {
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub revoke_all: bool,
}

#[derive(Debug, Serialize)]
pub struct ValidateTokenResponse {
    pub valid: bool,
    pub user_id: Option<String>,
    pub email: Option<String>,
    pub expires_at: Option<i64>,
}

/// Device information used for token binding
#[derive(Debug, Clone, Deserialize)]
pub struct DeviceInfo {
    pub user_agent: Option<String>,
    pub accept_language: Option<String>,
    pub ip_subnet: Option<String>,
}

impl DeviceInfo {
    /// Compute a hash of the device information for token binding.
    /// Uses only stable characteristics to minimize false positives.
    pub fn compute_hash(&self) -> String {
        let mut hasher = Sha256::new();

        // Include user agent (browser/OS fingerprint)
        if let Some(ua) = &self.user_agent {
            hasher.update(ua.as_bytes());
        }

        // Include accept-language (locale fingerprint)
        if let Some(lang) = &self.accept_language {
            hasher.update(lang.as_bytes());
        }

        // Include IP subnet (not full IP to allow for DHCP changes)
        // This should be the /24 subnet for IPv4 or /48 for IPv6
        if let Some(subnet) = &self.ip_subnet {
            hasher.update(subnet.as_bytes());
        }

        let result = hasher.finalize();
        hex::encode(&result[..16]) // Use first 16 bytes (128 bits) for shorter hash
    }

    /// Extract IP subnet from a full IP address
    pub fn extract_subnet(ip: &str) -> Option<String> {
        if let Ok(addr) = ip.parse::<std::net::IpAddr>() {
            match addr {
                std::net::IpAddr::V4(v4) => {
                    let octets = v4.octets();
                    // Return /24 subnet (first 3 octets)
                    Some(format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2]))
                }
                std::net::IpAddr::V6(v6) => {
                    let segments = v6.segments();
                    // Return /48 subnet (first 3 segments)
                    Some(format!("{:x}:{:x}:{:x}::/48", segments[0], segments[1], segments[2]))
                }
            }
        } else {
            None
        }
    }
}
