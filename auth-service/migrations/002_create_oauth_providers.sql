-- Create oauth_providers table for storing OAuth provider associations
CREATE TABLE oauth_providers (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL,
    provider_name TEXT NOT NULL,
    provider_user_id TEXT NOT NULL,
    access_token_encrypted TEXT,
    refresh_token_encrypted TEXT,
    token_expires_at TEXT,
    scope TEXT,
    provider_data TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(provider_name, provider_user_id)
);

-- Create indexes
CREATE INDEX idx_oauth_providers_user_id ON oauth_providers(user_id);
CREATE INDEX idx_oauth_providers_provider ON oauth_providers(provider_name, provider_user_id);
