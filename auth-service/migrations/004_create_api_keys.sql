-- Create api_keys table for client project authentication
CREATE TABLE api_keys (
    id TEXT PRIMARY KEY NOT NULL,
    key_hash TEXT UNIQUE NOT NULL,
    key_prefix TEXT NOT NULL,
    name TEXT NOT NULL,
    client_project TEXT NOT NULL,
    allowed_origins TEXT NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT 1,
    rate_limit_per_minute INTEGER NOT NULL DEFAULT 60,
    expires_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    last_used_at TEXT
);

-- Create indexes
CREATE INDEX idx_api_keys_key_hash ON api_keys(key_hash);
CREATE INDEX idx_api_keys_prefix ON api_keys(key_prefix);
CREATE INDEX idx_api_keys_project ON api_keys(client_project);
CREATE INDEX idx_api_keys_active ON api_keys(is_active);
