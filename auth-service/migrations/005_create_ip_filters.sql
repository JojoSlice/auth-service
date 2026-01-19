-- Create ip_filters table for IP whitelist/blacklist
CREATE TABLE ip_filters (
    id TEXT PRIMARY KEY NOT NULL,
    ip_address TEXT NOT NULL,
    filter_type TEXT NOT NULL,
    reason TEXT,
    is_active BOOLEAN NOT NULL DEFAULT 1,
    expires_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- Create indexes
CREATE INDEX idx_ip_filters_ip ON ip_filters(ip_address);
CREATE INDEX idx_ip_filters_type ON ip_filters(filter_type, is_active);
CREATE INDEX idx_ip_filters_active ON ip_filters(is_active);
