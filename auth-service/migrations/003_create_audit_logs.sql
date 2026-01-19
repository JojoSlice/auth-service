-- Create audit_logs table for security tracking
CREATE TABLE audit_logs (
    id TEXT PRIMARY KEY NOT NULL,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,
    user_id TEXT,
    ip_address TEXT NOT NULL,
    user_agent TEXT,
    request_id TEXT,
    endpoint TEXT,
    http_method TEXT,
    status_code INTEGER,
    error_message TEXT,
    metadata TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- Create indexes for querying audit logs
CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp);
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_event_type ON audit_logs(event_type);
CREATE INDEX idx_audit_logs_ip_address ON audit_logs(ip_address);
CREATE INDEX idx_audit_logs_request_id ON audit_logs(request_id);
