# Secure OAuth Authentication Service

A production-ready, security-first OAuth authentication service built with Rust and Axum. Provides centralized authentication for multiple client applications using Google and GitHub OAuth providers, with JWT-based stateless sessions and comprehensive security features.

## Features

- **OAuth 2.0 Integration**
  - Google OAuth (OpenID Connect)
  - GitHub OAuth
  - Extensible provider system

- **JWT Authentication**
  - ECDSA (ES256) signed tokens
  - Short-lived access tokens (15 minutes)
  - Long-lived refresh tokens (30 days)
  - Token rotation support

- **Security Features**
  - Multi-tier rate limiting
  - Dynamic CORS based on API keys
  - IP whitelist/blacklist
  - Comprehensive audit logging
  - CSRF protection
  - Secure secrets management

- **Multi-Project Support**
  - API key-based client authentication
  - Per-key CORS configuration
  - Per-key rate limiting

## Quick Start

### Prerequisites

- Rust 1.70+ ([install](https://rustup.rs/))
- SQLite 3
- OpenSSL (for key generation)

### 1. Clone and Setup

```bash
git clone <repository-url>
cd bibblo
cp .env.example .env
```

### 2. Generate JWT Keys

```bash
# Generate ECDSA P-256 key pair
openssl ecparam -name prime256v1 -genkey -noout -out private-key.pem
openssl ec -in private-key.pem -pubout -out public-key.pem

# Base64 encode for .env
echo "JWT_PRIVATE_KEY=$(cat private-key.pem | base64 -w0)" >> .env
echo "JWT_PUBLIC_KEY=$(cat public-key.pem | base64 -w0)" >> .env

# Generate encryption key
echo "ENCRYPTION_KEY=$(openssl rand -base64 32)" >> .env

# Clean up PEM files
rm private-key.pem public-key.pem
```

### 3. Setup OAuth Providers

#### Google OAuth
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing
3. Enable Google+ API
4. Create OAuth 2.0 credentials
5. Add authorized redirect URI: `http://localhost:3000/api/v1/auth/oauth/google/callback`
6. Copy Client ID and Client Secret to `.env`

#### GitHub OAuth
1. Go to [GitHub Developer Settings](https://github.com/settings/developers)
2. Click "New OAuth App"
3. Set Authorization callback URL: `http://localhost:3000/api/v1/auth/oauth/github/callback`
4. Copy Client ID and Client Secret to `.env`

### 4. Run the Service

```bash
# Run database migrations
cargo sqlx migrate run

# Start the service
cargo run
```

The service will be available at `http://localhost:3000`

## API Endpoints

### OAuth Flow
```
POST /api/v1/auth/oauth/google/init     - Initiate Google OAuth
POST /api/v1/auth/oauth/github/init     - Initiate GitHub OAuth
GET  /api/v1/auth/oauth/google/callback - Google callback handler
GET  /api/v1/auth/oauth/github/callback - GitHub callback handler
```

### Token Management
```
POST /api/v1/auth/token/refresh   - Refresh access token
POST /api/v1/auth/token/validate  - Validate and return user info
POST /api/v1/auth/token/revoke    - Logout/revoke token
```

### User Profile (Authenticated)
```
GET    /api/v1/user/profile       - Get user profile
PATCH  /api/v1/user/profile       - Update profile
DELETE /api/v1/user/account       - Delete account
```

### Admin (Requires Admin API Key)
```
GET    /api/v1/admin/users         - List users
GET    /api/v1/admin/audit-logs    - Query audit logs
POST   /api/v1/admin/ip-filters    - Add IP filter
POST   /api/v1/admin/api-keys      - Generate API key
DELETE /api/v1/admin/api-keys/:id  - Revoke API key
```

### Health
```
GET /health - Health check
```

## Configuration

Configuration is loaded from:
1. `config/default.toml` - Default values
2. `config/{environment}.toml` - Environment-specific overrides
3. Environment variables (highest priority)

Environment variables can use either:
- `BIBBLO__` prefix with double underscores: `BIBBLO__SERVER__PORT=3000`
- Direct variable names: `PORT=3000`

See `.env.example` for all available configuration options.

## Security

### Token Storage
- **Access tokens**: Store in memory only (JavaScript variable)
- **Refresh tokens**: HttpOnly, Secure, SameSite=Strict cookies

### Rate Limiting
- Global: 100 requests/minute per IP
- OAuth init: 10 requests/minute per IP
- Token refresh: 5 requests/minute per user
- Admin: 100 requests/minute per API key

### HTTPS
In production, always use HTTPS. Set `SECURITY__REQUIRE_HTTPS=true` and deploy behind a reverse proxy (nginx, Caddy) that handles TLS termination.

### Secrets
Never commit `.env` files. In production, use:
- AWS Secrets Manager
- HashiCorp Vault
- Kubernetes Secrets
- Environment variables from secure CI/CD

## Development

### Run Tests
```bash
cargo test
```

### Run with Debug Logging
```bash
RUST_LOG=debug cargo run
```

### Database Migrations
```bash
# Create new migration
sqlx migrate add <migration_name>

# Run migrations
cargo sqlx migrate run

# Revert last migration
cargo sqlx migrate revert
```

## Project Structure

```
├── migrations/          SQL database migrations
├── config/             Configuration files
├── src/
│   ├── models/         Data models
│   ├── handlers/       HTTP request handlers
│   ├── services/       Business logic
│   ├── middleware/     Axum middleware
│   ├── oauth/          OAuth provider implementations
│   ├── security/       JWT, API keys, CSRF
│   └── db/            Database connection and repositories
└── tests/             Integration tests
```

## License

MIT

## Support

For issues and questions, please open a GitHub issue.
