# Auth Service

En säkerhetsfokuserad OAuth-autentiseringstjänst byggd för att hantera centraliserad autentisering för multipla klientapplikationer.

## Arkitektur

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   auth-web      │────▶│   auth-proxy    │────▶│  auth-service   │
│  (React/TS)     │     │  (Node/Express) │     │  (Rust/Axum)    │
└─────────────────┘     └─────────────────┘     └────────┬────────┘
                                                         │
                                                ┌────────▼────────┐
                                                │     SQLite      │
                                                └─────────────────┘
```

- **auth-service**: Rust-baserad backend med Axum
- **auth-proxy**: Node.js proxy som hanterar API-nycklar och HttpOnly cookies
- **auth-web**: React/TypeScript frontend

## Säkerhetsfunktioner

| Funktion | Implementation |
|----------|----------------|
| JWT-tokens | ECDSA ES256, korta access tokens (15 min) |
| API-nycklar | Argon2-hashade, aldrig i klartext, dolda bakom proxy |
| HttpOnly cookies | Tokens lagras i HttpOnly cookies, ej åtkomliga via JavaScript |
| Rate limiting | Per IP och per API-nyckel |
| CORS | Konfigurerbar per API-nyckel |
| CSP | Content Security Policy |
| Audit logging | Full loggning av säkerhetshändelser |
| IP-filtrering | Blacklist/whitelist-stöd |
| Kryptering | AES-256-GCM för känslig data |

## OAuth-providers

- Google (OpenID Connect)
- GitHub

## Kom igång

### 1. Backend (auth-service)

```bash
cd auth-service
cp .env.example .env  # Konfigurera miljövariabler
cargo run
```

### 2. Proxy (auth-proxy)

```bash
cd auth-proxy
npm install
cp .env.example .env  # Konfigurera miljövariabler (inkl. AUTH_API_KEY)
npm run dev
```

### 3. Frontend (auth-web)

```bash
cd auth-web
npm install
cp .env.example .env  # Valfritt, använder localhost:4000 som default
npm run dev
```

## Konfiguration

Se `.env.example` i respektive katalog för nödvändiga miljövariabler.

### Miljövariabler

| Tjänst | Variabel | Beskrivning |
|--------|----------|-------------|
| auth-service | Se `auth-service/.env.example` | Backend-konfiguration |
| auth-proxy | `AUTH_API_KEY` | API-nyckel för auth-service |
| auth-proxy | `AUTH_SERVICE_URL` | URL till auth-service (default: localhost:3000) |
| auth-proxy | `CORS_ORIGIN` | Frontend URL för CORS (default: localhost:5173) |
| auth-web | `VITE_AUTH_PROXY_URL` | URL till auth-proxy (default: localhost:4000) |

## Utvecklingsstatus

Se [TODO.md](./TODO.md) för planerade säkerhetsförbättringar.
