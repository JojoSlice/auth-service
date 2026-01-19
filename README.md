# Bibblo

En säkerhetsfokuserad OAuth-autentiseringstjänst byggd för att hantera centraliserad autentisering för multipla klientapplikationer.

## Arkitektur

```
┌─────────────────┐     ┌─────────────────┐
│   auth-web      │────▶│  auth-service   │
│  (React/TS)     │     │  (Rust/Axum)    │
└─────────────────┘     └────────┬────────┘
                                 │
                        ┌────────▼────────┐
                        │     SQLite      │
                        └─────────────────┘
```

- **auth-service**: Rust-baserad backend med Axum
- **auth-web**: React/TypeScript frontend

## Säkerhetsfunktioner

| Funktion | Implementation |
|----------|----------------|
| JWT-tokens | ECDSA ES256, korta access tokens (15 min) |
| API-nycklar | Argon2-hashade, aldrig i klartext |
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

### Backend (auth-service)

```bash
cd auth-service
cp .env.example .env  # Konfigurera miljövariabler
cargo run
```

### Frontend (auth-web)

```bash
cd auth-web
npm install
npm run dev
```

## Konfiguration

Se `.env.example` i respektive katalog för nödvändiga miljövariabler.

## Utvecklingsstatus

Se [TODO.md](./TODO.md) för planerade säkerhetsförbättringar.
