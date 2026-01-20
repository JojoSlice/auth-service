# TODO: Säkerhetsförbättringar

## Implementerat

### Backend Proxy + HttpOnly Cookies ✅

Implementerat i `auth-proxy/`:
- Node.js/Express proxy-server som döljer API-nycklar från frontend
- HttpOnly cookies för access_token och refresh_token
- Automatisk cookie-hantering vid OAuth callback
- Frontend uppdaterad för cookie-baserad auth

Endpoints:
```
POST /api/auth/:provider/init   → OAuth flow start
GET  /api/auth/:provider/callback → OAuth callback + set cookies
POST /api/auth/refresh          → Token refresh via cookies
POST /api/auth/logout           → Logout + clear cookies
GET  /api/user/profile          → Get profile via cookies
GET  /api/auth/status           → Check auth status
```

### Secure Headers Bundle ✅

Implementerat i `auth-service/src/middleware/security_headers.rs`:
- `X-Content-Type-Options: nosniff` - Förhindrar MIME type sniffing
- `X-Frame-Options: DENY` - Skyddar mot clickjacking
- `Referrer-Policy: strict-origin-when-cross-origin` - Kontrollerar referrer-information
- `Permissions-Policy` - Inaktiverar onödiga webbläsarfunktioner
- `X-XSS-Protection: 1; mode=block` - Legacy XSS-skydd
- `Cache-Control: no-store, no-cache` - Förhindrar caching av API-svar
- `Pragma: no-cache` - Legacy cache-kontroll

### Inaktivitetslås ✅

Implementerat i `auth-web/src/auth/AuthProvider.tsx`:
- Automatisk utloggning efter 15 minuters inaktivitet
- Spårar användaraktivitet via mousedown, keydown, scroll, touchstart, mousemove
- Kontrollerar inaktivitet var 60:e sekund
- Endast aktiv när användaren är inloggad

### Rate limiting frontend ✅

Implementerat i `auth-web/src/components/Login.tsx`:
- 2 sekunders cooldown mellan login-försök
- Förhindrar spam av login-knappar
- Knapparna inaktiveras under cooldown-perioden

### CSP via HTTP-headers ✅

Implementerat i både `auth-service` och `auth-proxy`:
- Strikt Content-Security-Policy för API-svar
- `default-src 'none'` - blockerar allt som standard
- `frame-ancestors 'none'` - förhindrar embedding
- `base-uri 'none'` - förhindrar base tag injection
- `form-action 'none'` - förhindrar form submissions

### Token Binding / Device Fingerprinting ✅

Implementerat i `auth-service`:
- Refresh tokens binds till enhet via `device_hash` claim
- Hash beräknas från User-Agent, Accept-Language, och IP-subnet
- Vid token refresh verifieras att device matchar
- Vid mismatch revokeras token-familjen och ny inloggning krävs
- Skyddar mot token-stöld genom att binda tokens till ursprungsenheten

### JWT Secret Rotation ✅

Implementerat i `auth-service`:
- Stöd för `previous_public_key` i konfiguration
- Nya tokens signeras med current key (inkl. `kid` header)
- Validering sker mot current key först, sedan previous key
- Möjliggör sömlös nyckelrotation utan downtime
- Konfigurera via `jwt.previous_public_key` och `jwt.key_id`

### Suspicious Activity Detection ✅

Implementerat i `auth-service/src/services/anomaly_detection.rs`:
- **Brute force detection**: IP-baserad spårning av misslyckade inloggningsförsök
  - Max 5 misslyckade försök inom 30 minuter
  - 15 minuters lockout vid överträdelse
  - Automatisk rensning efter lyckad inloggning
- **Geografisk anomali**: Detekterar inloggning från ny IP-adress
  - Jämför mot kända IP-adresser per användare
  - Loggar varning vid ny location
- **Impossible travel**: Detekterar misstänkta platsbyten
  - Varnar vid inloggning från olika subnät inom 60 minuter
  - Baserat på IP-subnet jämförelse
- **Integration med OAuth callback**: Kontrollerar anomalier vid varje inloggning
- **Audit logging**: Loggar alla anomalier till audit_logs-tabellen
- **AuditEventType**: Nya typer `LoginAnomaly` och `BruteForceDetected`

---

## Övriga förbättringar

### CSP via HTTP-headers (Medel prioritet)

CSP via meta-tag är en bra start, men HTTP-headers är säkrare:

```nginx
# Nginx exempel
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' https: data:; connect-src 'self' https://your-api.com; frame-ancestors 'none';" always;
```

### HTTPS (Hög prioritet för produktion)

- Konfigurera SSL-certifikat (Let's Encrypt)
- Tvinga HTTPS-redirect
- Lägg till HSTS-header

### Rate limiting på frontend (Låg prioritet)

Förhindra spam av login-knappen:

```typescript
const [canLogin, setCanLogin] = useState(true);

const handleLogin = async () => {
  if (!canLogin) return;
  setCanLogin(false);
  await loginWithGoogle();
  setTimeout(() => setCanLogin(true), 2000);
};
```

### Subresource Integrity (Låg prioritet)

Om externa scripts används, lägg till SRI:

```html
<script
  src="https://example.com/script.js"
  integrity="sha384-..."
  crossorigin="anonymous">
</script>
```

---

## Avancerade säkerhetsförbättringar

### Refresh Token Rotation med Reuse Detection (Hög prioritet)

Förbättra befintlig `generation`-räknare för att detektera token-stöld:

- Vid varje refresh: utfärda ny refresh token, öka generation
- Om en gammal token (lägre generation) används: revokera hela token-familjen
- Detta indikerar att en token har stulits och återanvänds

```rust
// I token_service.rs
if presented_generation < stored_generation {
    // Token replay detected - revoke entire family
    revoke_token_family(family_id).await?;
    return Err(AuthError::TokenReplayDetected);
}
```

### Secure Headers Bundle (Medel prioritet)

Lägg till ytterligare säkerhetsheaders i auth-service:

```rust
// middleware/security_headers.rs
async fn add_security_headers(response: &mut Response) {
    let headers = response.headers_mut();
    headers.insert("X-Content-Type-Options", "nosniff".parse().unwrap());
    headers.insert("X-Frame-Options", "DENY".parse().unwrap());
    headers.insert("Referrer-Policy", "strict-origin-when-cross-origin".parse().unwrap());
    headers.insert("Permissions-Policy", "geolocation=(), camera=(), microphone=()".parse().unwrap());
}
```

### JWT Secret Rotation (Medel prioritet)

Stöd för att rotera JWT-nycklar utan downtime:

1. Lägg till stöd för multipla publika nycklar (current + previous)
2. Validera tokens mot båda nycklar under övergångsperiod
3. Signera endast nya tokens med current key
4. Exponera JWKS-endpoint för automatisk nyckeluppdatering

```rust
// config
jwt_keys: {
    current: { kid: "key-2024-01", private_key: "...", public_key: "..." },
    previous: { kid: "key-2023-06", public_key: "..." }  // endast för validering
}
```

### Token Binding / Device Fingerprinting (Medel prioritet)

Binda refresh tokens till en specifik enhet för att försvåra token-stöld:

```rust
// Lägg till i refresh token claims
device_hash: sha256(user_agent + accept_language + ip_subnet)
```

Vid refresh, verifiera att device_hash matchar. Vid mismatch: kräv re-autentisering.

### Inaktivitetslås (Medel prioritet)

Automatisk utloggning efter inaktivitet:

```typescript
// Frontend: AuthProvider
const INACTIVITY_TIMEOUT = 15 * 60 * 1000; // 15 minuter
let lastActivity = Date.now();

useEffect(() => {
  const events = ['mousedown', 'keydown', 'scroll', 'touchstart'];
  const updateActivity = () => { lastActivity = Date.now(); };
  events.forEach(e => window.addEventListener(e, updateActivity));

  const interval = setInterval(() => {
    if (Date.now() - lastActivity > INACTIVITY_TIMEOUT) {
      logout();
    }
  }, 60000);

  return () => {
    events.forEach(e => window.removeEventListener(e, updateActivity));
    clearInterval(interval);
  };
}, []);
```

### Suspicious Activity Detection (Medel prioritet)

Utöka audit-loggen med anomali-detektering:

- **Brute force**: Lås konto efter N misslyckade inloggningar
- **Geografisk anomali**: Varna vid inloggning från ny plats
- **Velocity check**: Detektera omöjliga resor (inloggning från två länder inom kort tid)
- **API-mönster**: Flagga ovanligt höga anropsfrekvenser

```rust
// services/anomaly_detection.rs
pub async fn check_login_anomalies(user_id: Uuid, ip: IpAddr, user_agent: &str) -> AnomalyResult {
    let recent_logins = get_recent_logins(user_id).await?;

    // Kontrollera geografisk anomali
    if let Some(geo) = geoip_lookup(ip) {
        if is_impossible_travel(&recent_logins, &geo) {
            return AnomalyResult::SuspiciousTravel;
        }
    }

    AnomalyResult::Normal
}
```

### Request Signing för känsliga operationer (Låg prioritet)

Extra skydd för destruktiva operationer (account deletion, password change):

```typescript
// Frontend
const signRequest = (body: object, timestamp: number) => {
  const payload = JSON.stringify({ ...body, timestamp });
  return crypto.subtle.sign('HMAC', sessionKey, new TextEncoder().encode(payload));
};

// Backend verifierar signatur + timestamp inom 5 minuter
```

### Database Encryption at Rest (Låg prioritet)

För extra skydd av känslig data i SQLite:

- Migrera till SQLCipher för transparent kryptering
- Eller kryptera känsliga fält med befintlig AES-256-GCM innan lagring

```toml
# Cargo.toml
sqlx = { version = "0.7", features = ["sqlite", "sqlcipher"] }
```

---

## Prioriteringsordning

| Prioritet | Åtgärd | Komplexitet | Status |
|-----------|--------|-------------|--------|
| 🔴 Hög | Backend Proxy + HttpOnly cookies | Medel | ✅ Klar |
| 🔴 Hög | HTTPS + HSTS | Låg | (Produktionskonfiguration) |
| 🔴 Hög | Refresh Token Reuse Detection | Låg | ✅ Klar (se token_service.rs) |
| 🟡 Medel | CSP via HTTP-headers | Låg | ✅ Klar |
| 🟡 Medel | Secure Headers Bundle | Låg | ✅ Klar |
| 🟡 Medel | JWT Secret Rotation | Medel | ✅ Klar |
| 🟡 Medel | Token Binding | Medel | ✅ Klar |
| 🟡 Medel | Inaktivitetslås | Låg | ✅ Klar |
| 🟡 Medel | Suspicious Activity Detection | Hög | ✅ Klar |
| 🟢 Låg | Rate limiting frontend | Låg | ✅ Klar |
| 🟢 Låg | SRI | Låg | |
| 🟢 Låg | Request Signing | Medel | |
| 🟢 Låg | Database Encryption | Medel | |