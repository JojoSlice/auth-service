# TODO: Säkerhetsförbättringar

## Backend Proxy (Hög prioritet)

Nuvarande implementation exponerar API-nyckeln i klientkoden. En backend-proxy löser detta och möjliggör säkrare token-hantering.

### Vad som behövs

1. **Skapa en proxy-server** (Node.js/Express, eller liknande)
   ```
   /api/auth/google     → POST → auth-service /api/v1/auth/oauth/google/init
   /api/auth/callback   → GET  → auth-service /api/v1/auth/oauth/{provider}/callback
   /api/auth/refresh    → POST → auth-service /api/v1/auth/token/refresh
   /api/auth/logout     → POST → auth-service /api/v1/auth/token/revoke
   /api/user/profile    → GET  → auth-service /api/v1/user/profile
   ```

2. **Flytta API-nyckeln till backend**
   - Lagra `AUTH_API_KEY` som miljövariabel på servern
   - Ta bort `VITE_AUTH_API_KEY` från frontend

3. **Använd HttpOnly cookies**
   - Backend sätter tokens i HttpOnly cookies vid inloggning
   - Frontend behöver inte hantera tokens direkt
   - Cookies skickas automatiskt med varje request

### Exempel på proxy-endpoint

```typescript
// /api/auth/google
app.post('/api/auth/google', async (req, res) => {
  const response = await fetch(`${AUTH_SERVICE_URL}/api/v1/auth/oauth/google/init`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': process.env.AUTH_API_KEY,
    },
  });

  const data = await response.json();
  res.json(data);
});

// /api/auth/callback
app.get('/api/auth/callback', async (req, res) => {
  const { code, state, provider } = req.query;

  const response = await fetch(
    `${AUTH_SERVICE_URL}/api/v1/auth/oauth/${provider}/callback?code=${code}&state=${state}`,
    { headers: { 'x-api-key': process.env.AUTH_API_KEY } }
  );

  const data = await response.json();

  // Sätt HttpOnly cookies
  res.cookie('access_token', data.access_token, {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    maxAge: data.expires_in * 1000,
  });

  res.cookie('refresh_token', data.refresh_token, {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    maxAge: 30 * 24 * 60 * 60 * 1000, // 30 dagar
  });

  res.json({ user: data.user });
});
```

### Uppdatera frontend

Efter proxy är implementerad:

1. Ta bort `VITE_AUTH_API_KEY` från config
2. Ändra API-url:er till proxy-endpoints
3. Ta bort token-lagring i sessionStorage
4. Uppdatera AuthProvider att hantera cookie-baserad auth

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

| Prioritet | Åtgärd | Komplexitet |
|-----------|--------|-------------|
| 🔴 Hög | Backend Proxy + HttpOnly cookies | Medel |
| 🔴 Hög | HTTPS + HSTS | Låg |
| 🔴 Hög | Refresh Token Reuse Detection | Låg |
| 🟡 Medel | CSP via HTTP-headers | Låg |
| 🟡 Medel | Secure Headers Bundle | Låg |
| 🟡 Medel | JWT Secret Rotation | Medel |
| 🟡 Medel | Token Binding | Medel |
| 🟡 Medel | Inaktivitetslås | Låg |
| 🟡 Medel | Suspicious Activity Detection | Hög |
| 🟢 Låg | Rate limiting frontend | Låg |
| 🟢 Låg | SRI | Låg |
| 🟢 Låg | Request Signing | Medel |
| 🟢 Låg | Database Encryption | Medel |