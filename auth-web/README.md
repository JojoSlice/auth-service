# Auth Service Web

Minimalistisk React-webbapp för autentisering via OAuth (Google/GitHub).

## Komma igång

```bash
npm install
cp .env.example .env
```

Konfigurera `.env`:

```
VITE_AUTH_API_URL=http://localhost:3000
VITE_AUTH_API_KEY=din-api-nyckel
```

Starta utvecklingsservern:

```bash
npm run dev
```

## Användning i andra projekt

Auth-modulen är byggd för att kunna återanvändas. Kopiera `src/auth/`-mappen till ditt projekt och använd den så här:

```tsx
import { AuthProvider, useAuth } from './auth';

// Wrappa din app
function App() {
  return (
    <AuthProvider config={{ apiUrl: '...', apiKey: '...' }}>
      <MyApp />
    </AuthProvider>
  );
}

// Använd hooken i komponenter
function MyComponent() {
  const { user, isAuthenticated, loginWithGoogle, logout } = useAuth();

  if (!isAuthenticated) {
    return <button onClick={loginWithGoogle}>Logga in</button>;
  }

  return (
    <div>
      <p>Inloggad som {user.email}</p>
      <button onClick={logout}>Logga ut</button>
    </div>
  );
}
```

## API

### `useAuth()`

| Property | Typ | Beskrivning |
|----------|-----|-------------|
| `user` | `User \| null` | Inloggad användare |
| `isAuthenticated` | `boolean` | Om användaren är inloggad |
| `isLoading` | `boolean` | Laddar autentiseringsstatus |
| `error` | `string \| null` | Felmeddelande |
| `loginWithGoogle()` | `() => Promise<void>` | Starta Google OAuth |
| `loginWithGithub()` | `() => Promise<void>` | Starta GitHub OAuth |
| `logout()` | `() => Promise<void>` | Logga ut |
| `refreshToken()` | `() => Promise<void>` | Uppdatera access token |

### `User`

```ts
interface User {
  id: string;
  email: string;
  display_name: string | null;
  profile_picture_url: string | null;
}
```

## Scripts

| Kommando | Beskrivning |
|----------|-------------|
| `npm run dev` | Starta utvecklingsserver |
| `npm run build` | Bygg för produktion |
| `npm run preview` | Förhandsgranska produktionsbygget |
