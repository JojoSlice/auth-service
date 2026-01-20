import express, { Request, Response, NextFunction } from 'express';
import cookieParser from 'cookie-parser';
import cors from 'cors';

// Auth service response types
interface AuthTokenResponse {
  access_token: string;
  refresh_token?: string;
  expires_in: number;
  user?: unknown;
  error?: string;
}

const app = express();

// Configuration from environment
const PORT = process.env.PORT || 4000;
const AUTH_SERVICE_URL = process.env.AUTH_SERVICE_URL || 'http://localhost:3000';
const AUTH_API_KEY = process.env.AUTH_API_KEY || '';
const COOKIE_DOMAIN = process.env.COOKIE_DOMAIN || 'localhost';
const COOKIE_SECURE = process.env.COOKIE_SECURE === 'true';
const CORS_ORIGIN = process.env.CORS_ORIGIN || 'http://localhost:5173';

if (!AUTH_API_KEY) {
  console.error('[auth-proxy] ERROR: AUTH_API_KEY is not set');
  process.exit(1);
}

// Cookie configuration
const cookieOptions = {
  httpOnly: true,
  secure: COOKIE_SECURE,
  sameSite: 'strict' as const,
  domain: COOKIE_DOMAIN,
  path: '/',
};

// Security headers middleware
app.use((_req: Request, res: Response, next: NextFunction) => {
  // Prevent MIME type sniffing
  res.setHeader('X-Content-Type-Options', 'nosniff');
  // Prevent clickjacking
  res.setHeader('X-Frame-Options', 'DENY');
  // Control referrer information
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  // Disable unnecessary browser features
  res.setHeader('Permissions-Policy', 'geolocation=(), camera=(), microphone=(), payment=()');
  // Prevent XSS attacks (legacy)
  res.setHeader('X-XSS-Protection', '1; mode=block');
  // Cache control for API responses
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.setHeader('Pragma', 'no-cache');
  // Content Security Policy - strict for API
  res.setHeader('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'");
  next();
});

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(cors({
  origin: CORS_ORIGIN,
  credentials: true,
}));

// Helper to forward requests to auth-service
async function authServiceRequest(
  endpoint: string,
  options: { method?: string; headers?: Record<string, string>; body?: string } = {}
): Promise<globalThis.Response> {
  const url = `${AUTH_SERVICE_URL}${endpoint}`;
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'x-api-key': AUTH_API_KEY,
    ...options.headers,
  };

  return fetch(url, {
    ...options,
    headers,
  });
}

// Health check
app.get('/health', (_req, res) => {
  res.json({ status: 'ok', service: 'auth-proxy' });
});

// OAuth init - starts OAuth flow
app.post('/api/auth/:provider/init', async (req: Request, res: Response) => {
  try {
    const { provider } = req.params;

    const response = await authServiceRequest(`/api/v1/auth/oauth/${provider}/init`, {
      method: 'POST',
      body: JSON.stringify({}),
    });

    const data = await response.json();

    if (!response.ok) {
      return res.status(response.status).json(data);
    }

    res.json(data);
  } catch (error) {
    console.error('[auth-proxy] OAuth init error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// OAuth callback - exchanges code for tokens and sets cookies
app.get('/api/auth/:provider/callback', async (req: Request, res: Response) => {
  try {
    const { provider } = req.params;
    const { code, state } = req.query;

    if (!code || !state) {
      return res.status(400).json({ error: 'Missing code or state parameter' });
    }

    const params = new URLSearchParams({
      code: code as string,
      state: state as string,
    });

    const response = await authServiceRequest(
      `/api/v1/auth/oauth/${provider}/callback?${params}`
    );

    const data = await response.json() as AuthTokenResponse;

    if (!response.ok) {
      return res.status(response.status).json(data);
    }

    // Set HttpOnly cookies for tokens
    res.cookie('access_token', data.access_token, {
      ...cookieOptions,
      maxAge: data.expires_in * 1000,
    });

    res.cookie('refresh_token', data.refresh_token, {
      ...cookieOptions,
      maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
    });

    // Return user info (without tokens)
    res.json({
      user: data.user,
      expires_in: data.expires_in,
    });
  } catch (error) {
    console.error('[auth-proxy] OAuth callback error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Token refresh - uses refresh_token cookie
app.post('/api/auth/refresh', async (req: Request, res: Response) => {
  try {
    const refreshToken = req.cookies.refresh_token;

    if (!refreshToken) {
      return res.status(401).json({ error: 'No refresh token' });
    }

    const response = await authServiceRequest('/api/v1/auth/token/refresh', {
      method: 'POST',
      body: JSON.stringify({ refresh_token: refreshToken }),
    });

    const data = await response.json() as AuthTokenResponse;

    if (!response.ok) {
      // Clear cookies on refresh failure
      res.clearCookie('access_token', cookieOptions);
      res.clearCookie('refresh_token', cookieOptions);
      return res.status(response.status).json(data);
    }

    // Update cookies with new tokens
    res.cookie('access_token', data.access_token, {
      ...cookieOptions,
      maxAge: data.expires_in * 1000,
    });

    if (data.refresh_token) {
      res.cookie('refresh_token', data.refresh_token, {
        ...cookieOptions,
        maxAge: 30 * 24 * 60 * 60 * 1000,
      });
    }

    res.json({
      expires_in: data.expires_in,
    });
  } catch (error) {
    console.error('[auth-proxy] Token refresh error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Logout - revokes tokens and clears cookies
app.post('/api/auth/logout', async (req: Request, res: Response) => {
  try {
    const accessToken = req.cookies.access_token;
    const refreshToken = req.cookies.refresh_token;

    if (accessToken) {
      // Try to revoke tokens on the auth service
      await authServiceRequest('/api/v1/auth/token/revoke', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
        body: JSON.stringify({
          refresh_token: refreshToken,
          revoke_all: false,
        }),
      }).catch(() => {
        // Ignore errors - we'll clear cookies anyway
      });
    }

    // Clear cookies
    res.clearCookie('access_token', cookieOptions);
    res.clearCookie('refresh_token', cookieOptions);

    res.json({ success: true });
  } catch (error) {
    console.error('[auth-proxy] Logout error:', error);
    // Clear cookies even on error
    res.clearCookie('access_token', cookieOptions);
    res.clearCookie('refresh_token', cookieOptions);
    res.json({ success: true });
  }
});

// Get user profile - uses access_token cookie
app.get('/api/user/profile', async (req: Request, res: Response) => {
  try {
    const accessToken = req.cookies.access_token;

    if (!accessToken) {
      return res.status(401).json({ error: 'Not authenticated' });
    }

    const response = await authServiceRequest('/api/v1/user/profile', {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });

    const data = await response.json();

    if (!response.ok) {
      return res.status(response.status).json(data);
    }

    res.json(data);
  } catch (error) {
    console.error('[auth-proxy] Get profile error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Check auth status - returns whether user is authenticated
app.get('/api/auth/status', (req: Request, res: Response) => {
  const accessToken = req.cookies.access_token;
  res.json({
    authenticated: Boolean(accessToken),
  });
});

// Error handler
app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  console.error('[auth-proxy] Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// Start server
app.listen(PORT, () => {
  console.log(`[auth-proxy] Server running on http://localhost:${PORT}`);
  console.log(`[auth-proxy] Proxying to auth-service at ${AUTH_SERVICE_URL}`);
  console.log(`[auth-proxy] CORS origin: ${CORS_ORIGIN}`);
});
