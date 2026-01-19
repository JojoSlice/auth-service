import type { AuthConfig, AuthResponse, AuthTokens, OAuthProvider, User } from './types';

export class AuthApi {
  private config: AuthConfig;

  constructor(config: AuthConfig) {
    this.config = config;
  }

  private async request<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<T> {
    const url = `${this.config.apiUrl}${endpoint}`;
    const headers: HeadersInit = {
      'Content-Type': 'application/json',
      'x-api-key': this.config.apiKey,
      ...options.headers,
    };

    const response = await fetch(url, {
      ...options,
      headers,
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ error: 'Unknown error' }));
      throw new Error(error.error_description || error.error || 'Request failed');
    }

    return response.json();
  }

  async initOAuth(provider: OAuthProvider): Promise<{ authorization_url: string; state: string }> {
    return this.request(`/api/v1/auth/oauth/${provider}/init`, {
      method: 'POST',
      body: JSON.stringify({}),
    });
  }

  async handleOAuthCallback(
    provider: OAuthProvider,
    code: string,
    state: string
  ): Promise<AuthResponse> {
    const params = new URLSearchParams({ code, state });
    return this.request(`/api/v1/auth/oauth/${provider}/callback?${params}`);
  }

  async refreshToken(refreshToken: string): Promise<AuthTokens> {
    return this.request('/api/v1/auth/token/refresh', {
      method: 'POST',
      body: JSON.stringify({ refresh_token: refreshToken }),
    });
  }

  async validateToken(token: string): Promise<{ valid: boolean; user_id: string; email: string; expires_at: number }> {
    return this.request('/api/v1/auth/token/validate', {
      method: 'POST',
      body: JSON.stringify({ token }),
    });
  }

  async revokeToken(accessToken: string, refreshToken?: string, revokeAll = false): Promise<void> {
    await this.request('/api/v1/auth/token/revoke', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
      body: JSON.stringify({
        refresh_token: refreshToken,
        revoke_all: revokeAll,
      }),
    });
  }

  async getProfile(accessToken: string): Promise<User> {
    return this.request('/api/v1/user/profile', {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });
  }
}
