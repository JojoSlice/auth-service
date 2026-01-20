import type { AuthConfig, OAuthProvider, User } from './types';

interface OAuthCallbackResponse {
  user: User;
  expires_in: number;
}

interface RefreshResponse {
  expires_in: number;
}

interface AuthStatusResponse {
  authenticated: boolean;
}

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
      ...options.headers,
    };

    const response = await fetch(url, {
      ...options,
      headers,
      credentials: 'include', // Send cookies with requests
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ error: 'Unknown error' }));
      throw new Error(error.error_description || error.error || 'Request failed');
    }

    return response.json();
  }

  async initOAuth(provider: OAuthProvider): Promise<{ authorization_url: string; state: string }> {
    return this.request(`/api/auth/${provider}/init`, {
      method: 'POST',
    });
  }

  async handleOAuthCallback(
    provider: OAuthProvider,
    code: string,
    state: string
  ): Promise<OAuthCallbackResponse> {
    const params = new URLSearchParams({ code, state });
    return this.request(`/api/auth/${provider}/callback?${params}`);
  }

  async refreshToken(): Promise<RefreshResponse> {
    return this.request('/api/auth/refresh', {
      method: 'POST',
    });
  }

  async logout(): Promise<void> {
    await this.request('/api/auth/logout', {
      method: 'POST',
    });
  }

  async getProfile(): Promise<User> {
    return this.request('/api/user/profile');
  }

  async getAuthStatus(): Promise<AuthStatusResponse> {
    return this.request('/api/auth/status');
  }
}
