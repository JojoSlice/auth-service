import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react';
import { AuthContext } from './AuthContext';
import { AuthApi } from './api';
import type { AuthConfig, AuthState, OAuthProvider, User } from './types';

const STORAGE_KEYS = {
  ACCESS_TOKEN: 'auth_access_token',
  REFRESH_TOKEN: 'auth_refresh_token',
  USER: 'auth_user',
} as const;

interface AuthProviderProps {
  children: ReactNode;
  config: AuthConfig;
}

export function AuthProvider({ children, config }: AuthProviderProps) {
  const [state, setState] = useState<AuthState>({
    user: null,
    isAuthenticated: false,
    isLoading: true,
    error: null,
  });

  const api = useMemo(() => new AuthApi(config), [config]);

  const getStoredTokens = useCallback(() => {
    const accessToken = sessionStorage.getItem(STORAGE_KEYS.ACCESS_TOKEN);
    const refreshToken = sessionStorage.getItem(STORAGE_KEYS.REFRESH_TOKEN);
    const userJson = sessionStorage.getItem(STORAGE_KEYS.USER);
    const user = userJson ? JSON.parse(userJson) as User : null;
    return { accessToken, refreshToken, user };
  }, []);

  const storeTokens = useCallback((accessToken: string, refreshToken: string, user: User) => {
    sessionStorage.setItem(STORAGE_KEYS.ACCESS_TOKEN, accessToken);
    sessionStorage.setItem(STORAGE_KEYS.REFRESH_TOKEN, refreshToken);
    sessionStorage.setItem(STORAGE_KEYS.USER, JSON.stringify(user));
  }, []);

  const clearTokens = useCallback(() => {
    sessionStorage.removeItem(STORAGE_KEYS.ACCESS_TOKEN);
    sessionStorage.removeItem(STORAGE_KEYS.REFRESH_TOKEN);
    sessionStorage.removeItem(STORAGE_KEYS.USER);
  }, []);

  const initOAuthFlow = useCallback(async (provider: OAuthProvider) => {
    setState(s => ({ ...s, isLoading: true, error: null }));
    try {
      const { authorization_url, state: oauthState } = await api.initOAuth(provider);
      sessionStorage.setItem('oauth_state', oauthState);
      sessionStorage.setItem('oauth_provider', provider);
      window.location.href = authorization_url;
    } catch (error) {
      setState(s => ({
        ...s,
        isLoading: false,
        error: error instanceof Error ? error.message : 'Failed to initiate login',
      }));
    }
  }, [api]);

  const loginWithGoogle = useCallback(() => initOAuthFlow('google'), [initOAuthFlow]);
  const loginWithGithub = useCallback(() => initOAuthFlow('github'), [initOAuthFlow]);

  const logout = useCallback(async () => {
    const { accessToken, refreshToken } = getStoredTokens();
    if (accessToken) {
      try {
        await api.revokeToken(accessToken, refreshToken || undefined, true);
      } catch {
        // Ignore errors during logout
      }
    }
    clearTokens();
    setState({
      user: null,
      isAuthenticated: false,
      isLoading: false,
      error: null,
    });
  }, [api, clearTokens, getStoredTokens]);

  const refreshToken = useCallback(async () => {
    const { refreshToken: storedRefreshToken } = getStoredTokens();
    if (!storedRefreshToken) {
      throw new Error('No refresh token available');
    }

    try {
      const tokens = await api.refreshToken(storedRefreshToken);
      const user = await api.getProfile(tokens.access_token);

      storeTokens(tokens.access_token, tokens.refresh_token, user);
      setState(s => ({
        ...s,
        user,
        isAuthenticated: true,
        error: null,
      }));
    } catch (error) {
      clearTokens();
      setState({
        user: null,
        isAuthenticated: false,
        isLoading: false,
        error: error instanceof Error ? error.message : 'Failed to refresh token',
      });
      throw error;
    }
  }, [api, clearTokens, getStoredTokens, storeTokens]);

  // Handle OAuth callback
  useEffect(() => {
    const handleCallback = async () => {
      const params = new URLSearchParams(window.location.search);
      const code = params.get('code');
      const state = params.get('state');
      const storedState = sessionStorage.getItem('oauth_state');
      const provider = sessionStorage.getItem('oauth_provider') as OAuthProvider | null;

      if (code && state && storedState && provider) {
        if (state !== storedState) {
          setState(s => ({
            ...s,
            isLoading: false,
            error: 'Invalid OAuth state',
          }));
          return;
        }

        sessionStorage.removeItem('oauth_state');
        sessionStorage.removeItem('oauth_provider');

        try {
          const response = await api.handleOAuthCallback(provider, code, state);
          storeTokens(response.access_token, response.refresh_token, response.user);
          setState({
            user: response.user,
            isAuthenticated: true,
            isLoading: false,
            error: null,
          });
          // Clean URL
          window.history.replaceState({}, '', window.location.pathname);
        } catch (error) {
          setState({
            user: null,
            isAuthenticated: false,
            isLoading: false,
            error: error instanceof Error ? error.message : 'Login failed',
          });
        }
        return;
      }

      // Check for existing session
      const { accessToken, refreshToken: storedRefresh, user } = getStoredTokens();
      if (accessToken && user) {
        try {
          const validation = await api.validateToken(accessToken);
          if (validation.valid) {
            setState({
              user,
              isAuthenticated: true,
              isLoading: false,
              error: null,
            });
            return;
          }
        } catch {
          // Token invalid, try refresh
        }

        if (storedRefresh) {
          try {
            const tokens = await api.refreshToken(storedRefresh);
            const freshUser = await api.getProfile(tokens.access_token);
            storeTokens(tokens.access_token, tokens.refresh_token, freshUser);
            setState({
              user: freshUser,
              isAuthenticated: true,
              isLoading: false,
              error: null,
            });
            return;
          } catch {
            clearTokens();
          }
        }
      }

      setState(s => ({ ...s, isLoading: false }));
    };

    handleCallback();
  }, [api, clearTokens, getStoredTokens, storeTokens]);

  const value = useMemo(() => ({
    ...state,
    loginWithGoogle,
    loginWithGithub,
    logout,
    refreshToken,
  }), [state, loginWithGoogle, loginWithGithub, logout, refreshToken]);

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
}
