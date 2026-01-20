import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { AuthContext } from './AuthContext';
import { AuthApi } from './api';
import type { AuthConfig, AuthState, OAuthProvider, User } from './types';

const STORAGE_KEYS = {
  USER: 'auth_user',
} as const;

const INACTIVITY_TIMEOUT = 15 * 60 * 1000; // 15 minutes
const ACTIVITY_CHECK_INTERVAL = 60 * 1000; // Check every minute

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
  const lastActivityRef = useRef<number>(Date.now());

  const getStoredUser = useCallback((): User | null => {
    const userJson = sessionStorage.getItem(STORAGE_KEYS.USER);
    return userJson ? JSON.parse(userJson) as User : null;
  }, []);

  const storeUser = useCallback((user: User) => {
    sessionStorage.setItem(STORAGE_KEYS.USER, JSON.stringify(user));
  }, []);

  const clearUser = useCallback(() => {
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
    try {
      await api.logout();
    } catch {
      // Ignore errors during logout - cookies are cleared by proxy anyway
    }
    clearUser();
    setState({
      user: null,
      isAuthenticated: false,
      isLoading: false,
      error: null,
    });
  }, [api, clearUser]);

  const refreshToken = useCallback(async () => {
    try {
      await api.refreshToken();
      const user = await api.getProfile();
      storeUser(user);
      setState(s => ({
        ...s,
        user,
        isAuthenticated: true,
        error: null,
      }));
    } catch (error) {
      clearUser();
      setState({
        user: null,
        isAuthenticated: false,
        isLoading: false,
        error: error instanceof Error ? error.message : 'Failed to refresh token',
      });
      throw error;
    }
  }, [api, clearUser, storeUser]);

  // Handle OAuth callback and check auth status on mount
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
          storeUser(response.user);
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

      // Check auth status via cookies
      try {
        const { authenticated } = await api.getAuthStatus();
        if (authenticated) {
          // We have valid cookies, fetch user profile
          const storedUser = getStoredUser();
          if (storedUser) {
            // Use cached user while we fetch fresh data
            setState({
              user: storedUser,
              isAuthenticated: true,
              isLoading: false,
              error: null,
            });
          }

          try {
            const user = await api.getProfile();
            storeUser(user);
            setState({
              user,
              isAuthenticated: true,
              isLoading: false,
              error: null,
            });
          } catch {
            // Profile fetch failed, try to refresh
            try {
              await api.refreshToken();
              const user = await api.getProfile();
              storeUser(user);
              setState({
                user,
                isAuthenticated: true,
                isLoading: false,
                error: null,
              });
            } catch {
              // Refresh failed, user is logged out
              clearUser();
              setState({
                user: null,
                isAuthenticated: false,
                isLoading: false,
                error: null,
              });
            }
          }
        } else {
          // No valid session
          clearUser();
          setState(s => ({ ...s, isLoading: false }));
        }
      } catch {
        // Auth status check failed, assume not authenticated
        clearUser();
        setState(s => ({ ...s, isLoading: false }));
      }
    };

    handleCallback();
  }, [api, clearUser, getStoredUser, storeUser]);

  // Inactivity timeout - auto logout after 15 minutes of inactivity
  useEffect(() => {
    if (!state.isAuthenticated) {
      return;
    }

    const updateActivity = () => {
      lastActivityRef.current = Date.now();
    };

    const checkInactivity = () => {
      const timeSinceLastActivity = Date.now() - lastActivityRef.current;
      if (timeSinceLastActivity >= INACTIVITY_TIMEOUT) {
        logout();
      }
    };

    // Track user activity
    const activityEvents = ['mousedown', 'keydown', 'scroll', 'touchstart', 'mousemove'];
    activityEvents.forEach(event => {
      window.addEventListener(event, updateActivity, { passive: true });
    });

    // Check for inactivity periodically
    const intervalId = setInterval(checkInactivity, ACTIVITY_CHECK_INTERVAL);

    // Reset activity on mount
    updateActivity();

    return () => {
      activityEvents.forEach(event => {
        window.removeEventListener(event, updateActivity);
      });
      clearInterval(intervalId);
    };
  }, [state.isAuthenticated, logout]);

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
