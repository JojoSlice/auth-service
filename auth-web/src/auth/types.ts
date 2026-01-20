export interface User {
  id: string;
  email: string;
  display_name: string | null;
  profile_picture_url: string | null;
  email_verified?: boolean;
  created_at?: string;
}

export interface AuthTokens {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
}

export interface AuthResponse extends AuthTokens {
  user: User;
}

export interface AuthConfig {
  apiUrl: string;
}

export interface AuthState {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;
}

export interface AuthContextValue extends AuthState {
  loginWithGoogle: () => Promise<void>;
  loginWithGithub: () => Promise<void>;
  logout: () => Promise<void>;
  refreshToken: () => Promise<void>;
}

export type OAuthProvider = 'google' | 'github';
