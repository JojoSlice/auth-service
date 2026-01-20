import type { AuthConfig } from './auth';

export const authConfig: AuthConfig = {
  apiUrl: import.meta.env.VITE_AUTH_PROXY_URL || 'http://localhost:4000',
};
