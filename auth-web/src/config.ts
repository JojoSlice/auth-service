import type { AuthConfig } from './auth';

const apiKey = import.meta.env.VITE_AUTH_API_KEY || '';

if (!apiKey) {
  console.warn(
    '[Auth] VITE_AUTH_API_KEY is not configured. ' +
    'Authentication will not work. ' +
    'See .env.example for setup instructions.'
  );
}

export const authConfig: AuthConfig = {
  apiUrl: import.meta.env.VITE_AUTH_API_URL || 'http://localhost:3000',
  apiKey,
};

export const isConfigValid = Boolean(apiKey);
