import { apiBase, storeTokens, clearSession } from './api';

export interface User {
  id: string;
  username: string;
  email: string;
  patron_tier?: string;
  status?: string;
  avatar_url?: string | null;
  is_site_owner?: boolean;
}

export function getCurrentUser(): User | null {
  const userStr = localStorage.getItem('user');
  if (!userStr) return null;
  
  try {
    return JSON.parse(userStr);
  } catch {
    return null;
  }
}

export async function login(email: string, password: string): Promise<User> {
  const response = await fetch(`${apiBase()}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });

  if (!response.ok) {
    const err = await response.json().catch(() => ({ error: 'Login failed' }));
    throw new Error(err.error || 'Login failed');
  }

  const data = await response.json();
  
  // Store the tokens and user
  storeTokens(data.token, data.refresh_token);
  localStorage.setItem('user', JSON.stringify(data.user));
  
  return data.user;
}

export async function register(username: string, email: string, password: string): Promise<User> {
  const response = await fetch(`${apiBase()}/api/v1/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, email, password }),
  });

  if (!response.ok) {
    const err = await response.json().catch(() => ({ error: 'Registration failed' }));
    throw new Error(err.error || 'Registration failed');
  }

  const data = await response.json();
  
  // Store the tokens and user
  storeTokens(data.token, data.refresh_token);
  localStorage.setItem('user', JSON.stringify(data.user));
  
  return data.user;
}

export function setAuth(token: string, user: User, refreshToken?: string): void {
  storeTokens(token, refreshToken);
  localStorage.setItem('user', JSON.stringify(user));
}

export function updateUserInStorage(user: User): void {
  localStorage.setItem('user', JSON.stringify(user));
}

export function logout(): void {
  // End the session on the server too, so the refresh token can't be reused.
  const refreshToken = localStorage.getItem('refresh_token');
  if (refreshToken) {
    fetch(`${apiBase()}/api/v1/auth/logout`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: refreshToken }),
      keepalive: true,
    }).catch(() => {});
  }
  clearSession();
}

export function getToken(): string | null {
  return localStorage.getItem('token');
}