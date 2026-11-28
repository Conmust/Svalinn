import { apiBase, apiFetch, storeTokens, clearSession } from './api';

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

  // `dev_verification_link` is only ever present when the server is running
  // with APP_ENV=development (see svalinn-server's routes::auth) -- there's
  // no real email provider wired up yet, so the server hands the link back
  // directly instead of mailing it. Following it automatically here means
  // joining a server works right away in local testing, the same as it
  // will once a real "click the email link" flow exists; this is a no-op
  // in any other environment, since the field is simply absent there.
  if (data.dev_verification_link) {
    try {
      await fetch(data.dev_verification_link);
    } catch {
      // Best-effort only -- registration itself already succeeded.
    }
  }

  return data.user;
}

/**
 * Requests a fresh verification link for the logged-in account. Needed
 * because, without this, anyone whose original registration link never
 * arrived (there's no real email provider wired up yet -- see the server's
 * `routes::auth::send_verification_email`) or whose 48-hour link expired
 * would have no way back in: `accept_invite` requires a verified email to
 * join any server.
 */
export async function resendVerificationEmail(): Promise<void> {
  const response = await apiFetch(`${apiBase()}/api/v1/auth/resend-verification`, { method: 'POST' });

  if (!response.ok) {
    const err = await response.json().catch(() => ({ error: 'Failed to resend the verification email' }));
    throw new Error(err.error || 'Failed to resend the verification email');
  }

  const data = await response.json().catch(() => ({}));
  // Same dev-only convenience as `register()` above: with no real email
  // provider wired up, following the link ourselves is how local
  // dev/testing verifies without an inbox. No-op (and `dev_verification_link`
  // simply absent) in any other environment.
  if (data.dev_verification_link) {
    try {
      await fetch(data.dev_verification_link);
    } catch {
      // Best-effort only -- the resend itself already succeeded.
    }
  }
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