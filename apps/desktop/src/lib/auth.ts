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

/** What `login` resolves to when the account has 2FA enabled: no session
 * yet, just a short-lived handle for `completeTotpLogin` to finish the job
 * once the person enters a code. */
export interface TwoFactorRequired {
  requiresTwoFactor: true;
  pendingToken: string;
}

export function isTwoFactorRequired(x: User | TwoFactorRequired): x is TwoFactorRequired {
  return (x as TwoFactorRequired).requiresTwoFactor === true;
}

export async function login(email: string, password: string): Promise<User | TwoFactorRequired> {
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

  // A 2FA-enabled account stops here: no tokens to store yet, just a
  // pending-login handle for the caller to pass to `completeTotpLogin`
  // once the person has entered a code.
  if (data.requires_2fa) {
    return { requiresTwoFactor: true, pendingToken: data.pending_token };
  }

  // Store the tokens and user
  storeTokens(data.token, data.refresh_token);
  localStorage.setItem('user', JSON.stringify(data.user));

  return data.user;
}

/**
 * Finishes a login that `login()` left pending on a 2FA-enabled account.
 * `code` can be either a 6-digit authenticator code or one of the
 * account's backup codes -- the server accepts either (see
 * `routes::auth::totp_login`).
 */
export async function completeTotpLogin(pendingToken: string, code: string): Promise<User> {
  const response = await fetch(`${apiBase()}/api/v1/auth/2fa/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ pending_token: pendingToken, code }),
  });

  if (!response.ok) {
    const err = await response.json().catch(() => ({ error: 'That code is incorrect' }));
    throw new Error(err.error || 'That code is incorrect');
  }

  const data = await response.json();
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

/**
 * Requests a password-reset email. Always resolves (there's no "that email
 * doesn't exist" error to surface) -- the server deliberately returns the
 * same response whether or not the account exists, so this can't be used to
 * check whether someone has a Svalinn account. Returns a link to the reset
 * page only under APP_ENV=development, for local testing without a real
 * inbox; this is a standalone web page (not part of the desktop app), since
 * actually resetting the password means typing one in, which a clicked
 * link alone can't do for an app with no deep-link handler.
 */
export async function forgotPassword(email: string): Promise<{ devResetLink?: string }> {
  const response = await fetch(`${apiBase()}/api/v1/auth/forgot-password`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email }),
  });

  if (!response.ok) {
    // The server only fails this closed on its own rate limit, which still
    // shouldn't reveal account existence -- so there's nothing account-
    // specific to show here either.
    const err = await response.json().catch(() => ({ error: 'Could not request a password reset right now.' }));
    throw new Error(err.error || 'Could not request a password reset right now.');
  }

  const data = await response.json().catch(() => ({}));
  return { devResetLink: data.dev_reset_link };
}

// ---------- Two-factor authentication (TOTP) ----------

/** Starts (or restarts) 2FA setup. Nothing is enabled until `enableTotp`
 * confirms a real code -- calling this again before confirming just
 * replaces whatever secret/QR code was shown last. */
export async function setupTotp(): Promise<{ secret: string; otpauthUrl: string }> {
  const response = await apiFetch(`${apiBase()}/api/v1/users/me/2fa/setup`, { method: 'POST' });
  if (!response.ok) {
    const err = await response.json().catch(() => ({ error: 'Could not start two-factor setup' }));
    throw new Error(err.error || 'Could not start two-factor setup');
  }
  const data = await response.json();
  return { secret: data.secret, otpauthUrl: data.otpauth_url };
}

/** Confirms setup with a real code from the authenticator and turns 2FA on.
 * Returns the backup codes -- shown only this once, so the caller needs to
 * display them somewhere the person can actually save. */
export async function enableTotp(code: string): Promise<{ backupCodes: string[] }> {
  const response = await apiFetch(`${apiBase()}/api/v1/users/me/2fa/enable`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code }),
  });
  if (!response.ok) {
    const err = await response.json().catch(() => ({ error: 'That code is incorrect' }));
    throw new Error(err.error || 'That code is incorrect');
  }
  const data = await response.json();
  return { backupCodes: data.backup_codes };
}

export async function disableTotp(currentPassword: string): Promise<void> {
  const response = await apiFetch(`${apiBase()}/api/v1/users/me/2fa/disable`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ current_password: currentPassword }),
  });
  if (!response.ok) {
    const err = await response.json().catch(() => ({ error: 'Could not disable two-factor authentication' }));
    throw new Error(err.error || 'Could not disable two-factor authentication');
  }
}

/** Invalidates every existing backup code and issues a fresh set of 8. */
export async function regenerateBackupCodes(currentPassword: string): Promise<{ backupCodes: string[] }> {
  const response = await apiFetch(`${apiBase()}/api/v1/users/me/2fa/backup-codes/regenerate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ current_password: currentPassword }),
  });
  if (!response.ok) {
    const err = await response.json().catch(() => ({ error: 'Could not regenerate backup codes' }));
    throw new Error(err.error || 'Could not regenerate backup codes');
  }
  const data = await response.json();
  return { backupCodes: data.backup_codes };
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