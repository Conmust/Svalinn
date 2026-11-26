// Authenticated requests to the Svalinn server.
//
// Logins hold two tokens in localStorage:
// - `token`: short-lived access token (5 minutes), sent with every request;
// - `refresh_token`: long-lived (90 days), only used to get new tokens.
//
// `apiFetch` refreshes the access token shortly before it expires, and if a
// request still comes back 401 it refreshes once and retries. Every
// authenticated request should go through it.

const SERVER_URL_KEY = 'svalinn_server_url';
/** Server used unless the user picks another one. Set VITE_API_URL when building. */
export const DEFAULT_SERVER_URL: string =
  (import.meta.env.VITE_API_URL as string | undefined)?.replace(/\/+$/, '') || 'http://localhost:3001';

/** Address of the Svalinn server, e.g. "https://chat.example.com". */
export function apiBase(): string {
  try {
    return localStorage.getItem(SERVER_URL_KEY) || DEFAULT_SERVER_URL;
  } catch {
    return DEFAULT_SERVER_URL;
  }
}

/** WebSocket address of the server (ws:// or wss://). */
export function wsBase(): string {
  return apiBase().replace(/^http/i, 'ws');
}

/**
 * Validates and saves the server address. Returns the normalized URL, or
 * throws with a message to show. Saving the default clears the override.
 */
export function setServerUrl(input: string): string {
  let url: URL;
  try {
    url = new URL(input.trim());
  } catch {
    throw new Error('Enter a full address, like https://chat.example.com');
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error('The server address must start with http:// or https://');
  }
  const normalized = url.origin;
  if (normalized === DEFAULT_SERVER_URL) localStorage.removeItem(SERVER_URL_KEY);
  else localStorage.setItem(SERVER_URL_KEY, normalized);
  return normalized;
}

/** Schemes `fileUrl` treats as already-absolute and safe to render directly
 * into an `href`/`src`/`<source>`: `http(s):` for a signed server link or a
 * genuine external URL (the server accepts and stores those for an avatar,
 * server icon, or attachment -- see `files::is_safe_external_url` there),
 * and `blob:` for a locally-decrypted attachment's object URL (see
 * `ChatArea.svelte`/`DMChatArea.svelte`'s `ensureAttachmentDecrypted`, which
 * substitutes one of these in place of `attachment_url` for an encrypted
 * message -- always created locally via `URL.createObjectURL()`, never a
 * value the server hands back). Deliberately an allow-list, not "has any
 * scheme at all": this is rendered straight into a clickable link with no
 * further check (see every `fileUrl(...)` call site), so treating, say, a
 * `javascript:` URL the same as an `http:` one would let it run in this
 * app's own origin -- with access to everything in `localStorage`, private
 * keys included -- the moment someone clicked the resulting "attachment"
 * link. The server already rejects a value like that outright before it's
 * ever stored, but this is the one place every such value is about to be
 * rendered, so it gets its own check too rather than trusting every past
 * and future caller to have validated what it received.
 */
const SAFE_ABSOLUTE_FILE_URL_SCHEMES = /^(https?|blob):/i;

/**
 * Full URL for a file link from the server. Uploaded files come as signed,
 * session-bound paths ("/api/v1/files/..."); a safe external link (see
 * `SAFE_ABSOLUTE_FILE_URL_SCHEMES`) is kept as it is. Anything else --
 * including a relative `/uploads/...` path, but also anything that isn't
 * recognized as a safe absolute URL at all -- gets `apiBase()` glued onto
 * the front of it, which for a bare relative path produces the intended
 * server-relative link, and for anything else just produces a harmless,
 * non-executing string rather than rendering it as-is.
 */
export function fileUrl(path: string | null | undefined): string {
  if (!path) return '';
  return SAFE_ABSOLUTE_FILE_URL_SCHEMES.test(path) ? path : `${apiBase()}${path}`;
}

/** Refresh this long before the access token expires. */
const REFRESH_MARGIN_MS = 30_000;

export function getAuthHeaders(): Record<string, string> {
  const token = localStorage.getItem('token');

  if (!token) {
    console.warn('No auth token found in localStorage');
    return {};
  }

  return {
    'Authorization': `Bearer ${token}`
  };
}

export function getAuthHeadersWithJson(): Record<string, string> {
  return {
    'Content-Type': 'application/json',
    ...getAuthHeaders()
  };
}

/** Stores the tokens from a login, register or refresh response. */
export function storeTokens(token: string, refreshToken?: string): void {
  localStorage.setItem('token', token);
  if (refreshToken) localStorage.setItem('refresh_token', refreshToken);
}

export function clearSession(): void {
  localStorage.removeItem('token');
  localStorage.removeItem('refresh_token');
  localStorage.removeItem('user');
}

const LOGOUT_REASON_KEY = 'svalinn_logout_reason';

/** Signs out locally and returns to the login screen, which shows `reason`. */
export function endSession(reason?: string): void {
  clearSession();
  try {
    if (reason) sessionStorage.setItem(LOGOUT_REASON_KEY, reason);
  } catch {
    // storage unavailable: the login screen just won't show a reason
  }
  location.reload();
}

/** Why the last session ended, if it was ended by the server. Read once. */
export function takeLogoutReason(): string | null {
  try {
    const reason = sessionStorage.getItem(LOGOUT_REASON_KEY);
    sessionStorage.removeItem(LOGOUT_REASON_KEY);
    return reason;
  } catch {
    return null;
  }
}

/** Expiry of a JWT in milliseconds since the epoch, or null if unreadable. */
function tokenExpiry(token: string): number | null {
  try {
    const payload = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
    const { exp } = JSON.parse(atob(payload));
    return typeof exp === 'number' ? exp * 1000 : null;
  } catch {
    return null;
  }
}

function isFresh(token: string | null): token is string {
  if (!token) return false;
  const exp = tokenExpiry(token);
  return exp !== null && exp - Date.now() > REFRESH_MARGIN_MS;
}

/** A usable access token, refreshing first if it's about to expire. Null if logged out. */
export async function getValidAccessToken(): Promise<string | null> {
  const token = localStorage.getItem('token');
  if (!token && !localStorage.getItem('refresh_token')) return null;
  if (isFresh(token)) return token;
  return refreshAccessToken();
}

let inFlight: Promise<string | null> | null = null;

/**
 * Gets a new access token using the refresh token. Concurrent callers share one
 * request. `rejectedToken` is an access token the server just refused, which
 * must be replaced even if it hasn't expired yet.
 */
export function refreshAccessToken(rejectedToken?: string): Promise<string | null> {
  if (!inFlight) {
    inFlight = withRefreshLock(() => doRefresh(rejectedToken)).finally(() => {
      inFlight = null;
    });
  }
  return inFlight;
}

/**
 * Each refresh token works once, so two windows refreshing at the same moment
 * would log each other out. Web Locks make them take turns; the second one then
 * finds the first one's new tokens already stored.
 */
async function withRefreshLock<T>(fn: () => Promise<T>): Promise<T> {
  const locks = (navigator as Navigator & { locks?: LockManager }).locks;
  return locks ? locks.request('svalinn-token-refresh', fn) : fn();
}

async function doRefresh(rejectedToken?: string): Promise<string | null> {
  // Another window may have refreshed while we waited.
  const current = localStorage.getItem('token');
  if (current !== rejectedToken && isFresh(current)) return current;

  const refreshToken = localStorage.getItem('refresh_token');
  if (!refreshToken) return null;

  let response: Response;
  try {
    response = await fetch(`${apiBase()}/api/v1/auth/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: refreshToken }),
    });
  } catch {
    return null; // offline: keep the session and try again later
  }

  if (response.ok) {
    const data = await response.json();
    storeTokens(data.token, data.refresh_token);
    return data.token;
  }

  if (response.status === 401) {
    // Without Web Locks another window may have rotated the token meanwhile.
    if (localStorage.getItem('refresh_token') !== refreshToken) {
      return localStorage.getItem('token');
    }
    // The session is over (expired, revoked or banned): back to login.
    const err = await response.json().catch(() => ({}));
    endSession(err.error);
  }
  return null;
}

/**
 * `fetch` for authenticated API calls. Adds a fresh access token, and on a 401
 * refreshes the token once and retries.
 */
export async function apiFetch(input: string, init: RequestInit = {}): Promise<Response> {
  const send = (token: string | null) => {
    const headers = new Headers(init.headers);
    if (token) headers.set('Authorization', `Bearer ${token}`);
    return fetch(input, { ...init, headers });
  };

  const token = await getValidAccessToken();
  const response = await send(token);
  if (response.status !== 401 || !localStorage.getItem('refresh_token')) return response;

  const fresh = await refreshAccessToken(token ?? undefined);
  return fresh ? send(fresh) : response;
}
