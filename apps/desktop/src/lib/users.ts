import { getAuthHeaders, apiFetch, apiBase } from './api';


export interface UserProfile {
  id: string;
  username: string;
  patron_tier?: string;
  status: string;
  created_at: string;
  avatar_url?: string | null;
  /** This user's nickname in the server the profile was opened from, if any
   *  -- only populated when `fetchUserProfile` was called with a `serverId`. */
  nickname?: string | null;
  badge_emblem?: string | null;
  is_site_owner?: boolean;
  /** Owner-granted, independent of patron_tier -- see `updateUserBetaBadge`. */
  has_beta_badge?: boolean;
}

/**
 * Fetches a user's profile. Pass `serverId` when opening the profile from
 * within a server (e.g. the member roster) to also get this user's
 * nickname there; omit it (e.g. opening from a DM) and `nickname` comes
 * back null.
 */
export async function fetchUserProfile(userId: string, serverId?: string): Promise<UserProfile> {
  const query = serverId ? `?server_id=${encodeURIComponent(serverId)}` : '';
  const response = await apiFetch(`${apiBase()}/api/v1/users/${userId}${query}`, {
    headers: getAuthHeaders(),
  });

  if (!response.ok) {
    const errData = await response.json().catch(() => ({}));
    throw new Error(errData.error || 'Failed to fetch user profile');
  }

  return response.json();
}

export interface PublicUser {
  id: string;
  username: string;
  is_online: boolean;
  status: string;
  patron_tier: string;
  bio?: string | null;
  public_key?: string | null;
  avatar_url?: string | null;
  badge_emblem?: string | null;
  is_site_owner?: boolean;
  has_beta_badge?: boolean;
}

/** The logged-in user's own profile, with a freshly-signed `avatar_url`. */
export async function fetchMyProfile(): Promise<PublicUser> {
  const response = await apiFetch(`${apiBase()}/api/v1/users/me`, {
    headers: getAuthHeaders(),
  });

  if (!response.ok) {
    throw new Error('Failed to fetch your profile');
  }

  return response.json();
}

/** All non-banned users, for pickers like "start a new DM". */
export async function fetchAllUsers(): Promise<PublicUser[]> {
  const response = await apiFetch(`${apiBase()}/api/v1/users`, {
    headers: getAuthHeaders(),
  });

  if (!response.ok) {
    throw new Error('Failed to fetch users');
  }

  return response.json();
}

export const PATRON_TIERS = ['free', 'patron', 'guild', 'enterprise'] as const;
export type PatronTier = (typeof PATRON_TIERS)[number];

/**
 * Self-service patron tier change. There's no payment processor wired up
 * yet (see README's MVP scope) -- this really does let a user pick any
 * tier for themselves with no billing check. It exists for honest testing
 * and for self-hosters who want to badge accounts manually, not as a real
 * paywall; don't read it as proof the app monetizes today.
 */
export async function updateMyPatronTier(tier: PatronTier): Promise<PublicUser> {
  const response = await apiFetch(`${apiBase()}/api/v1/users/me/patron-tier`, {
    method: 'PATCH',
    headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
    body: JSON.stringify({ patron_tier: tier }),
  });

  if (!response.ok) {
    const errData = await response.json().catch(() => ({}));
    throw new Error(errData.error || 'Failed to update patron tier');
  }

  return response.json();
}

/**
 * Sets or clears the caller's own profile picture. Pass the `url` from
 * `uploadFile()` (see `lib/messages.ts`) to set one, or `null` to clear it
 * back to the initial-letter default. The returned `avatar_url` is already
 * signed for display.
 */
export async function updateMyAvatar(avatarUrl: string | null): Promise<PublicUser> {
  const response = await apiFetch(`${apiBase()}/api/v1/users/me/avatar`, {
    method: 'PATCH',
    headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
    body: JSON.stringify({ avatar_url: avatarUrl }),
  });

  if (!response.ok) {
    const errData = await response.json().catch(() => ({}));
    throw new Error(errData.error || 'Failed to update avatar');
  }

  return response.json();
}

/** The 5 emblems a `patron`-tier user may pick from. */
export const PATRON_EMBLEMS = ['crown', 'starlight', 'ember', 'wayfinder', 'laurel'] as const;
/** The 10 emblems a `guild`-tier user may pick from. */
export const GUILD_EMBLEMS = [
  'aegis', 'blade', 'warbrand', 'bastion', 'anchor', 'storm', 'reaper', 'wolf', 'ruby', 'conqueror',
] as const;
/** Selectable only by the site owner. */
export const OWNER_EMBLEM = 'fehu_rune';

/**
 * The emblem ids `patron_tier`/`isSiteOwner` may pick from. Mirrors the
 * server's `crate::badges::allowed_emblems` -- the server re-validates
 * regardless, this is just for building the picker UI.
 */
export function allowedEmblems(patronTier: string, isSiteOwner: boolean): string[] {
  if (isSiteOwner) return [...PATRON_EMBLEMS, ...GUILD_EMBLEMS, OWNER_EMBLEM];
  if (patronTier === 'patron') return [...PATRON_EMBLEMS];
  if (patronTier === 'guild') return [...GUILD_EMBLEMS];
  return [];
}

/**
 * Sets or clears the caller's own badge emblem. `emblemId` must be one of
 * `allowedEmblems(...)` for the caller's own tier, or `null` to clear back
 * to that tier's default emblem.
 */
export async function updateMyBadgeEmblem(emblemId: string | null): Promise<PublicUser> {
  const response = await apiFetch(`${apiBase()}/api/v1/users/me/badge-emblem`, {
    method: 'PATCH',
    headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
    body: JSON.stringify({ badge_emblem: emblemId }),
  });

  if (!response.ok) {
    const errData = await response.json().catch(() => ({}));
    throw new Error(errData.error || 'Failed to update badge emblem');
  }

  return response.json();
}

/**
 * Site-owner-only: grants or revokes the Beta badge on any user, from their
 * profile. Independent of that user's patron tier -- see
 * `routes::users::admin_set_beta_badge` server-side.
 */
export async function setUserBetaBadge(userId: string, hasBetaBadge: boolean): Promise<PublicUser> {
  const response = await apiFetch(`${apiBase()}/api/v1/admin/beta-badge`, {
    method: 'PATCH',
    headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
    body: JSON.stringify({ user_id: userId, has_beta_badge: hasBetaBadge }),
  });

  if (!response.ok) {
    const errData = await response.json().catch(() => ({}));
    throw new Error(errData.error || 'Failed to update the Beta badge');
  }

  return response.json();
}

/** Sets or clears the caller's own nickname in one server. */
export async function setMyNickname(serverId: string, nickname: string | null): Promise<string | null> {
  const response = await apiFetch(`${apiBase()}/api/v1/servers/${serverId}/nickname`, {
    method: 'PATCH',
    headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
    body: JSON.stringify({ nickname }),
  });

  if (!response.ok) {
    const errData = await response.json().catch(() => ({}));
    throw new Error(errData.error || 'Failed to update nickname');
  }

  return (await response.json()).nickname ?? null;
}

/**
 * Admin/owner override: sets or clears another member's nickname in a
 * server. Requires admin or owner rank -- see `require_admin` server-side.
 */
export async function adminSetNickname(serverId: string, userId: string, nickname: string | null): Promise<string | null> {
  const response = await apiFetch(`${apiBase()}/api/v1/servers/${serverId}/members/${userId}/nickname`, {
    method: 'PATCH',
    headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
    body: JSON.stringify({ nickname }),
  });

  if (!response.ok) {
    const errData = await response.json().catch(() => ({}));
    throw new Error(errData.error || 'Failed to update nickname');
  }

  return (await response.json()).nickname ?? null;
}