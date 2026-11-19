import { getAuthHeaders, apiFetch, apiBase } from './api';


export interface UserProfile {
  id: string;
  username: string;
  patron_tier?: string;
  status: string;
  created_at: string;
}

export async function fetchUserProfile(userId: string): Promise<UserProfile> {
  const response = await apiFetch(`${apiBase()}/api/v1/users/${userId}`, {
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