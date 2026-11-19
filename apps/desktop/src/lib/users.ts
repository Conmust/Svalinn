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