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