import { getAuthHeaders, apiFetch } from './api';

const API_BASE = 'http://localhost:3001';

export interface Member {
  id: string;
  username: string;
  display_name: string | null;
  avatar_url: string | null;
  status: string;
}

export async function fetchServerMembers(serverId: string): Promise<Member[]> {
  const response = await apiFetch(`${API_BASE}/api/v1/servers/${serverId}/members`, {
    headers: getAuthHeaders(),
  });

  if (response.status === 401) {
    localStorage.removeItem('svalinn_token');
    localStorage.removeItem('svalinn_user');
    window.location.reload();
    throw new Error('Session expired');
  }

  if (!response.ok) {
    throw new Error('Failed to fetch members');
  }

  return response.json();
}