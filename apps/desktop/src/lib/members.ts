import { getAuthHeaders, apiFetch, apiBase, endSession } from './api';


export interface Member {
  id: string;
  username: string;
  display_name: string | null;
  avatar_url: string | null;
  status: string;
}

export async function fetchServerMembers(serverId: string): Promise<Member[]> {
  const response = await apiFetch(`${apiBase()}/api/v1/servers/${serverId}/members`, {
    headers: getAuthHeaders(),
  });

  if (response.status === 401) {
    // `svalinn_token`/`svalinn_user` were never this app's real session
    // storage keys (see `api.ts`'s `token`/`refresh_token`/`user`), so
    // clearing them was a no-op -- the actual stale token and user stayed
    // in place and this just reloaded straight back into the same broken
    // session (an infinite reload loop whenever `apiFetch` had no refresh
    // token to retry with, since neither `token` nor `user` ever actually
    // got cleared). `endSession()` is the real version of what this was
    // trying to do: it clears the keys this app actually uses.
    endSession('Session expired');
    throw new Error('Session expired');
  }

  if (!response.ok) {
    throw new Error('Failed to fetch members');
  }

  return response.json();
}