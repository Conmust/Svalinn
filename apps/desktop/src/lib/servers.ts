import { getAuthHeaders, apiFetch, apiBase, endSession } from './api';


export interface Server {
  id: string;
  name: string;
  icon: string | null;
  owner_id: string;
  created_at: string;
}

export interface Channel {
  id: string;
  name: string;
  server_id: string;
  channel_type: string;
  created_at: string;
}

// Fetch all servers the current user is a member of
export async function fetchUserServers(): Promise<Server[]> {
  const response = await apiFetch(`${apiBase()}/api/v1/servers`, {
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
    const error = await response.json().catch(() => ({ error: 'Failed to fetch servers' }));
    throw new Error(error.error || 'Failed to fetch servers');
  }

  return response.json();
}

// Fetch all channels for a specific server
export async function fetchServerChannels(serverId: string): Promise<Channel[]> {
  const response = await apiFetch(`${apiBase()}/api/v1/servers/${serverId}/channels`);

  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: 'Failed to fetch channels' }));
    throw new Error(error.error || 'Failed to fetch channels');
  }

  return response.json();
}

// Create a new server
export async function createServer(name: string, icon?: string): Promise<Server> {
  const response = await apiFetch(`${apiBase()}/api/v1/servers`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...getAuthHeaders(),
    },
    body: JSON.stringify({ name, icon }),
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
    const error = await response.json().catch(() => ({ error: 'Failed to create server' }));
    throw new Error(error.error || 'Failed to create server');
  }

  return response.json();
}

// Create a new channel in a server
export async function createChannel(
  serverId: string,
  name: string,
  channelType: string = 'text'
): Promise<Channel> {
  const response = await apiFetch(`${apiBase()}/api/v1/servers/${serverId}/channels`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...getAuthHeaders(),
    },
    body: JSON.stringify({ name, channel_type: channelType }),
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
    const error = await response.json().catch(() => ({ error: 'Failed to create channel' }));
    throw new Error(error.error || 'Failed to create channel');
  }

  return response.json();
}