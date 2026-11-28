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

export interface ServerUsage {
  message_count: number;
  message_cap: number;
  pinned_count: number;
  pin_cap: number;
  unread_backlog_count: number;
  unread_backlog_cap: number;
  attachment_bytes_used: number;
  attachment_quota_bytes: number;
}

/** Channel slowmode is capped server-side at 6 hours (see migration
 * 0052_channel_slowmode.sql's CHECK constraint and `MAX_SLOWMODE_SECONDS`
 * in routes/channels.rs) -- kept in sync here so the client can reject an
 * out-of-range value before round-tripping to the server at all. */
export const MAX_SLOWMODE_SECONDS = 21_600;

/** `null` when `seconds` is a valid slowmode value, otherwise the message
 * to show the person instead of submitting it. */
export function validateSlowmodeSeconds(seconds: number): string | null {
  if (!Number.isInteger(seconds) || seconds < 0 || seconds > MAX_SLOWMODE_SECONDS) {
    return `Must be between 0 and ${MAX_SLOWMODE_SECONDS} seconds.`;
  }
  return null;
}

/** Merges a partial update (from a `channel_updated` broadcast, say) into
 * whichever entry in `channels` it names, leaving every other field of
 * that entry untouched. Generic over the exact channel shape so a
 * narrower broadcast payload (e.g. just `{id, slowmode_seconds}`, with no
 * `name`) never blanks out fields it simply didn't mention -- which a
 * merge that assumed a fixed field (like `name`) used to do. */
export function mergeChannelUpdate<T extends { id: string }>(
  channels: T[],
  update: Partial<T> & { id: string }
): T[] {
  return channels.map(c => (c.id === update.id ? { ...c, ...update } : c));
}

/** Formats a byte count as a human-readable size (B/KB/MB/GB/TB), rounded
 * to one decimal place from KB upward. */
export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(1)} ${units[unit]}`;
}

/** Green under 75% of a cap, amber from there up to the cap, red at or
 * past it -- used to color a usage bar (messages, pins, unread backlog,
 * attachment storage) by how close it is to its limit. A non-positive
 * cap (shouldn't happen, but better than dividing by zero) reads as
 * "fine" rather than a false alarm. */
export function usageColor(used: number, cap: number): string {
  if (cap <= 0) return '#00ff00';
  const fraction = used / cap;
  if (fraction >= 1) return '#ff0000';
  if (fraction >= 0.75) return '#ffaa00';
  return '#00ff00';
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