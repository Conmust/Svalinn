import { getAuthHeaders } from './api';

const API_BASE = 'http://localhost:3001';

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
  const response = await fetch(`${API_BASE}/api/v1/servers`, {
    headers: getAuthHeaders(),
  });

  if (response.status === 401) {
    localStorage.removeItem('svalinn_token');
    localStorage.removeItem('svalinn_user');
    window.location.reload();
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
  const response = await fetch(`${API_BASE}/api/v1/servers/${serverId}/channels`);

  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: 'Failed to fetch channels' }));
    throw new Error(error.error || 'Failed to fetch channels');
  }

  return response.json();
}

// Create a new server
export async function createServer(name: string, icon?: string): Promise<Server> {
  const response = await fetch(`${API_BASE}/api/v1/servers`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...getAuthHeaders(),
    },
    body: JSON.stringify({ name, icon }),
  });

  if (response.status === 401) {
    localStorage.removeItem('svalinn_token');
    localStorage.removeItem('svalinn_user');
    window.location.reload();
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
  const response = await fetch(`${API_BASE}/api/v1/servers/${serverId}/channels`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...getAuthHeaders(),
    },
    body: JSON.stringify({ name, channel_type: channelType }),
  });

  if (response.status === 401) {
    localStorage.removeItem('svalinn_token');
    localStorage.removeItem('svalinn_user');
    window.location.reload();
    throw new Error('Session expired');
  }

  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: 'Failed to create channel' }));
    throw new Error(error.error || 'Failed to create channel');
  }

  return response.json();
}