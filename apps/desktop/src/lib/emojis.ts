import { getAuthHeaders } from './api';
const API_BASE = 'http://localhost:3001';

export interface CustomEmoji {
  id: string;
  server_id: string;
  name: string;
  url: string;
  created_by: string;
  created_at: string;
}

export async function fetchServerEmojis(serverId: string): Promise<CustomEmoji[]> {
  const res = await fetch(`${API_BASE}/api/v1/servers/${serverId}/emojis`, { headers: getAuthHeaders() });
  if (!res.ok) throw new Error('Failed to fetch emojis');
  return res.json();
}

export async function uploadEmoji(serverId: string, name: string, file: File): Promise<CustomEmoji> {
  const formData = new FormData();
  formData.append('name', name);
  formData.append('file', file);

  const res = await fetch(`${API_BASE}/api/v1/servers/${serverId}/emojis`, {
    method: 'POST',
    headers: { 'Authorization': getAuthHeaders()['Authorization'] }, // Don't set Content-Type, browser does it for FormData
    body: formData,
  });
  if (!res.ok) throw new Error('Failed to upload emoji');
  return res.json();
}

export async function deleteEmoji(serverId: string, emojiId: string): Promise<void> {
  const res = await fetch(`${API_BASE}/api/v1/servers/${serverId}/emojis/${emojiId}`, {
    method: 'DELETE',
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to delete emoji');
}