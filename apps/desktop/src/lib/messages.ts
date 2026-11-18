import { getAuthHeaders, apiFetch, apiBase } from './api';


export interface Message {
  id: string;
  channel_id: string;
  user_id: string;
  username: string;
  patron_tier?: string;
  content: string;
  created_at: string;
  is_edited: boolean;
  updated_at: string | null;
  is_locked: boolean;
  locked_by?: string;
  is_pinned?: boolean;
  pinned_by?: string;
  attachment_url?: string | null;
  attachment_filename?: string | null;
  attachment_size?: number | null;
  attachment_mime_type?: string | null;
  is_hidden?: boolean;
  reactions?: Reaction[];
}

export interface Reaction {
  emoji: string;
  count: number;
  user_ids: string[];
}

export interface UploadedFile {
  url: string;
  filename: string;
  size: number;
  mime_type: string;
}

/** Sends a request and returns the JSON body, throwing the server's error message on failure. */
async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const response = await apiFetch(`${apiBase()}${path}`, {
    method,
    headers: body === undefined
      ? getAuthHeaders()
      : { 'Content-Type': 'application/json', ...getAuthHeaders() },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err.error || `Request failed (${response.status})`);
  }
  return response.json();
}

export interface GetMessagesOptions {
  limit?: number;
  before?: string;
}

export async function fetchMessages(channelId: string, options: GetMessagesOptions = {}): Promise<Message[]> {
  const params = new URLSearchParams();
  if (options.limit) params.append('limit', options.limit.toString());
  if (options.before) params.append('before', options.before);

  const response = await apiFetch(`${apiBase()}/api/v1/messages/${channelId}?${params}`, {
    headers: getAuthHeaders(),
  });

  if (!response.ok) throw new Error('Failed to fetch messages');
  return response.json();
}

export async function sendMessage(
  channelId: string,
  content: string,
  attachment?: UploadedFile | null
): Promise<Message> {
  const response = await apiFetch(`${apiBase()}/api/v1/messages`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
    body: JSON.stringify({
      channel_id: channelId,
      content,
      attachment_url: attachment?.url || null,
      attachment_filename: attachment?.filename || null,
      attachment_size: attachment?.size || null,
      attachment_mime_type: attachment?.mime_type || null,
    }),
  });

  if (!response.ok) throw new Error('Failed to send message');
  return response.json();
}

export async function editMessage(messageId: string, content: string): Promise<Message> {
  const response = await apiFetch(`${apiBase()}/api/v1/messages/${messageId}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
    body: JSON.stringify({ content }),
  });

  if (!response.ok) throw new Error('Failed to edit message');
  return response.json();
}

export async function deleteMessage(messageId: string): Promise<void> {
  await request('DELETE', `/api/v1/messages/${messageId}`);
}

export async function hideMessage(messageId: string): Promise<void> {
  await request('POST', `/api/v1/messages/${messageId}/hide`);
}

export async function unhideMessage(messageId: string): Promise<void> {
  await request('DELETE', `/api/v1/messages/${messageId}/hide`);
}

export async function lockMessage(messageId: string): Promise<void> {
  await request('POST', `/api/v1/messages/${messageId}/lock`);
}

export async function unlockMessage(messageId: string): Promise<void> {
  await request('DELETE', `/api/v1/messages/${messageId}/lock`);
}

export async function pinMessage(messageId: string): Promise<void> {
  await request('POST', `/api/v1/messages/${messageId}/pin`);
}

export async function unpinMessage(messageId: string): Promise<void> {
  await request('DELETE', `/api/v1/messages/${messageId}/pin`);
}

export async function fetchPinnedMessages(channelId: string): Promise<Message[]> {
  const response = await apiFetch(`${apiBase()}/api/v1/messages/${channelId}/pinned`, {
    headers: getAuthHeaders(),
  });

  if (!response.ok) throw new Error('Failed to fetch pinned messages');
  return response.json();
}

export async function bulkDeleteMessages(messageIds: string[]): Promise<{
  deleted_count: number;
  skipped_count: number;
  deleted_ids: string[];
  skipped_ids: string[];
}> {
  const response = await apiFetch(`${apiBase()}/api/v1/messages/bulk-delete`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
    body: JSON.stringify({ message_ids: messageIds }),
  });

  if (!response.ok) {
    const errData = await response.json().catch(() => ({}));
    throw new Error(errData.error || 'Failed to bulk delete messages');
  }

  return response.json();
}

export async function fetchReactions(messageId: string): Promise<Reaction[]> {
  const response = await apiFetch(`${apiBase()}/api/v1/messages/${messageId}/reactions`, {
    headers: getAuthHeaders(),
  });

  if (!response.ok) throw new Error('Failed to fetch reactions');
  return response.json();
}

/** Returns the message's full, updated reaction list. */
export async function addReaction(messageId: string, emoji: string): Promise<Reaction[]> {
  const res = await request<{ reactions: Reaction[] }>('POST', `/api/v1/messages/${messageId}/reactions`, { emoji });
  return res.reactions;
}

/** Returns the message's full, updated reaction list. */
export async function removeReaction(messageId: string, emoji: string): Promise<Reaction[]> {
  const res = await request<{ reactions: Reaction[] }>(
    'DELETE',
    `/api/v1/messages/${messageId}/reactions/${encodeURIComponent(emoji)}`,
  );
  return res.reactions;
}

export async function searchMessages(options: {
  q: string;
  channelId?: string;
  conversationId?: string;
  limit?: number;
}): Promise<Message[]> {
  const params = new URLSearchParams();
  params.append('q', options.q);
  if (options.channelId) params.append('channel_id', options.channelId);
  if (options.conversationId) params.append('conversation_id', options.conversationId);
  if (options.limit) params.append('limit', options.limit.toString());

  const response = await apiFetch(`${apiBase()}/api/v1/search?${params}`, {
    headers: getAuthHeaders(),
  });

  if (!response.ok) {
    const errData = await response.json().catch(() => ({}));
    throw new Error(errData.error || 'Search failed');
  }

  return response.json();
}

export async function banUser(userId: string, reason?: string): Promise<{ success: boolean; messages_deleted: number }> {
  const response = await apiFetch(`${apiBase()}/api/v1/moderation/ban/${userId}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
    body: JSON.stringify({ reason }),
  });

  if (!response.ok) {
    const errData = await response.json().catch(() => ({}));
    throw new Error(errData.error || 'Failed to ban user');
  }

  return response.json();
}

export async function uploadFile(file: File): Promise<UploadedFile> {
  const formData = new FormData();
  formData.append('file', file);

  const response = await apiFetch(`${apiBase()}/api/v1/upload`, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: formData,
  });

  if (!response.ok) {
    const errData = await response.json().catch(() => ({}));
    throw new Error(errData.error || 'Upload failed');
  }

  return response.json();
}

export async function markChannelRead(channelId: string, messageId: string): Promise<void> {
  const response = await apiFetch(`${apiBase()}/api/v1/messages/${channelId}/read`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
    body: JSON.stringify({ message_id: messageId }),
  });

  if (!response.ok) throw new Error('Failed to mark as read');
}

export async function markConversationRead(conversationId: string, messageId: string): Promise<void> {
  const response = await apiFetch(`${apiBase()}/api/v1/conversations/${conversationId}/read`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
    body: JSON.stringify({ message_id: messageId }),
  });

  if (!response.ok) throw new Error('Failed to mark as read');
}

export async function fetchHiddenMessages(): Promise<Message[]> {
  const response = await apiFetch(`${apiBase()}/api/v1/messages/hidden`, {
    method: 'GET',
    headers: getAuthHeaders(), // This must return { 'Authorization': 'Bearer <token>' }
  });

  if (!response.ok) {
    const errData = await response.json().catch(() => ({}));
    throw new Error(errData.error || `Failed to fetch hidden messages (${response.status})`);
  }
  
  return response.json();
}