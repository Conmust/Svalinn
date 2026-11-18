import { getAuthHeaders, apiFetch, apiBase } from './api';
import { type UploadedFile } from './messages';


export interface Conversation {
  id: string;
  created_at: string;
  participant_id: string;
  participant_username: string;
  participant_is_online: boolean;
  participant_status: string;
  participant_patron_tier: string;
  has_unread: boolean;
}

export async function fetchUserConversations(): Promise<Conversation[]> {
  const response = await apiFetch(`${apiBase()}/api/v1/conversations`, {
    headers: getAuthHeaders(),
  });

  if (!response.ok) {
    throw new Error('Failed to fetch conversations');
  }

  return response.json();
}

export async function createConversation(participantId: string): Promise<Conversation> {
  const response = await apiFetch(`${apiBase()}/api/v1/conversations`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...getAuthHeaders(),
    },
    body: JSON.stringify({ participant_id: participantId }),
  });

  if (!response.ok) {
    throw new Error('Failed to create conversation');
  }

  return response.json();
}

/** A direct message, as returned by the conversation message endpoints. */
export interface ConversationMessage {
  id: string;
  conversation_id: string;
  user_id: string;
  username: string;
  content: string;
  attachment_url?: string | null;
  attachment_filename?: string | null;
  attachment_size?: number | null;
  attachment_mime_type?: string | null;
  is_edited: boolean;
  created_at: string;
}

export interface GetConversationMessagesOptions {
  limit?: number;
  before?: string;
}

export async function fetchConversationMessages(
  conversationId: string,
  options: GetConversationMessagesOptions = {}
): Promise<ConversationMessage[]> {
  const params = new URLSearchParams();
  if (options.limit) params.append('limit', options.limit.toString());
  if (options.before) params.append('before', options.before);

  const response = await apiFetch(`${apiBase()}/api/v1/conversations/${conversationId}/messages?${params}`, {
    headers: getAuthHeaders(),
  });

  if (!response.ok) {
    throw new Error('Failed to fetch messages');
  }

  return response.json();
}

export async function sendDirectMessage(
  conversationId: string,
  content: string,
  attachment?: UploadedFile | null
): Promise<ConversationMessage> {
  const response = await apiFetch(`${apiBase()}/api/v1/conversations/${conversationId}/messages`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
    body: JSON.stringify({
      conversation_id: conversationId,
      content,
      attachment_url: attachment?.url || null,
      attachment_filename: attachment?.filename || null,
      attachment_size: attachment?.size || null,
      attachment_mime_type: attachment?.mime_type || null,
    }),
  });

  if (!response.ok) throw new Error('Failed to send direct message');
  return response.json();
}