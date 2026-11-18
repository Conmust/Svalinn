import { getAuthHeaders } from './api';
import { type Message, type UploadedFile } from './messages';

const API_BASE = 'http://localhost:3001';

export interface Conversation {
  id: string;
  created_at: string;
  participant_id: string;
  participant_username: string;
  participant_is_online: boolean;
}

export async function fetchUserConversations(): Promise<Conversation[]> {
  const response = await fetch(`${API_BASE}/api/v1/conversations`, {
    headers: getAuthHeaders(),
  });

  if (!response.ok) {
    throw new Error('Failed to fetch conversations');
  }

  return response.json();
}

export async function createConversation(participantId: string): Promise<Conversation> {
  const response = await fetch(`${API_BASE}/api/v1/conversations`, {
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

export async function fetchConversationMessages(conversationId: string): Promise<any[]> {
  const response = await fetch(`${API_BASE}/api/v1/conversations/${conversationId}/messages`, {
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
): Promise<Message> {
  const response = await fetch(`${API_BASE}/api/v1/conversations/${conversationId}/messages`, {
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