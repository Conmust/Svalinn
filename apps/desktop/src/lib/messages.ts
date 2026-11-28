import { getAuthHeaders, apiFetch, apiBase } from './api';
import { withTimeout } from './timeout';

// Mirrors `conversations.ts`'s identically-named constant: message history
// pages can carry a lot of data (and, for a send, one ciphertext per
// recipient device), so this gets more headroom than a small fixed-shape
// device lookup.
const CHANNEL_MESSAGE_NETWORK_TIMEOUT_MS = 15_000;

/** One recipient device's ciphertext within a channel message's fan-out --
 * a `message_recipients` row. `sender_public_key` is the SENDING device's
 * public key, which `decryptFromSender` needs alongside this device's own
 * private key. Mirrors `conversations.ts`'s `MessageRecipientEntry`. */
export interface MessageRecipientEntry {
  device_id: string;
  ciphertext: string;
  nonce: string;
  sender_public_key: string;
  attachment_key_ciphertext?: string | null;
  attachment_key_nonce?: string | null;
  /** This entry's Double Ratchet envelope metadata (`ratchet.ts`'s
   * `RatchetEnvelope`, minus `ciphertext`/`nonce`, as a JSON string), when
   * it was encrypted via `ratchet.ts` rather than the legacy stateless
   * per-device path (`crypto.ts`). `null`/absent for a legacy entry. */
  ratchet_header_json?: string | null;
  /** Same idea as `ratchet_header_json` above, but for the ATTACHMENT key:
   * when present, `attachment_key_ciphertext`/`attachment_key_nonce` hold
   * the ratchet's own envelope fields (the file key, base64-encoded,
   * passed through `ratchet.ts`'s `encryptMessage` like ordinary message
   * text) rather than the legacy static `crypto_box_easy` wrap. See
   * migration 0044. */
  attachment_key_ratchet_header_json?: string | null;
}

export interface Message {
  id: string;
  channel_id: string;
  user_id: string;
  username: string;
  /** This author's nickname in this message's server, if they have one set. */
  nickname?: string | null;
  avatar_url?: string | null;
  patron_tier?: string;
  /** Plaintext content, or `null` for a per-device fan-out encrypted
   * message -- its ciphertext is in `recipients` instead. Channel
   * messages have no legacy single-device-era encrypted path: a message
   * with `is_encrypted` true always has `content` null. */
  content: string | null;
  created_at: string;
  is_edited: boolean;
  updated_at: string | null;
  is_locked: boolean;
  locked_by?: string;
  is_pinned?: boolean;
  pinned_by?: string;
  /** A readable copy of this message's content, present only when a
   * moderator chose to reveal it while pinned (see `setPinVisibility`) --
   * lets a member with no `recipients` entry for this message (e.g. they
   * joined the channel after it was sent) still read it. `null`/absent
   * for every ordinary message, and for a pinned one nobody has revealed. */
  pin_plaintext_content?: string | null;
  /** Client-only, never sent by the server: set on a message whose
   * `content` above came from `pin_plaintext_content` because this
   * device had no other way to read it (see ChatArea's
   * `toDisplayMessage`), so the UI can mark it as a moderator reveal
   * rather than this device's own decryption. */
  revealed_fallback?: boolean;
  attachment_url?: string | null;
  attachment_filename?: string | null;
  attachment_size?: number | null;
  attachment_mime_type?: string | null;
  /** Base64 `crypto_secretbox` nonce for the encrypted attachment blob at
   * `attachment_url`. `null`/absent when there's no attachment, or it's
   * plaintext pre-E2EE history. */
  attachment_nonce?: string | null;
  /** Whether this message went through the per-device fan-out send path.
   * False for all history that predates server-level E2EE. */
  is_encrypted: boolean;
  /** Unused for channel messages -- always null/absent. */
  nonce?: string | null;
  /** Per-device ciphertext for a fan-out message. From the history-fetch
   * endpoint, at most one entry -- this device's own, if any ("sent
   * before this device was added" when empty). From a WebSocket
   * `new_message` event, every recipient device's entry. */
  recipients?: MessageRecipientEntry[];
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

export interface GetChannelMessagesOptions {
  limit?: number;
  before?: string;
  /** This device's own id (from `ensureDeviceKeypair`/`getMyDeviceId`).
   * Required to get back any fan-out message's ciphertext at all --
   * omitting it is indistinguishable, server-side, from an unrecognized
   * device id, so every such message comes back with no ciphertext. */
  deviceId?: string | null;
}

/** GET /api/v1/channels/:channel_id/messages?before=&limit=&device_id= */
export async function fetchChannelMessages(
  channelId: string,
  options: GetChannelMessagesOptions = {}
): Promise<Message[]> {
  const params = new URLSearchParams();
  if (options.limit) params.append('limit', options.limit.toString());
  if (options.before) params.append('before', options.before);
  if (options.deviceId) params.append('device_id', options.deviceId);

  const response = await withTimeout(
    apiFetch(`${apiBase()}/api/v1/channels/${channelId}/messages?${params}`, {
      headers: getAuthHeaders(),
    }),
    CHANNEL_MESSAGE_NETWORK_TIMEOUT_MS,
    'Timed out loading messages.'
  );

  if (!response.ok) throw new Error('Failed to fetch messages');
  return response.json();
}

export interface SendChannelMessageOptions {
  /** One ciphertext per recipient device -- must cover EXACTLY every
   * currently-registered device of every current member of this channel's
   * server, including the sender's own sending device. Channel messages
   * have no plaintext or legacy single-device send path: this is always
   * required and non-empty. */
  encryptedFor: Array<{
    deviceId: string;
    ciphertext: string;
    nonce: string;
    /** This recipient device's wrapped copy of the attachment's symmetric
     * key (see `lib/crypto.ts`'s `wrapFileKey`). Required for every entry
     * when `attachmentNonce` is set; must be omitted otherwise. */
    attachmentKeyCiphertext?: string;
    attachmentKeyNonce?: string;
    /** This entry's Double Ratchet envelope metadata, when it was
     * encrypted via `ratchet.ts`'s `encryptMessage` rather than
     * `crypto.ts`'s `encryptForRecipient` -- see `MessageRecipientEntry`. */
    ratchetHeaderJson?: string;
    /** Same idea as `ratchetHeaderJson` above, but for the attachment key
     * -- set when `attachmentKeyCiphertext`/`attachmentKeyNonce` are the
     * ratchet's own envelope fields rather than the legacy static wrap.
     * See `MessageRecipientEntry`. */
    attachmentKeyRatchetHeaderJson?: string;
  }>;
  /** The id of THIS device (the one that did the encrypting), so the
   * server can resolve and record its public key on every
   * `message_recipients` row. */
  senderDeviceId: string;
  /** Base64 `crypto_secretbox` nonce for the encrypted attachment blob
   * passed as `attachment` below. Only meaningful alongside an
   * `attachment`. */
  attachmentNonce?: string;
}

/** Thrown by `sendChannelMessage` on a non-OK response. Carries the HTTP
 * status and the server's own `{ "error": ... }` message so callers can
 * tell a stale-device-list rejection (400, naming a bad `device_id`) apart
 * from any other failure. Mirrors `conversations.ts`'s
 * `SendDirectMessageError`. */
export class SendChannelMessageError extends Error {
  status: number;
  serverMessage: string | null;
  constructor(status: number, serverMessage: string | null) {
    super(serverMessage ?? 'Failed to send message');
    this.name = 'SendChannelMessageError';
    this.status = status;
    this.serverMessage = serverMessage;
  }
}

/** POST /api/v1/channels/:channel_id/messages -- always encrypted; see
 * `SendChannelMessageOptions`. */
export async function sendChannelMessage(
  channelId: string,
  attachment: UploadedFile | null,
  options: SendChannelMessageOptions
): Promise<Message> {
  const response = await withTimeout(
    apiFetch(`${apiBase()}/api/v1/channels/${channelId}/messages`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
      body: JSON.stringify({
        attachment_url: attachment?.url || null,
        attachment_filename: attachment?.filename || null,
        attachment_size: attachment?.size || null,
        attachment_mime_type: attachment?.mime_type || null,
        attachment_nonce: options.attachmentNonce ?? null,
        encrypted_for: options.encryptedFor.map((r) => ({
          device_id: r.deviceId,
          ciphertext: r.ciphertext,
          nonce: r.nonce,
          attachment_key_ciphertext: r.attachmentKeyCiphertext ?? null,
          attachment_key_nonce: r.attachmentKeyNonce ?? null,
          ratchet_header_json: r.ratchetHeaderJson ?? null,
          attachment_key_ratchet_header_json: r.attachmentKeyRatchetHeaderJson ?? null,
        })),
        sender_device_id: options.senderDeviceId,
      }),
    }),
    CHANNEL_MESSAGE_NETWORK_TIMEOUT_MS,
    'Timed out sending message.'
  );

  if (!response.ok) {
    let serverMessage: string | null = null;
    try {
      const body = await response.json();
      if (body && typeof body.error === 'string') serverMessage = body.error;
    } catch {
      // Body wasn't JSON (or was empty) -- fall back to no server message.
    }
    throw new SendChannelMessageError(response.status, serverMessage);
  }
  return response.json();
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

/**
 * Pins a message. `revealPlaintext`, if given, is this device's own
 * already-decrypted copy of the message's content -- passing it also
 * stores a server-readable copy (see `setPinVisibility`'s doc comment for
 * what that trade-off actually means) in the same request, so a member who
 * joins the channel later can still read a pinned announcement they'd
 * otherwise have no decryption key for. Omit it to pin without that
 * trade-off, which is always safe to do for a plaintext (non-encrypted)
 * message, since it's already readable to everyone regardless.
 */
export async function pinMessage(messageId: string, revealPlaintext?: string): Promise<void> {
  await request('POST', `/api/v1/messages/${messageId}/pin`, { reveal_plaintext: revealPlaintext ?? null });
}

export async function unpinMessage(messageId: string): Promise<void> {
  await request('DELETE', `/api/v1/messages/${messageId}/pin`);
}

/**
 * Toggles whether a currently-pinned, encrypted message also has a
 * server-readable plaintext copy, independently of pinning/unpinning it.
 * Pass this device's own decrypted copy of the message to reveal (or
 * replace) it, or `null` to revoke a previous reveal. See
 * `pinMessage`'s doc comment and the server's `set_pin_visibility` for
 * what revealing actually means: the server (and so anyone who can view
 * the channel) can read `plaintextContent` from that point on, for as
 * long as the message stays pinned.
 */
export async function setPinVisibility(messageId: string, plaintextContent: string | null): Promise<void> {
  await request('PUT', `/api/v1/messages/${messageId}/pin-visibility`, { plaintext_content: plaintextContent });
}

export async function fetchPinnedMessages(channelId: string): Promise<Message[]> {
  const response = await apiFetch(`${apiBase()}/api/v1/channels/${channelId}/pinned`, {
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