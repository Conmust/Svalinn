import { getAuthHeaders, apiFetch, apiBase } from './api';
import { type UploadedFile } from './messages';
import { withTimeout } from './timeout';

// Bounds how long a conversation-messages fetch or send is willing to wait,
// consistent with the other E2EE-adjacent network calls in `devices.ts`/
// `recovery.ts` (which use 10s for comparably-sized device/participant-
// device lookups) -- nothing in this subsystem should be able to hang the
// UI indefinitely (see `DMChatArea.svelte`'s "Loading messages..."/sending
// states, which otherwise had no bound at all). Message history pages can
// carry up to `PAGE_SIZE` full message bodies (plus attachment metadata)
// rather than the small, fixed-shape JSON a device lookup returns, so this
// uses a somewhat longer bound than that 10s to leave headroom for a
// slower connection to still succeed instead of being timed out for simply
// fetching more data.
const CONVERSATION_NETWORK_TIMEOUT_MS = 15_000;


export interface Conversation {
  id: string;
  created_at: string;
  participant_id: string;
  participant_username: string;
  participant_is_online: boolean;
  participant_status: string;
  participant_patron_tier: string;
  /** Base64-encoded X25519 public key for the other participant's device,
   * if they've set one up. Missing/null means they haven't -- sending must
   * be blocked client-side rather than falling back to plaintext. */
  participant_public_key?: string | null;
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

/** One recipient device's ciphertext within a fan-out (new multi-device
 * model) message -- a `message_recipients` row. `sender_public_key` is the
 * SENDING device's public key (not this device's), which is what
 * `decryptFromSender` needs alongside this device's own private key. */
export interface MessageRecipientEntry {
  device_id: string;
  ciphertext: string;
  nonce: string;
  sender_public_key: string;
}

/** A direct message, as returned by the conversation message endpoints. */
export interface ConversationMessage {
  id: string;
  conversation_id: string;
  user_id: string;
  username: string;
  /** Plaintext, or legacy (single-device-era) ciphertext. `null` for a
   * message sent through the new per-device fan-out model -- its
   * ciphertext is in `recipients` instead. This is the discriminator: a
   * message with `is_encrypted` true and `content` null is a fan-out
   * message; `is_encrypted` true with `content` set is a legacy message. */
  content: string | null;
  attachment_url?: string | null;
  attachment_filename?: string | null;
  attachment_size?: number | null;
  attachment_mime_type?: string | null;
  is_edited: boolean;
  /** Whether this message is encrypted, either the legacy single-device
   * way or the new fan-out way. False for all pre-E2EE history. */
  is_encrypted: boolean;
  /** Base64-encoded nonce for the legacy `content` ciphertext. Only
   * present for a legacy single-device-era encrypted message. */
  nonce?: string | null;
  /** Per-device ciphertext for a fan-out message. From the history-fetch
   * endpoint, at most one entry -- this device's own, if any ("sent before
   * this device was added" when empty). From a WebSocket
   * `new_direct_message` event, every recipient device's entry for both
   * participants -- pick out the one matching this device's own id. */
  recipients?: MessageRecipientEntry[];
  created_at: string;
}

export interface GetConversationMessagesOptions {
  limit?: number;
  before?: string;
  /** This device's own id (from `ensureDeviceKeypair`/`getMyDeviceId`).
   * Required to get back any fan-out message's ciphertext at all --
   * omitting it is indistinguishable, server-side, from an unrecognized
   * device id, so every such message comes back with no ciphertext. */
  deviceId?: string | null;
}

export async function fetchConversationMessages(
  conversationId: string,
  options: GetConversationMessagesOptions = {}
): Promise<ConversationMessage[]> {
  const params = new URLSearchParams();
  if (options.limit) params.append('limit', options.limit.toString());
  if (options.before) params.append('before', options.before);
  if (options.deviceId) params.append('device_id', options.deviceId);

  const response = await withTimeout(
    apiFetch(`${apiBase()}/api/v1/conversations/${conversationId}/messages?${params}`, {
      headers: getAuthHeaders(),
    }),
    CONVERSATION_NETWORK_TIMEOUT_MS,
    'Timed out loading messages.'
  );

  if (!response.ok) {
    throw new Error('Failed to fetch messages');
  }

  return response.json();
}

export interface SendDirectMessageOptions {
  /** Legacy single-device path: set when `content` is base64 ciphertext
   * rather than plaintext. Ignored (and should not be set) when
   * `encryptedFor` is used instead. */
  isEncrypted?: boolean;
  /** Legacy single-device path: base64-encoded nonce; required when
   * `isEncrypted` is true. */
  nonce?: string;
  /** New per-device fan-out path: one ciphertext per recipient device.
   * When set (and non-empty), this takes over the whole send -- `content`
   * is ignored and the message is stored with no shared ciphertext at all,
   * only these per-device entries. */
  encryptedFor?: Array<{ deviceId: string; ciphertext: string; nonce: string }>;
  /** Required alongside `encryptedFor`: the id of THIS device (the one
   * that did the encrypting), so the server can resolve and record its
   * public key on every `message_recipients` row -- recipients need the
   * sender's public key to decrypt, not their own. */
  senderDeviceId?: string;
}

/** Thrown by `sendDirectMessage` on a non-OK response. Carries the HTTP
 * status and the server's own `{ "error": ... }` message (when the body
 * parses as that) so callers can tell a stale-device-list rejection (400,
 * naming a bad `device_id` -- see `send_fanout_message`'s validation in
 * `conversations.rs`) apart from any other failure, instead of only ever
 * seeing a generic "network error". */
export class SendDirectMessageError extends Error {
  status: number;
  serverMessage: string | null;
  constructor(status: number, serverMessage: string | null) {
    super(serverMessage ?? 'Failed to send direct message');
    this.name = 'SendDirectMessageError';
    this.status = status;
    this.serverMessage = serverMessage;
  }
}

export async function sendDirectMessage(
  conversationId: string,
  content: string | null,
  attachment?: UploadedFile | null,
  options: SendDirectMessageOptions = {}
): Promise<ConversationMessage> {
  const usingFanout = !!options.encryptedFor && options.encryptedFor.length > 0;

  const response = await withTimeout(
    apiFetch(`${apiBase()}/api/v1/conversations/${conversationId}/messages`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
      body: JSON.stringify({
        conversation_id: conversationId,
        content: usingFanout ? null : content,
        attachment_url: attachment?.url || null,
        attachment_filename: attachment?.filename || null,
        attachment_size: attachment?.size || null,
        attachment_mime_type: attachment?.mime_type || null,
        is_encrypted: usingFanout ? false : (options.isEncrypted ?? false),
        nonce: usingFanout ? null : (options.nonce ?? null),
        encrypted_for: usingFanout
          ? options.encryptedFor!.map((r) => ({ device_id: r.deviceId, ciphertext: r.ciphertext, nonce: r.nonce }))
          : null,
        sender_device_id: usingFanout ? options.senderDeviceId ?? null : null,
      }),
    }),
    CONVERSATION_NETWORK_TIMEOUT_MS,
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
    throw new SendDirectMessageError(response.status, serverMessage);
  }
  return response.json();
}