<script lang="ts">
  import { onMount, onDestroy, createEventDispatcher, tick } from 'svelte';
  import { getAuthHeaders, apiFetch, apiBase } from '../lib/api';
  import { wsClient } from '../lib/websocket';
  import MessageItem from './MessageItem.svelte';
  import InlineEmojiPicker from './InlineEmojiPicker.svelte';
  import ConfirmModal from './ConfirmModal.svelte';
  import {
    type Message,
    type MessageRecipientEntry,
    deleteMessage, hideMessage, unhideMessage, lockMessage, unlockMessage,
    pinMessage, unpinMessage, setPinVisibility, fetchPinnedMessages, addReaction, removeReaction,
    fetchChannelMessages, sendChannelMessage, SendChannelMessageError,
    uploadFile,
  } from '../lib/messages';
  import {
    encryptForRecipient,
    decryptFromSender,
    encryptFileForFanout,
    wrapFileKey,
    unwrapFileKey,
    decryptFileBytes,
    CryptoLibraryError,
    DeviceSetupError,
  } from '../lib/crypto';
  import { activeDeviceKeypair, deviceEncryptionReady } from '../lib/recovery';
  import { fetchChannelMemberDevices, type ParticipantDevice } from '../lib/devices';
  import { fileUrl } from '../lib/api';
  import { withTimeout, TimeoutError } from '../lib/timeout';
  import { encryptMessage, decryptMessage, RatchetNotSupportedError, b64, fromB64, type RatchetEnvelope } from '../lib/ratchet';
  import { getCachedPlaintext, cachePlaintext, deleteCachedPlaintext } from '../lib/message-history';
  import { fetchServerMembers, type Member } from '../lib/members';
  import { extractMentionedUsernames } from '../lib/mentions';
  import { notifyTypingInChannel, TypingTracker } from '../lib/typing';
  import { notifyNewMessage } from '../lib/notifications';

  // --- Encryption error boundary -------------------------------------------
  // Mirrors `DMChatArea.svelte`'s identically-named helper: a broken
  // libsodium load, a broken device registration, and a plain network
  // timeout are reported distinctly, instead of a real bug quietly reading
  // the same as "not set up yet".
  function describeCryptoError(e: unknown): string {
    if (e instanceof CryptoLibraryError) {
      return 'Encrypted messaging is currently unavailable: the encryption library failed to load.';
    }
    if (e instanceof DeviceSetupError) {
      return `Encrypted messaging is currently unavailable: ${e.message}`;
    }
    if (e instanceof TimeoutError) {
      return 'Encrypted messaging is currently unavailable: the server did not respond in time.';
    }
    return 'Encrypted messaging is currently unavailable due to an unexpected error.';
  }

  export let channelId: string;
  export let serverId: string;
  export let currentUser: { id: string } | null = null;
  export let showRoster = false;

  const dispatch = createEventDispatcher();

  // Source of truth, exactly as fetched/received -- never mutated with
  // decrypted content, so re-deriving `messages` below is always correct.
  // Mirrors `DMChatArea.svelte`'s `rawMessages`/`messages` split.
  let rawMessages: Message[] = [];
  let loading = true;
  let newMessage = '';
  let sending = false;

  // Channel slowmode: ticks down once a send comes back 429'd, so the
  // person sees why Send is disabled instead of just hitting the same
  // error again a moment later.
  let slowmodeSecondsLeft = 0;
  let slowmodeInterval: ReturnType<typeof setInterval> | null = null;

  function startSlowmodeCountdown(seconds: number) {
    slowmodeSecondsLeft = Math.max(1, Math.ceil(seconds));
    if (slowmodeInterval) clearInterval(slowmodeInterval);
    slowmodeInterval = setInterval(() => {
      slowmodeSecondsLeft -= 1;
      if (slowmodeSecondsLeft <= 0) {
        slowmodeSecondsLeft = 0;
        if (slowmodeInterval) clearInterval(slowmodeInterval);
        slowmodeInterval = null;
      }
    }, 1000);
  }
  let attachmentFile: File | null = null;
  let selectionMode = false;
  let selectedMessages: string[] = [];
  let highlightedMessageId: string | null = null;
  let messageInput: HTMLInputElement;
  let myRole = 'member';
  let showPinnedOnly = false;
  /** The authoritative pinned-message list for the open channel; see
   * `pinnedCount`'s comment above for why this isn't just a filter over
   * `messages`. */
  let pinnedMessages: Message[] | null = null;

  async function loadPinnedMessages(forChannel: string) {
    try {
      const list = await fetchPinnedMessages(forChannel);
      if (forChannel !== channelId) return; // channel switched while this was in flight
      pinnedMessages = list;
    } catch (e) {
      console.error('Failed to load pinned messages:', e);
      if (forChannel === channelId) pinnedMessages = null;
    }
  }
  let pendingDelete: Message | null = null;

  /** Set the moment this panel's encryption setup hits an unrecoverable
   * failure (crypto library, device setup, or an unexpected exception
   * while preparing messages for display). Non-null means the template
   * below shows a plain error state instead of the message list. Mirrors
   * `DMChatArea.svelte`'s `panelError`. */
  let panelError: string | null = null;

  /** This device's own X25519 private key and id, set once
   * `deviceEncryptionReady` resolves -- the SAME shared gate `App.svelte`
   * uses, never `ensureDeviceKeypair()` directly. */
  let myPrivateKey: string | null = null;
  let myDeviceId: string | null = null;
  deviceEncryptionReady()
    .then(kp => { myPrivateKey = kp.privateKey; myDeviceId = kp.deviceId; })
    .catch(e => {
      console.error('Failed to set up encryption keys:', e);
      panelError = describeCryptoError(e);
    });

  // Keeps this device's key in sync with LATER changes too (e.g. the
  // manual "Recover from backup" escape hatch) -- see the identical block
  // in `DMChatArea.svelte` for the full rationale.
  let lastSeenDeviceId: string | null = null;
  $: if ($activeDeviceKeypair) {
    myPrivateKey = $activeDeviceKeypair.privateKey;
    myDeviceId = $activeDeviceKeypair.deviceId;
    if (lastSeenDeviceId !== null && lastSeenDeviceId !== $activeDeviceKeypair.deviceId) {
      void loadMessages();
    }
    lastSeenDeviceId = $activeDeviceKeypair.deviceId;
  }

  const DECRYPT_FAILED_PLACEHOLDER = '[Unable to decrypt this message]';
  const SENT_BEFORE_DEVICE_ADDED_PLACEHOLDER = '[Sent before this device was added]';
  const UNEXPECTED_MESSAGE_ERROR_PLACEHOLDER = '[This message could not be displayed due to an unexpected error]';

  /** Per-message decryption state for an encrypted attachment, keyed by
   * message id. Populated lazily, same as `DMChatArea.svelte`'s identical
   * mechanism. Declared before `toDisplayMessage` below, which reads it. */
  type AttachmentState =
    | { status: 'loading' }
    | { status: 'ready'; objectUrl: string; mimeType: string }
    | { status: 'error'; message: string };
  let attachmentState: Record<string, AttachmentState> = {};
  const createdObjectUrls: string[] = [];
  const ATTACHMENT_FETCH_TIMEOUT_MS = 30_000;

  /** Per-message decryption state for a message sent via `ratchet.ts`,
   * mirroring `DMChatArea.svelte`'s identical mechanism -- see there for
   * the full rationale. A channel member only has a ratchet session with
   * SOME other members (whoever has bootstrapped one), so unlike a DM
   * this is routinely a mix of ratchet- and legacy-encrypted entries
   * within the very same message's `recipients` array. */
  type RatchetDecryptState = { status: 'loading' } | { status: 'done'; text: string | null };
  let ratchetDecryptState: Record<string, RatchetDecryptState> = {};
  const RATCHET_DECRYPTING_PLACEHOLDER = 'Decrypting…';

  // Decrypting a message depends on whether it went through the fan-out
  // send path: not encrypted -> show `content` (and `attachment_url`) as
  // -is; encrypted -> look for the entry in `recipients` addressed to THIS
  // device and decrypt it with (that entry's sender_public_key, MY OWN
  // private key). No matching entry means this device wasn't registered
  // (or wasn't yet a member) when the message was sent -- including, by
  // design, a member who joined after the fact (see
  // `messages.rs::create_message`'s completeness check). Also substitutes
  // an encrypted attachment's `attachment_url` for the decrypted object
  // URL once `ensureAttachmentDecrypted` below has produced one, so
  // `MessageItem` (which just renders `attachment_url` directly, same as
  // for a plaintext message) never has to know the difference -- and
  // never shows the raw ciphertext blob as if it were a viewable file
  // while decryption is still in flight or failed. `attachmentState` is
  // passed in explicitly (rather than closed over) purely so Svelte's
  // reactivity tracker sees it referenced directly in the `$:` block below
  // and re-runs this whenever it changes.
  function toDisplayMessage(
    message: Message,
    attachmentState: Record<string, AttachmentState>,
    ratchetState: Record<string, RatchetDecryptState>
  ): Message {
    try {
      let displayed = message;
      if (message.is_encrypted) {
        if (!myPrivateKey) {
          displayed = { ...message, content: DECRYPT_FAILED_PLACEHOLDER };
        } else {
          const recipients = Array.isArray(message.recipients) ? message.recipients : [];
          const mine = myDeviceId ? recipients.find(r => r.device_id === myDeviceId) : undefined;
          if (!mine) {
            displayed = { ...message, content: SENT_BEFORE_DEVICE_ADDED_PLACEHOLDER };
          } else if (mine.ratchet_header_json) {
            // Decrypted asynchronously by `ensureRatchetMessageDecrypted`,
            // kicked off by the reactive block below -- same lazy pattern
            // as `ensureAttachmentDecrypted` for files. This function
            // itself stays synchronous.
            const state = ratchetState[message.id];
            displayed = { ...message, content: !state || state.status === 'loading' ? RATCHET_DECRYPTING_PLACEHOLDER : (state.text ?? DECRYPT_FAILED_PLACEHOLDER) };
          } else {
            const decrypted = decryptFromSender(mine.ciphertext, mine.nonce, mine.sender_public_key, myPrivateKey);
            displayed = { ...message, content: decrypted ?? DECRYPT_FAILED_PLACEHOLDER };
          }
        }
        // A moderator's explicit, server-readable reveal of a pinned
        // message (see `pin_plaintext_content`'s doc comment in
        // `lib/messages.ts`) stands in only where this device couldn't
        // read the real ciphertext at all -- most importantly the
        // `SENT_BEFORE_DEVICE_ADDED_PLACEHOLDER` case, which is exactly
        // the "joined after it was sent" situation this feature exists
        // for. It never overrides a message this device actually has the
        // key for, even if that one decrypt attempt happened to fail.
        // `is_pinned` is checked here too, defensively, even though the
        // server is supposed to clear `pin_plaintext_content` the moment a
        // message is unpinned (and masks it at read time besides): this
        // client has no way to verify that server-side invariant actually
        // held, and showing a stale reveal for an unpinned message would
        // be exactly the exposure this feature is built to avoid outside
        // of "currently pinned".
        if (message.is_pinned && message.pin_plaintext_content && (displayed.content === DECRYPT_FAILED_PLACEHOLDER || displayed.content === SENT_BEFORE_DEVICE_ADDED_PLACEHOLDER)) {
          displayed = { ...displayed, content: message.pin_plaintext_content, revealed_fallback: true };
        }
      }
      if (displayed.is_encrypted && displayed.attachment_url && displayed.attachment_nonce) {
        const state = attachmentState[displayed.id];
        displayed = state?.status === 'ready'
          ? { ...displayed, attachment_url: state.objectUrl, attachment_mime_type: state.mimeType }
          : { ...displayed, attachment_url: null };
      }
      return displayed;
    } catch (e) {
      console.error('Unexpected error while preparing a channel message for display:', e);
      return { ...message, content: UNEXPECTED_MESSAGE_ERROR_PLACEHOLDER };
    }
  }

  /** Decrypts one ratchet-encrypted channel message's text, mirroring
   * `DMChatArea.svelte`'s identical function -- see there for the full
   * rationale. Needs `channelMemberDevices` (not `participantDevices`,
   * since a channel has many members) to map the entry's
   * `sender_public_key` back to a device id. */
  async function ensureRatchetMessageDecrypted(message: Message, mine: MessageRecipientEntry): Promise<void> {
    ratchetDecryptState = { ...ratchetDecryptState, [message.id]: { status: 'loading' } };
    try {
      // Check the local history cache FIRST, before touching the ratchet
      // at all -- not just an optimization. If this message was originally
      // received out of order, its key was a single-use entry in the
      // ratchet's `skippedKeys` map, deleted the moment it was consumed
      // (see `ratchet.ts`'s header comment); a second decrypt attempt
      // against the live ratchet would fail outright, even though the
      // user already legitimately read this message once. See
      // `message-history.ts`'s header comment for the full trade this
      // cache makes.
      const cached = await getCachedPlaintext(message.id);
      if (cached !== null) {
        ratchetDecryptState = { ...ratchetDecryptState, [message.id]: { status: 'done', text: cached } };
        return;
      }

      const senderDeviceId = channelMemberDevices.find(d => d.public_key === mine.sender_public_key)?.device_id;
      if (!senderDeviceId) {
        ratchetDecryptState = { ...ratchetDecryptState, [message.id]: { status: 'done', text: null } };
        return;
      }
      const header = JSON.parse(mine.ratchet_header_json as string);
      const envelope: RatchetEnvelope = {
        dh: header.dh,
        pn: header.pn,
        n: header.n,
        ciphertext: mine.ciphertext,
        nonce: mine.nonce,
        initial: header.initial,
      };
      const plaintext = await decryptMessage(senderDeviceId, envelope);
      if (plaintext !== null) {
        await cachePlaintext(message.id, plaintext);
      }
      ratchetDecryptState = { ...ratchetDecryptState, [message.id]: { status: 'done', text: plaintext } };
    } catch (e) {
      console.error('Failed to decrypt a ratchet-encrypted channel message:', e);
      ratchetDecryptState = { ...ratchetDecryptState, [message.id]: { status: 'done', text: null } };
    }
  }

  // Re-derived whenever the raw messages, our key, an attachment's
  // decryption state, or a ratchet decryption's state changes. The `map`
  // itself is also guarded, as the last line of defense against anything
  // escaping `toDisplayMessage` (see the identical note in
  // `DMChatArea.svelte`).
  let messages: Message[] = [];
  $: {
    try {
      messages = rawMessages.map(m => toDisplayMessage(m, attachmentState, ratchetDecryptState));
    } catch (e) {
      console.error('Unexpected error building the channel message list:', e);
      messages = [];
      if (!panelError) panelError = 'Encrypted messaging is currently unavailable due to an unexpected error.';
    }
  }

  // Kicks off `ensureRatchetMessageDecrypted` for any ratchet-encrypted
  // message not yet attempted. Gated on `channelMemberDevices` actually
  // being loaded (needed to resolve a sender's device id), same as
  // `DMChatArea.svelte`'s identical block.
  $: {
    if (myDeviceId && channelMemberDevices.length > 0) {
      // Also covers `pinnedMessages`, not just the currently loaded page
      // of history -- a pinned message this device genuinely can decrypt
      // (it has a `recipients` entry) shouldn't get stuck on "Decrypting…"
      // forever in the pinned panel just because it predates whatever's
      // paginated into `rawMessages` right now.
      for (const m of [...rawMessages, ...(pinnedMessages ?? [])]) {
        if (!m.is_encrypted) continue;
        const recipients = Array.isArray(m.recipients) ? m.recipients : [];
        const mine = recipients.find(r => r.device_id === myDeviceId);
        if (mine?.ratchet_header_json && !ratchetDecryptState[m.id]) {
          void ensureRatchetMessageDecrypted(m, mine);
        }
      }
    }
  }

  // Triggers attachment decryption off the RAW messages (never the
  // already-decrypted `messages` above, which itself depends on
  // `attachmentState` -- scanning that here would be circular).
  $: {
    for (const m of [...rawMessages, ...(pinnedMessages ?? [])]) {
      if (m.attachment_url && m.is_encrypted && m.attachment_nonce && !attachmentState[m.id]) {
        void ensureAttachmentDecrypted(m);
      }
    }
  }

  async function ensureAttachmentDecrypted(message: Message): Promise<void> {
    attachmentState = { ...attachmentState, [message.id]: { status: 'loading' } };
    const fail = (text: string) => {
      attachmentState = { ...attachmentState, [message.id]: { status: 'error', message: text } };
    };
    try {
      if (!myPrivateKey || !myDeviceId) {
        fail('Encryption keys not ready yet');
        return;
      }
      const recipients = Array.isArray(message.recipients) ? message.recipients : [];
      const mine = recipients.find(r => r.device_id === myDeviceId);
      if (!mine || !mine.attachment_key_ciphertext || !mine.attachment_key_nonce) {
        fail(SENT_BEFORE_DEVICE_ADDED_PLACEHOLDER);
        return;
      }

      // The ratchet's message keys are single-use and deleted the instant
      // they're consumed (forward secrecy), so a second ratchet-decrypt
      // attempt for this same attachment key would fail outright -- see
      // `DMChatArea.svelte`'s identical note. Reuses the same local
      // history cache, namespaced so it never collides with this
      // message's own text-plaintext cache entry.
      const attachmentKeyCacheId = `${message.id}:attachment-key`;
      let fileKey: Uint8Array | null = null;
      const cachedKeyB64 = await getCachedPlaintext(attachmentKeyCacheId);
      if (cachedKeyB64 !== null) {
        fileKey = fromB64(cachedKeyB64);
      } else if (mine.attachment_key_ratchet_header_json) {
        const senderDeviceId = channelMemberDevices.find(d => d.public_key === mine.sender_public_key)?.device_id;
        if (senderDeviceId) {
          const header = JSON.parse(mine.attachment_key_ratchet_header_json);
          const envelope: RatchetEnvelope = {
            dh: header.dh,
            pn: header.pn,
            n: header.n,
            ciphertext: mine.attachment_key_ciphertext,
            nonce: mine.attachment_key_nonce,
            initial: header.initial,
          };
          const keyB64 = await decryptMessage(senderDeviceId, envelope);
          if (keyB64 !== null) {
            await cachePlaintext(attachmentKeyCacheId, keyB64);
            fileKey = fromB64(keyB64);
          }
        }
      } else {
        // Legacy static wrap (migration 0032, pre-0044).
        fileKey = unwrapFileKey(mine.attachment_key_ciphertext, mine.attachment_key_nonce, mine.sender_public_key, myPrivateKey);
      }
      if (!fileKey) {
        fail(DECRYPT_FAILED_PLACEHOLDER);
        return;
      }

      const response = await withTimeout(
        fetch(fileUrl(message.attachment_url)),
        ATTACHMENT_FETCH_TIMEOUT_MS,
        'Timed out downloading the attachment.'
      );
      if (!response.ok) {
        fail('Failed to download attachment');
        return;
      }
      const ciphertextBytes = new Uint8Array(await response.arrayBuffer());

      const plaintextBytes = decryptFileBytes(ciphertextBytes, message.attachment_nonce as string, fileKey);
      if (!plaintextBytes) {
        fail(DECRYPT_FAILED_PLACEHOLDER);
        return;
      }

      const mimeType = message.attachment_mime_type || 'application/octet-stream';
      const blob = new Blob([plaintextBytes.slice()], { type: mimeType });
      const objectUrl = URL.createObjectURL(blob);
      createdObjectUrls.push(objectUrl);
      attachmentState = { ...attachmentState, [message.id]: { status: 'ready', objectUrl, mimeType } };
    } catch (e) {
      console.error('Unexpected error decrypting a channel attachment:', e);
      fail(e instanceof TimeoutError ? e.message : 'Failed to decrypt attachment');
    }
  }

  /** This server's members, for resolving `@username` mentions typed in
   * the composer and for rendering a sent message's `mentioned_user_ids`
   * back into highlighted `@username` text. Fetched fresh per server
   * (unlike `channelMemberDevices`, membership itself -- not device lists
   * -- is server-wide, so this doesn't need to reload on every channel
   * switch within the same server). Best-effort: if this fails to load,
   * mentions just silently don't resolve for this session rather than
   * blocking sending. */
  let serverMembers: Member[] = [];
  $: usernameToId = new Map(serverMembers.map(m => [m.username.toLowerCase(), m.id]));
  $: idToUsername = new Map(serverMembers.map(m => [m.id, m.username]));
  /** This message's `mentioned_user_ids` resolved to usernames, for
   * `MessageItem`'s `mentionUsernames` prop -- a mentioned member no
   * longer in `serverMembers` (left since, say) is simply left out, since
   * there's no username left to highlight. */
  function mentionUsernamesFor(message: Message): string[] {
    const usernames: string[] = [];
    for (const id of message.mentioned_user_ids ?? []) {
      const username = idToUsername.get(id);
      if (username) usernames.push(username);
    }
    return usernames;
  }
  async function loadServerMembers() {
    const forServer = serverId;
    try {
      const members = await fetchServerMembers(forServer);
      if (forServer !== serverId) return;
      serverMembers = members;
    } catch (e) {
      if (forServer !== serverId) return;
      console.error('Failed to load server members for @mentions:', e);
      serverMembers = [];
    }
  }
  $: if (serverId) loadServerMembers();

  /** Every registered device of every current member of this channel's
   * server -- fetched fresh per channel, since (unlike a DM's fixed pair)
   * this set can be large and changes as members join or leave. */
  let channelMemberDevices: ParticipantDevice[] = [];
  async function loadChannelMemberDevices() {
    const forChannel = channelId;
    try {
      const devices = await fetchChannelMemberDevices(forChannel);
      if (forChannel !== channelId) return;
      channelMemberDevices = devices;
    } catch (e) {
      if (forChannel !== channelId) return;
      console.error('Failed to load channel member devices:', e);
      channelMemberDevices = [];
    }
  }

  $: canModerate = ['owner', 'admin', 'moderator'].includes(myRole);
  // Every currently-pinned message, fetched straight from the server
  // (`get_pinned_messages`) rather than filtered out of `messages` --
  // filtering `messages` would miss a pinned message older than
  // whatever page of history happens to be loaded, which is exactly the
  // case (a member who joined after an old pinned announcement) this
  // panel most needs to cover. `null` means "not loaded yet for this
  // channel" (so the toggle button stays hidden rather than flashing
  // empty); `pinnedMessages ?? []` is used everywhere that treats it as
  // an array.
  $: pinnedCount = pinnedMessages?.length ?? 0;
  $: if (pinnedMessages !== null && pinnedCount === 0) showPinnedOnly = false;
  $: displayedPinnedMessages = (pinnedMessages ?? []).map(m => toDisplayMessage(m, attachmentState, ratchetDecryptState));
  $: visibleMessages = showPinnedOnly ? displayedPinnedMessages : messages;
  $: if (serverId) loadRole(serverId);

  async function loadRole(id: string) {
    try {
      const res = await apiFetch(`${apiBase()}/api/v1/servers/${id}/role`, { headers: getAuthHeaders() });
      if (res.ok) myRole = (await res.json()).role;
    } catch (e) {
      console.error('Failed to load role:', e);
    }
  }

  function patchMessage(id: string, changes: Partial<Message>) {
    rawMessages = rawMessages.map(m => (m.id === id ? { ...m, ...changes } : m));
    if (pinnedMessages) {
      pinnedMessages = changes.is_pinned === false
        ? pinnedMessages.filter(m => m.id !== id)
        : pinnedMessages.map(m => (m.id === id ? { ...m, ...changes } : m));
    }
  }

  // Runs a message action and shows the server's error if it fails.
  async function run(action: () => Promise<void>) {
    try {
      await action();
    } catch (e: any) {
      alert(e.message || 'Something went wrong');
    }
  }

  function handleToggleReaction(e: CustomEvent<{ messageId: string; emoji: string }>) {
    const { messageId, emoji } = e.detail;
    const message = messages.find(m => m.id === messageId);
    const mine = message?.reactions?.find(r => r.emoji === emoji)?.user_ids.includes(currentUser?.id ?? '');
    run(async () => {
      const reactions = mine ? await removeReaction(messageId, emoji) : await addReaction(messageId, emoji);
      patchMessage(messageId, { reactions });
    });
  }

  const handlePin = (e: CustomEvent<Message>) => run(async () => {
    const m = e.detail;
    if (m.is_pinned) {
      const result = await unpinMessage(m.id);
      if (result.requires_confirmation) {
        // Nothing happened server-side yet -- the message is still
        // pinned. Don't touch local state; `confirmUnpin` does the real
        // work once the user agrees to lose it.
        pendingUnpin = { message: m, warning: result.warning ?? "This message is old enough that unpinning it will delete it immediately. This can't be undone." };
        return;
      }
      patchMessage(m.id, { is_pinned: false });
      return;
    }
    await pinMessage(m.id);
    patchMessage(m.id, { is_pinned: true });
    // Newly pinning a message that wasn't already in the pinned panel's
    // list needs a refetch to actually appear there -- `patchMessage`
    // only updates an entry already present.
    if (pinnedMessages && !pinnedMessages.some(p => p.id === m.id)) {
      void loadPinnedMessages(channelId);
    }
  });

  /** A message pending the "unpinning this deletes it immediately"
   * confirmation dialog, with the server's own explanation of why --
   * see `unpinMessage`'s doc comment for the general rule. */
  let pendingUnpin: { message: Message; warning: string } | null = null;

  async function confirmUnpin() {
    const pending = pendingUnpin;
    pendingUnpin = null;
    if (!pending) return;
    const m = pending.message;
    await run(async () => {
      const result = await unpinMessage(m.id, true);
      if (result.deleted) {
        // The server already broadcasts `message_deleted` for this (same
        // as an ordinary delete), which `onMessageDeleted` will pick up
        // shortly -- but remove it locally right away too, same as
        // `confirmDelete`, so the actor isn't left looking at a message
        // that's actually already gone.
        rawMessages = rawMessages.filter(x => x.id !== m.id);
        if (pinnedMessages) pinnedMessages = pinnedMessages.filter(x => x.id !== m.id);
        await deleteCachedPlaintext(m.id);
        await deleteCachedPlaintext(`${m.id}:attachment-key`);
      }
    });
  }

  /** A message pending the reveal confirmation dialog -- see
   * `confirmReveal` below for why this needs its own ConfirmModal rather
   * than reusing `pendingDelete`'s. */
  let pendingReveal: Message | null = null;

  const handlePinVisibility = (e: CustomEvent<Message>) => {
    const m = e.detail;
    if (m.pin_plaintext_content) {
      // Hiding a reveal only narrows exposure back down -- no
      // confirmation needed, unlike revealing it in the first place.
      run(async () => {
        await setPinVisibility(m.id, null);
        patchMessage(m.id, { pin_plaintext_content: null });
      });
    } else {
      pendingReveal = m;
    }
  };

  async function confirmReveal() {
    const m = pendingReveal;
    pendingReveal = null;
    if (!m) return;
    // This device's own already-decrypted copy of the message -- the
    // same text on screen right now -- never the raw ciphertext. If this
    // device hasn't actually decrypted it (shouldn't normally happen,
    // since the "Reveal" button only shows once content is on screen),
    // refuse rather than send a placeholder string to the server.
    const displayed = messages.find(x => x.id === m.id) ?? displayedPinnedMessages.find(x => x.id === m.id);
    const plaintext = displayed?.content;
    if (!plaintext || plaintext === DECRYPT_FAILED_PLACEHOLDER || plaintext === SENT_BEFORE_DEVICE_ADDED_PLACEHOLDER || plaintext === RATCHET_DECRYPTING_PLACEHOLDER) {
      alert("Can't reveal this message yet: it hasn't finished decrypting on this device.");
      return;
    }
    await run(async () => {
      await setPinVisibility(m.id, plaintext);
      patchMessage(m.id, { pin_plaintext_content: plaintext });
    });
  }

  const handleLock = (e: CustomEvent<Message>) => run(async () => {
    const m = e.detail;
    await (m.is_locked ? unlockMessage(m.id) : lockMessage(m.id));
    patchMessage(m.id, { is_locked: !m.is_locked });
  });

  const handleHide = (e: CustomEvent<Message>) => run(async () => {
    await hideMessage(e.detail.id);
    patchMessage(e.detail.id, { is_hidden: true });
  });

  const handleUnhide = (e: CustomEvent<Message>) => run(async () => {
    await unhideMessage(e.detail.id);
    patchMessage(e.detail.id, { is_hidden: false });
  });

  async function confirmDelete() {
    const m = pendingDelete;
    pendingDelete = null;
    if (!m) return;
    await run(async () => {
      await deleteMessage(m.id);
      await deleteCachedPlaintext(m.id);
      await deleteCachedPlaintext(`${m.id}:attachment-key`);
      rawMessages = rawMessages.filter(x => x.id !== m.id);
    });
  }

  // Insert the picked emoji where the cursor is, then put the cursor after it.
  async function insertEmoji(event: CustomEvent<string>) {
    const emoji = event.detail;
    const start = messageInput?.selectionStart ?? newMessage.length;
    const end = messageInput?.selectionEnd ?? newMessage.length;
    newMessage = newMessage.slice(0, start) + emoji + newMessage.slice(end);
    await tick();
    messageInput?.focus();
    const pos = start + emoji.length;
    messageInput?.setSelectionRange(pos, pos);
  }

  // History is loaded a page at a time; scrolling to the top loads more.
  const PAGE_SIZE = 50;
  let container: HTMLDivElement;
  let hasMore = false;
  let loadingOlder = false;

  $: if (channelId) {
    loadMessages();
    loadChannelMemberDevices();
    pinnedMessages = null;
    void loadPinnedMessages(channelId);
    searchOpen = false;
    searchQuery = '';
    historyFullyLoadedFor = null;
    typingTracker.reset();
  }

  // --- "Someone is typing..." -------------------------------------------
  // See `lib/typing.ts` for the full design (not E2EE, deliberately carries
  // no message content, no explicit "stopped" event).
  let typingUserIds: string[] = [];
  const typingTracker = new TypingTracker(() => {
    typingUserIds = typingTracker.ids();
  });

  function onTyping(data: { channel_id: string; user_id: string }) {
    if (data.channel_id !== channelId || data.user_id === currentUser?.id) return;
    typingTracker.see(data.user_id);
  }

  $: typingDisplayNames = typingUserIds
    .map(id => serverMembers.find(m => m.id === id)?.username)
    .filter((u): u is string => !!u);

  // --- In-channel search ----------------------------------------------
  // Channel messages are mandatory end-to-end encrypted, so there's no
  // server-side full-text search to call -- the server never has
  // plaintext to index. This searches the channel's *decrypted* history
  // on this device instead: once a search starts, it pages in every
  // remaining page of history (the same `loadOlder` scrolling to the top
  // already uses) and waits for the existing decryption pipeline (the
  // reactive block above) to catch up, then filters the resulting
  // plaintext. A message this device genuinely cannot decrypt (its
  // ratchet key is long gone, same as anywhere else in this app) simply
  // can't match -- there's no way around that without the server ever
  // seeing plaintext, which is exactly what this app doesn't do.
  let searchOpen = false;
  let searchQuery = '';
  let searchLoadingHistory = false;
  let searchInput: HTMLInputElement;
  /** Which channel's full history + decryption has already been loaded
   * for search, so re-typing in the same channel doesn't re-page
   * through history it already has. Reset to null on every channel
   * switch above. */
  let historyFullyLoadedFor: string | null = null;

  async function toggleSearch() {
    searchOpen = !searchOpen;
    if (!searchOpen) {
      searchQuery = '';
      return;
    }
    await tick();
    searchInput?.focus();
  }

  async function ensureFullHistoryLoadedForSearch() {
    if (historyFullyLoadedFor === channelId) return;
    const forChannel = channelId;
    searchLoadingHistory = true;
    try {
      while (hasMore && forChannel === channelId) {
        await loadOlder();
      }
      if (forChannel !== channelId) return;
      // `loadOlder` only pages ciphertext in; decryption itself runs on
      // the reactive block above and finishes asynchronously, so wait
      // for every message this device has a key for to reach 'done'
      // before treating history as searchable, rather than guessing a
      // fixed delay.
      for (let i = 0; i < 200 && forChannel === channelId; i++) {
        const stillDecrypting = rawMessages.some(m => {
          if (!m.is_encrypted) return false;
          const recipients = Array.isArray(m.recipients) ? m.recipients : [];
          const mine = recipients.find(r => r.device_id === myDeviceId);
          if (!mine?.ratchet_header_json) return false;
          return ratchetDecryptState[m.id]?.status !== 'done';
        });
        if (!stillDecrypting) break;
        await new Promise(resolve => setTimeout(resolve, 50));
      }
      if (forChannel === channelId) historyFullyLoadedFor = forChannel;
    } finally {
      if (forChannel === channelId) searchLoadingHistory = false;
    }
  }

  $: if (searchOpen && searchQuery.trim()) {
    void ensureFullHistoryLoadedForSearch();
  }

  $: searchResults =
    searchOpen && searchQuery.trim() && historyFullyLoadedFor === channelId
      ? messages.filter(m => m.content?.toLowerCase().includes(searchQuery.trim().toLowerCase()))
      : [];

  /** Same formatting as `MessageItem.svelte`'s identically-named helper,
   * for the timestamp shown next to each search result. */
  function formatTime(dateString: string): string {
    return new Date(dateString).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
  }

  async function jumpToSearchResult(messageId: string) {
    searchOpen = false;
    searchQuery = '';
    highlightedMessageId = messageId;
    await tick();
    container?.querySelector(`[data-message-id="${messageId}"]`)?.scrollIntoView({ block: 'center' });
    setTimeout(() => {
      if (highlightedMessageId === messageId) highlightedMessageId = null;
    }, 2500);
  }

  // Named handlers so onDestroy removes only this component's listeners
  // (ChannelList listens to the same events).
  // Message ids we're waiting to notify about once their content is
  // available. A plaintext message can notify immediately; a ratchet-
  // encrypted one has to wait for `ensureRatchetMessageDecrypted` to finish
  // (see the reactive block below) since `data.content` is null for those
  // until decrypted -- the server never has the plaintext to begin with.
  let pendingNotifyIds = new Set<string>();

  function onNewMessage(data: Message) {
    if (data.channel_id !== channelId) return;
    addMessage(data);
    scrollToBottom();
    typingTracker.clear(data.user_id); // their message just arrived -- they're done typing it
    if (data.user_id === currentUser?.id) return; // never notify on our own messages
    const name = data.nickname || data.username;
    if (data.content) {
      void notifyNewMessage(name, data.content);
    } else if (data.is_encrypted) {
      pendingNotifyIds.add(data.id);
    }
  }

  // Fires the deferred notification for a just-arrived encrypted message
  // once its ratchet decryption completes. Keyed off `ratchetDecryptState`
  // so it reruns whenever a decrypt finishes; `pendingNotifyIds` only ever
  // contains ids from `onNewMessage` above, never from history backfill or
  // the pinned-messages panel, so this never fires for old messages.
  $: {
    for (const id of [...pendingNotifyIds]) {
      const state = ratchetDecryptState[id];
      if (state?.status === 'done') {
        pendingNotifyIds.delete(id);
        if (state.text) {
          const msg = rawMessages.find(m => m.id === id);
          if (msg) void notifyNewMessage(msg.nickname || msg.username, state.text);
        }
      }
    }
  }

  function onMessageDeleted(data: { message_id: string }) {
    rawMessages = rawMessages.filter(m => m.id !== data.message_id);
    if (pinnedMessages) pinnedMessages = pinnedMessages.filter(m => m.id !== data.message_id);
  }

  function onMessageUpdated(data: Message) {
    rawMessages = rawMessages.map(m => m.id === data.id ? { ...m, ...data } : m);
    if (pinnedMessages) {
      const isPinnedChange = Object.prototype.hasOwnProperty.call(data, 'is_pinned');
      if (isPinnedChange && (data as any).is_pinned === false) {
        pinnedMessages = pinnedMessages.filter(m => m.id !== data.id);
      } else if (isPinnedChange && !pinnedMessages.some(m => m.id === data.id)) {
        // Newly pinned somewhere we don't already have it loaded (possibly
        // by another moderator) -- simplest to just refetch rather than
        // try to splice in a payload that may only be a partial patch.
        void loadPinnedMessages(channelId);
      } else {
        pinnedMessages = pinnedMessages.map(m => m.id === data.id ? { ...m, ...data } : m);
      }
    }
  }

  // The sender gets their message both from the POST response and from the
  // WebSocket broadcast, so skip ids we already have.
  function addMessage(message: Message) {
    if (rawMessages.some(m => m.id === message.id)) return;
    rawMessages = [...rawMessages, message];
  }

  // My role changed (promoted, demoted, ownership transferred): refresh what I can do.
  function onMemberUpdated(data: { server_id: string; user_id: string }) {
    if (data.server_id === serverId && data.user_id === currentUser?.id) loadRole(serverId);
  }

  onMount(() => {
    wsClient.connect();
    wsClient.on('new_message', onNewMessage);
    wsClient.on('message_deleted', onMessageDeleted);
    wsClient.on('message_updated', onMessageUpdated);
    wsClient.on('member_updated', onMemberUpdated);
    wsClient.on('typing', onTyping);
  });

  onDestroy(() => {
    wsClient.off('new_message', onNewMessage);
    wsClient.off('message_deleted', onMessageDeleted);
    wsClient.off('message_updated', onMessageUpdated);
    wsClient.off('member_updated', onMemberUpdated);
    wsClient.off('typing', onTyping);
    typingTracker.destroy();
    for (const url of createdObjectUrls) URL.revokeObjectURL(url);
    if (slowmodeInterval) clearInterval(slowmodeInterval);
  });

  const handleEdit = (e: CustomEvent<{ message: Message; content: string }>) => run(async () => {
    const { message, content } = e.detail;
    const res = await apiFetch(`${apiBase()}/api/v1/messages/${message.id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content }),
    });
    if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || 'Could not edit message');
    patchMessage(message.id, { content, is_edited: true });
  });

  /** Loads the page of messages before the oldest one shown, keeping the view in place. */
  async function loadOlder() {
    if (loadingOlder || !hasMore || rawMessages.length === 0) return;
    const forChannel = channelId;
    loadingOlder = true;
    try {
      const older = await fetchChannelMessages(forChannel, {
        before: rawMessages[0].id,
        limit: PAGE_SIZE,
        deviceId: myDeviceId,
      });
      if (forChannel !== channelId) return;
      hasMore = older.length === PAGE_SIZE;
      const fresh = older.filter(o => !rawMessages.some(m => m.id === o.id));
      if (fresh.length === 0) return;

      const heightBefore = container?.scrollHeight ?? 0;
      const topBefore = container?.scrollTop ?? 0;
      rawMessages = [...fresh, ...rawMessages];
      await tick();
      if (container) container.scrollTop = topBefore + (container.scrollHeight - heightBefore);
    } catch (e) {
      console.error('Failed to load older messages:', e);
    } finally {
      loadingOlder = false;
    }
  }

  function onScroll() {
    if (!container) return;
    nearBottom = container.scrollHeight - container.scrollTop - container.clientHeight < 80;
    // Ignore scrolling while a channel is still loading or being positioned.
    if (loading || showPinnedOnly) return;
    if (container.scrollTop < 120) loadOlder();
  }

  async function loadMessages() {
    const forChannel = channelId;
    loading = true;
    hasMore = false;
    try {
      // Wait for this device's own id before fetching: without it, every
      // fan-out message in the page would come back with no ciphertext at
      // all (see `HistoryQuery` in `messages.rs`).
      const { deviceId } = await deviceEncryptionReady();
      if (forChannel !== channelId) return;
      const fetched = await fetchChannelMessages(forChannel, { limit: PAGE_SIZE, deviceId });
      if (forChannel !== channelId) return;
      rawMessages = fetched;
      hasMore = fetched.length === PAGE_SIZE;
      loading = false;
      await scrollToBottom(true);
    } catch (e) {
      console.error('Failed to load messages:', e);
      if (!panelError) panelError = describeCryptoError(e);
    } finally {
      loading = false;
    }
  }

  // Keep in sync with MAX_ATTACHMENT_BYTES on the server.
  const MAX_ATTACHMENT_MB = 100;

  function handleFileSelect(event: Event) {
    const target = event.target as HTMLInputElement;
    const file = target.files?.[0] || null;
    if (file && file.size > MAX_ATTACHMENT_MB * 1024 * 1024) {
      alert(`That file is too large. The limit is ${MAX_ATTACHMENT_MB} MB.`);
      target.value = '';
      attachmentFile = null;
      return;
    }
    attachmentFile = file;
  }

  function clearAttachment() {
    attachmentFile = null;
    const fileInput = document.querySelector('input[type="file"]') as HTMLInputElement;
    if (fileInput) fileInput.value = '';
  }

  // Encrypts `content` for one recipient device, mirroring
  // `DMChatArea.svelte`'s identical function -- see there for the full
  // rationale (prefer the ratchet when the device supports it, fall back
  // to the legacy per-device key otherwise, and never ratchet this
  // device's own self-entry).
  async function encryptForDevice(
    d: ParticipantDevice,
    content: string
  ): Promise<{ deviceId: string; ciphertext: string; nonce: string; ratchetHeaderJson?: string }> {
    if (d.device_id === myDeviceId) {
      const { ciphertext, nonce } = encryptForRecipient(content, d.public_key, myPrivateKey as string);
      return { deviceId: d.device_id, ciphertext, nonce };
    }
    try {
      const envelope = await encryptMessage(d.device_id, content);
      return {
        deviceId: d.device_id,
        ciphertext: envelope.ciphertext,
        nonce: envelope.nonce,
        ratchetHeaderJson: JSON.stringify({ dh: envelope.dh, pn: envelope.pn, n: envelope.n, initial: envelope.initial }),
      };
    } catch (err) {
      // A channel routinely has members who haven't bootstrapped a
      // ratchet session yet (unlike a DM's single fixed peer) -- this
      // fallback is the normal case here, not an edge case.
      if (!(err instanceof RatchetNotSupportedError)) throw err;
      const { ciphertext, nonce } = encryptForRecipient(content, d.public_key, myPrivateKey as string);
      return { deviceId: d.device_id, ciphertext, nonce };
    }
  }

  // Wraps an attachment's symmetric file key for one recipient device,
  // preferring the Double Ratchet exactly like `encryptForDevice` does for
  // text, and falling back to the legacy static `wrapFileKey` scheme
  // (`crypto.ts`, raw-bytes `crypto_box_easy`) the same way too -- see
  // migration 0044. Deliberately a SEPARATE function from `encryptForDevice`
  // -- see `DMChatArea.svelte`'s identical function for why its static
  // fallback must keep `wrapFileKey`'s raw-byte wire format rather than
  // sharing `encryptForRecipient`'s UTF-8-string format.
  async function wrapAttachmentKeyForDevice(
    d: ParticipantDevice,
    fileKey: Uint8Array
  ): Promise<{ ciphertext: string; nonce: string; ratchetHeaderJson?: string }> {
    if (d.device_id === myDeviceId) {
      return wrapFileKey(fileKey, d.public_key, myPrivateKey as string);
    }
    try {
      const envelope = await encryptMessage(d.device_id, b64(fileKey));
      return {
        ciphertext: envelope.ciphertext,
        nonce: envelope.nonce,
        ratchetHeaderJson: JSON.stringify({ dh: envelope.dh, pn: envelope.pn, n: envelope.n, initial: envelope.initial }),
      };
    } catch (err) {
      if (!(err instanceof RatchetNotSupportedError)) throw err;
      return wrapFileKey(fileKey, d.public_key, myPrivateKey as string);
    }
  }

  // Encrypts `content` once per device in `devices` -- including this
  // device's own current device, with no special-casing (see
  // `DMChatArea.svelte`'s identical function for the full rationale: the
  // sending device gets a real `message_recipients` row too, so it
  // decrypts its own sent message the exact same way any other device
  // would).
  async function encryptAndSend(
    content: string,
    devices: ParticipantDevice[],
    file: File | null
  ): Promise<Message> {
    // Resolved from the PLAINTEXT content here, before it's encrypted --
    // the server never sees this text, so it has no way to detect mentions
    // itself. Only a real server member's username resolves; anything else
    // typed as "@word" is sent as plain text.
    const mentionedUserIds = extractMentionedUsernames(content, serverMembers.map(m => m.username)).map(
      u => usernameToId.get(u.toLowerCase())!
    );

    if (!file) {
      const encryptedFor = await Promise.all(devices.map(d => encryptForDevice(d, content)));
      return sendChannelMessage(channelId, null, { encryptedFor, senderDeviceId: myDeviceId as string, mentionedUserIds });
    }

    // Hybrid encryption, same as the DM attachment flow: the file is
    // encrypted ONCE with a fresh random symmetric key, then that small
    // key is wrapped once per recipient device, through
    // `wrapAttachmentKeyForDevice` -- which prefers the ratchet (forward
    // secrecy + post-compromise security for the key wrap, not just the
    // text) and falls back to the legacy static scheme exactly like text
    // does -- see migration 0044.
    const fileBytes = new Uint8Array(await file.arrayBuffer());
    const { ciphertext: fileCiphertext, nonce: attachmentNonce, fileKey } = encryptFileForFanout(fileBytes);
    const encryptedBlob = new File([fileCiphertext.slice()], file.name, { type: 'application/octet-stream' });
    const uploaded = await uploadFile(encryptedBlob);

    const encryptedFor = await Promise.all(
      devices.map(async d => {
        const textResult = await encryptForDevice(d, content);
        const keyWrap = await wrapAttachmentKeyForDevice(d, fileKey);
        return {
          ...textResult,
          attachmentKeyCiphertext: keyWrap.ciphertext,
          attachmentKeyNonce: keyWrap.nonce,
          attachmentKeyRatchetHeaderJson: keyWrap.ratchetHeaderJson,
        };
      })
    );

    return sendChannelMessage(
      channelId,
      { url: uploaded.url, filename: file.name, size: file.size, mime_type: file.type || 'application/octet-stream' },
      { encryptedFor, senderDeviceId: myDeviceId as string, attachmentNonce, mentionedUserIds }
    );
  }

  // Whether a failed send was caused by `channelMemberDevices` going stale
  // (a member joined/left, or added/removed a device, while this channel
  // stayed open) -- the server rejects the whole send with a 400 naming
  // the bad `device_id` in that case.
  function isStaleDeviceListError(e: unknown): boolean {
    if (!(e instanceof SendChannelMessageError) || e.status !== 400 || !e.serverMessage) return false;
    // Two distinct validation failures both mean the same thing here --
    // `channelMemberDevices` is stale -- and the server's wording differs
    // between them (see `messages.rs`'s two checks): a device that's been
    // removed/revoked produces "...a device_id that doesn't belong...",
    // while a NEW device that was added since the list was last loaded
    // (the more common race -- someone just joined, or just added a
    // device) produces "...must contain exactly every currently-registered
    // device...; missing: [...]", which never contains the literal
    // substring "device_id" at all. Both need to trigger the same
    // reload-and-retry below.
    return (
      e.serverMessage.includes('device_id') ||
      e.serverMessage.includes('must contain exactly every currently-registered device')
    );
  }

  async function handleSendMessage(e: Event) {
    e.preventDefault();
    const content = newMessage.trim();
    if ((!content && !attachmentFile) || sending || slowmodeSecondsLeft > 0) return;

    // The single most important invariant: never send plaintext when
    // encryption was supposed to happen. There is no silent plaintext
    // fallback -- if our own keypair isn't ready, sending is blocked.
    if (!canSend || !myPrivateKey || !myDeviceId) return;

    const fileToSend = attachmentFile;
    sending = true;
    try {
      let created: Message;
      try {
        created = await encryptAndSend(content, channelMemberDevices, fileToSend);
      } catch (err) {
        if (!isStaleDeviceListError(err)) throw err;
        await loadChannelMemberDevices();
        created = await encryptAndSend(content, channelMemberDevices, fileToSend);
      }
      addMessage(created);
      newMessage = '';
      clearAttachment();
      scrollToBottom(true);
    } catch (e) {
      console.error('Failed to send message:', e);
      if (isStaleDeviceListError(e)) {
        alert("Couldn't send: the channel's member devices changed, please try again");
      } else if (e instanceof SendChannelMessageError && e.status === 429) {
        // Slowmode -- show a countdown instead of the generic network-error
        // alert, and don't throw the composed text/attachment away (unlike
        // a successful send, nothing above cleared them).
        startSlowmodeCountdown(e.retryAfterSeconds ?? 1);
      } else if (e instanceof CryptoLibraryError || e instanceof DeviceSetupError) {
        panelError = describeCryptoError(e);
      } else if (e instanceof TimeoutError) {
        alert('Timed out sending message. Please try again.');
      } else if (e instanceof SendChannelMessageError && e.status === 400 && e.serverMessage) {
        // A rejection with something specific to say -- e.g. the
        // attachment-storage-quota check in `create_message` ("This
        // attachment doesn't fit even after freeing everything...").
        // Worth showing verbatim instead of the generic fallback below.
        alert(e.serverMessage);
      } else {
        alert('Network error while sending message');
      }
    } finally {
      sending = false;
    }
  }

  // Whether we're able to send an encrypted message right now: our own
  // keypair must have finished loading/generating, and nothing has gone
  // wrong at the panel level. Unlike a DM (a fixed two-person pair where
  // the other side having zero devices means sending is pointless), a
  // channel can have members who haven't set up encrypted messaging yet
  // without that blocking everyone else -- the server's completeness
  // check only ever requires covering devices that actually exist.
  $: canSend = !panelError && !!myPrivateKey && !!myDeviceId;
  
  function handleSelectMessage(event: CustomEvent<string>) {
    const messageId = event.detail;
    if (selectedMessages.includes(messageId)) {
      selectedMessages = selectedMessages.filter(id => id !== messageId);
    } else {
      selectedMessages = [...selectedMessages, messageId];
    }
  }

  function handleToggleSelectionMode() {
    selectionMode = !selectionMode;
    selectedMessages = [];
  }

  async function handleDeleteSelected() {
    if (selectedMessages.length === 0) return;
    if (!confirm(`Delete ${selectedMessages.length} message(s)?`)) return;

    const failures: string[] = [];
    for (const messageId of selectedMessages) {
      try {
        await deleteMessage(messageId);
        await deleteCachedPlaintext(messageId);
        await deleteCachedPlaintext(`${messageId}:attachment-key`);
      } catch (e: any) {
        failures.push(e.message);
      }
    }

    selectedMessages = [];
    selectionMode = false;
    await loadMessages();
    if (failures.length > 0) {
      alert(`${failures.length} message(s) couldn't be deleted: ${[...new Set(failures)].join('; ')}`);
    }
  }

  function handleUserClick(userId: string) {
    dispatch('userClicked', userId);
  }

  // Whether the view is at (or near) the newest message. New messages only
  // pull the view down while it is, so reading older history isn't interrupted.
  let nearBottom = true;

  // Jump to the newest message once it's rendered, and again shortly after in
  // case images change the height, unless the user has scrolled up meanwhile.
  // `force` is for opening a channel and sending your own message.
  async function scrollToBottom(force = false) {
    if (!force && !nearBottom) return;
    await tick();
    if (!container) return;
    container.scrollTop = container.scrollHeight;
    nearBottom = true;
    setTimeout(() => {
      if (container && nearBottom) container.scrollTop = container.scrollHeight;
    }, 150);
  }
</script>

<div class="flex-1 min-w-0 flex flex-col bg-black border-l-2 border-[#00ff00]">
  <!-- Header -->
  <div class="h-12 border-b-2 border-[#00ff00] flex items-center px-4 gap-2">
    <!-- Mobile only: chat is its own full-screen pane there (see
         App.svelte), so it needs its own way back to the channel list. -->
    <button
      type="button"
      class="md:hidden w-7 h-7 flex-shrink-0 flex items-center justify-center border border-[#00ff00] text-[#00ff00] hover:bg-[#00ff00] hover:text-black transition-all terminal-glow"
      aria-label="Back to channels"
      on:click={() => dispatch('back')}
    >
      ←
    </button>

    <!-- Which channel this is now shows only via the highlighted row in the
         channel list, not here -- this spacer just keeps the buttons below
         pinned to the right edge like before. -->
    <div class="flex-1"></div>

    {#if pinnedCount > 0}
      <button
        type="button"
        class="w-7 h-7 flex-shrink-0 flex items-center justify-center border border-[#00ff00] text-xs transition-all terminal-glow {showPinnedOnly ? 'bg-[#00ff00] text-black' : 'text-[#00ff00] hover:bg-[#00ff00] hover:text-black'}"
        title={showPinnedOnly ? 'Show all messages' : `Show only pinned messages (${pinnedCount})`}
        aria-label={showPinnedOnly ? 'Show all messages' : `Show only pinned messages, ${pinnedCount} pinned`}
        aria-pressed={showPinnedOnly}
        on:click={() => (showPinnedOnly = !showPinnedOnly)}
      >
        📌
      </button>
    {/if}

    <button
      type="button"
      class="w-7 h-7 flex-shrink-0 flex items-center justify-center border border-[#00ff00] text-xs transition-all terminal-glow {searchOpen ? 'bg-[#00ff00] text-black' : 'text-[#00ff00] hover:bg-[#00ff00] hover:text-black'}"
      title={searchOpen ? 'Close search' : 'Search this channel'}
      aria-label={searchOpen ? 'Close search' : 'Search this channel'}
      aria-pressed={searchOpen}
      on:click={toggleSearch}
    >
      🔍
    </button>

    <button
      type="button"
      class="px-3 py-1 border border-[#00ff00] text-[#00ff00] text-xs hover:bg-[#00ff00] hover:text-black transition-all terminal-glow"
      on:click={handleToggleSelectionMode}
    >
      {selectionMode ? 'Cancel' : 'Select'}
    </button>

    {#if selectionMode && selectedMessages.length > 0}
      <button
        type="button"
        class="px-3 py-1 border border-red-500 text-red-500 text-xs hover:bg-red-500 hover:text-black transition-all terminal-glow"
        on:click={handleDeleteSelected}
      >
        Delete ({selectedMessages.length})
      </button>
    {/if}

    <button
      type="button"
      class="px-3 py-1 border border-[#00ff00] text-xs transition-all terminal-glow {showRoster ? 'bg-[#00ff00] text-black' : 'text-[#00ff00] hover:bg-[#00ff00] hover:text-black'}"
      title={showRoster ? 'Hide member list' : 'Show member list'}
      on:click={() => dispatch('toggleRoster')}
    >
      Members
    </button>
  </div>

  {#if searchOpen}
    <div class="border-b-2 border-[#00ff00] bg-[#0a0e0a] p-3">
      <input
        type="text"
        bind:this={searchInput}
        bind:value={searchQuery}
        placeholder="Search this channel's messages..."
        class="w-full bg-black border border-[#00ff00] px-2 py-1 text-sm text-[#00ff00] focus:outline-none"
      />
      {#if searchQuery.trim()}
        <div class="mt-2 max-h-64 overflow-y-auto">
          {#if searchLoadingHistory}
            <div class="text-xs text-[#00aa00] animate-pulse py-2">{'>'} Loading this channel's history to search it...</div>
          {:else if searchResults.length === 0}
            <div class="text-xs text-[#00aa00] py-2">No matches in this channel's decrypted history.</div>
          {:else}
            {#each searchResults as result (result.id)}
              <button
                type="button"
                class="block w-full text-left px-2 py-1 text-xs text-[#00ff00] hover:bg-[rgba(0,255,0,0.1)] border-b border-[#00aa00]/30 last:border-b-0"
                on:click={() => jumpToSearchResult(result.id)}
              >
                <span class="text-[#00aa00]">{formatTime(result.created_at)}</span> — {result.content}
              </button>
            {/each}
          {/if}
        </div>
      {/if}
    </div>
  {/if}

  <!-- Messages -->
  <div class="flex-1 overflow-y-auto p-4 custom-scrollbar messages-container" bind:this={container} on:scroll={onScroll}>
    {#if panelError}
      <div class="flex items-center justify-center h-full text-red-500 text-sm text-center px-4" role="alert">
        {panelError}
      </div>
    {:else if loading}
      <div class="flex items-center justify-center h-full">
        <div class="text-[#00aa00] animate-pulse terminal-glow">{'>'} Loading messages...</div>
      </div>
    {:else if messages.length === 0}
      <div class="flex flex-col items-center justify-center h-full text-[#00aa00] terminal-glow">
        <div class="text-4xl mb-4">💬</div>
        <div class="text-sm">{'>'} No messages yet. Start the conversation!</div>
      </div>
    {:else}
      {#if !showPinnedOnly}
        <div class="text-center text-xs text-[#00aa00] py-2">
          {#if loadingOlder}
            <span class="animate-pulse">{'>'} Loading older messages...</span>
          {:else if hasMore}
            <button type="button" class="underline hover:text-[#00ff00]" on:click={loadOlder}>Load older messages</button>
          {:else}
            {'>'} This is the beginning of the channel.
          {/if}
        </div>
      {/if}
      <div class="space-y-1">
        {#each visibleMessages as message, i (message.id)}
          {@const prev = visibleMessages[i - 1]}
          {@const showHeader = i === 0 || prev.user_id !== message.user_id || !!prev.is_hidden}
          <MessageItem
            {message}
            currentUserId={currentUser?.id ?? ''}
            mentionUsernames={mentionUsernamesFor(message)}
            {canModerate}
            {showHeader}
            {selectionMode}
            isSelected={selectedMessages.includes(message.id)}
            isHighlighted={highlightedMessageId === message.id}
            on:select={handleSelectMessage}
            on:userClicked={(e) => handleUserClick(e.detail)}
            on:toggleReaction={handleToggleReaction}
            on:pin={handlePin}
            on:pinVisibility={handlePinVisibility}
            on:lock={handleLock}
            on:hide={handleHide}
            on:unhide={handleUnhide}
            on:delete={(e) => (pendingDelete = e.detail)}
            on:edit={handleEdit}
          />
        {/each}
      </div>
    {/if}
  </div>

  <!-- Input Area -->
  <div class="border-t-2 border-[#00ff00] p-4">
    {#if typingDisplayNames.length > 0}
      <div class="mb-1 text-xs text-[#00aa00] italic animate-pulse" aria-live="polite">
        {#if typingDisplayNames.length === 1}
          {typingDisplayNames[0]} is typing...
        {:else if typingDisplayNames.length === 2}
          {typingDisplayNames[0]} and {typingDisplayNames[1]} are typing...
        {:else}
          Several people are typing...
        {/if}
      </div>
    {/if}
    {#if attachmentFile}
      <div class="mb-2 flex items-center gap-2 text-xs text-[#00aa00] bg-[#0a0e0a] p-2 rounded border border-[#00ff00]">
        <span class="truncate flex-1">📎 {attachmentFile.name}</span>
        <button type="button" class="text-red-500 hover:text-red-400 font-bold" on:click={clearAttachment}>✕</button>
      </div>
    {/if}

    {#if slowmodeSecondsLeft > 0}
      <div class="mb-1 text-xs text-[#ffaa00]">
        {'>'} Slowmode: wait {slowmodeSecondsLeft}s before sending another message here
      </div>
    {/if}
    <form on:submit={handleSendMessage} class="flex gap-2">
      <!-- File Upload Button -->
      <label class="cursor-pointer px-3 py-2 border border-[#00ff00] text-[#00ff00] hover:bg-[#00ff00] hover:text-black transition-all terminal-glow flex items-center justify-center" title="Attach File">
        <svg xmlns="http://www.w3.org/2000/svg" class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15.172 7l-6.586 6.586a2 2 0 102.828 2.828l6.414-6.586a4 4 0 00-5.656-5.656l-6.415 6.585a6 6 0 108.486 8.486L20.5 13" />
        </svg>
        <input type="file" class="hidden" accept="image/*,video/*,.pdf,.txt" on:change={handleFileSelect} disabled={sending || !canSend} />
      </label>

      <!-- Emoji Picker -->
      <InlineEmojiPicker on:select={insertEmoji} />

      <!-- Text Input -->
      <input
        bind:this={messageInput}
        bind:value={newMessage}
        type="text"
        class="flex-1 min-w-0 bg-[#0a0e0a] border border-[#00ff00] px-4 py-2 text-[#00ff00] focus:outline-none focus:shadow-[0_0_10px_rgba(0,255,0,0.3)]"
        placeholder={canSend ? 'Type a message...' : 'Encrypted messaging unavailable'}
        disabled={sending || !canSend}
        on:input={() => newMessage.trim() && notifyTypingInChannel(channelId)}
      />

      <!-- Send Button -->
      <button
        type="submit"
        disabled={sending || !canSend || slowmodeSecondsLeft > 0 || (!newMessage.trim() && !attachmentFile)}
        class="px-6 py-2 bg-[#00ff00] text-black font-bold hover:bg-[#00aa00] transition-all terminal-glow disabled:opacity-50 disabled:cursor-not-allowed"
      >
        {sending ? '...' : slowmodeSecondsLeft > 0 ? `${slowmodeSecondsLeft}s` : 'Send'}
      </button>
    </form>
  </div>
</div>

{#if pendingDelete}
  <ConfirmModal
    title="Delete message"
    message="Delete this message? This can't be undone."
    confirmText="Delete"
    on:confirm={confirmDelete}
    on:cancel={() => (pendingDelete = null)}
  />
{/if}

{#if pendingReveal}
  <ConfirmModal
    title="Reveal pinned message"
    variant="warning"
    message={"This stores a readable copy of this message on the server, so anyone who can view this channel -- including a member who joins later -- can read it, even though it's normally end-to-end encrypted.\n\nThis stays in effect only while the message is pinned; hiding it again or unpinning it removes the readable copy."}
    confirmText="Reveal it"
    on:confirm={confirmReveal}
    on:cancel={() => (pendingReveal = null)}
  />
{/if}

{#if pendingUnpin}
  <ConfirmModal
    title="Unpin message"
    variant="danger"
    message={pendingUnpin.warning}
    confirmText="Unpin and delete"
    on:confirm={confirmUnpin}
    on:cancel={() => (pendingUnpin = null)}
  />
{/if}
