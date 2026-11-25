<script lang="ts">
  import { onMount, onDestroy, tick, createEventDispatcher } from 'svelte';
  import { wsClient } from '../lib/websocket';
  import {
    type ConversationMessage,
    type MessageRecipientEntry,
    fetchConversationMessages,
    sendDirectMessage,
    SendDirectMessageError,
  } from '../lib/conversations';
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
  import { encryptMessage, decryptMessage, RatchetNotSupportedError, type RatchetEnvelope } from '../lib/ratchet';
  import { activeDeviceKeypair, deviceEncryptionReady } from '../lib/recovery';
  import { fetchParticipantDevices, type ParticipantDevice } from '../lib/devices';
  import { uploadFile } from '../lib/messages';
  import { fileUrl } from '../lib/api';
  import { withTimeout, TimeoutError } from '../lib/timeout';
  import { startCall } from '../lib/calls';

  // --- DM-specific error boundary -----------------------------------------
  //
  // Svelte 4 has no `<svelte:boundary>` (that's a Svelte 5 feature), so
  // this component is its own error boundary: every path that could throw
  // -- device setup, network calls, decryption -- is wrapped in try/catch
  // right here, and any failure is funneled into `panelError` instead of
  // being allowed to escape as an uncaught exception during a reactive
  // update (which, in Svelte, can propagate well beyond this component and
  // take down the rest of the app). `panelError` being set swaps the WHOLE
  // conversation view for a plain, specific "unavailable" message -- see
  // the template below -- while everything outside this component (the
  // server rail, channel list, every other chat surface) stays completely
  // unaffected, since none of it depends on anything this component does.
  //
  // `describeCryptoError` is what keeps this from flattening every failure
  // into one generic message: a broken libsodium load, a broken device
  // registration, and a plain network timeout are reported distinctly,
  // instead of a real bug quietly reading the same as "not set up yet".
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

  export let conversationId: string;
  export let participantId: string = '';
  export let participantUsername: string = '';
  export let participantPublicKey: string | null | undefined = null;

  const dispatch = createEventDispatcher();
  // No longer read in this component now that the sending device's own
  // current device is treated like any other recipient device (see
  // `encryptAndSend`) -- kept only because the parent passes it uniformly
  // to every chat-area-like component.
  export const currentUser: { id: string } | null = null;

  // A message as actually rendered: either the original fetched/received
  // message (for plaintext history) or that same message with its content
  // replaced by the decrypted plaintext (or a failure placeholder).
  type DisplayMessage = ConversationMessage & { displayContent: string };

  // Source of truth, exactly as fetched/received -- never mutated with
  // decrypted content, so re-deriving `messages` below is always correct.
  let rawMessages: ConversationMessage[] = [];
  let loading = true;
  let newMessage = '';
  let sending = false;

  /** A file picked in the compose box, waiting to be encrypted and sent
   * with the next message. Cleared on send (success or failure) and when
   * the user removes it explicitly. */
  let selectedFile: File | null = null;
  let fileInputEl: HTMLInputElement;
  /** Set when a selected file is rejected client-side (too large) --
   * shown next to the compose box; distinct from `panelError` since
   * nothing else about the panel is affected. */
  let attachmentError: string | null = null;
  /** Mirrors the server's own cap (`MAX_ATTACHMENT_BYTES` in
   * `access.rs`) so an oversized file is rejected immediately instead of
   * only after encrypting and uploading it. */
  const MAX_ATTACHMENT_BYTES = 100 * 1024 * 1024;

  const ATTACHMENT_FETCH_TIMEOUT_MS = 30_000;

  /** Per-message decryption state for an encrypted attachment, keyed by
   * message id. Populated lazily (see `ensureAttachmentDecrypted`) rather
   * than for every attachment in a loaded page up front, since decrypting
   * is real work (a network fetch plus two crypto operations) that most
   * messages in a long history don't need right away. */
  type AttachmentState =
    | { status: 'loading' }
    | { status: 'ready'; objectUrl: string; mimeType: string }
    | { status: 'error'; message: string };
  let attachmentState: Record<string, AttachmentState> = {};
  /** Object URLs created for decrypted attachments, revoked on destroy so
   * this component never leaks them for the lifetime of the whole app. */
  const createdObjectUrls: string[] = [];

  /** Per-message decryption state for a message sent via `ratchet.ts`
   * (one recipient entry carrying `ratchet_header_json`), keyed by message
   * id. Needed because `ratchet.ts`'s `decryptMessage` is async (it may
   * need to recover a session from its server-side backup, or bootstrap
   * one as responder) while `toDisplayMessage` below runs synchronously
   * inside a reactive block -- same lazy-populate-then-rerender pattern as
   * `attachmentState` above, just for message text instead of a file. */
  type RatchetDecryptState = { status: 'loading' } | { status: 'done'; text: string | null };
  let ratchetDecryptState: Record<string, RatchetDecryptState> = {};
  const RATCHET_DECRYPTING_PLACEHOLDER = 'Decrypting…';

  /** Set the moment ANY part of this panel's setup hits an unrecoverable
   * failure (crypto library, device setup, or an unexpected exception
   * while preparing messages for display). Non-null means the template
   * below shows a plain error state instead of the chat UI -- see the
   * error-boundary note above. Deliberately never cleared automatically:
   * the fixes for all of these (reload, fix the webview/network, etc.)
   * require a fresh component instance anyway, which happens naturally
   * when the user picks a different conversation or reopens this one. */
  let panelError: string | null = null;

  /** Separately tracks a failure to fetch the OTHER participant's device
   * list, so that's never confused with "they haven't set up encrypted
   * messaging" (`participantDevices.some(d => !d.is_me)` being false for a
   * perfectly innocent reason) -- see `loadParticipantDevices` and the
   * input-area notice below. Sending stays blocked either way; this only
   * changes which message is shown. */
  let participantDevicesLoadFailed = false;

  /** This device's own X25519 private key and id, set once
   * `deviceEncryptionReady` resolves. Goes through the SAME shared gate
   * `App.svelte` uses -- never `ensureDeviceKeypair()` directly -- so
   * opening a DM while the recovery-backup check is still in flight waits
   * on that same check instead of racing ahead and generating a throwaway
   * key (see `lib/recovery.ts`). */
  let myPrivateKey: string | null = null;
  let myDeviceId: string | null = null;
  deviceEncryptionReady()
    .then(kp => { myPrivateKey = kp.privateKey; myDeviceId = kp.deviceId; })
    .catch(e => {
      console.error('Failed to set up encryption keys:', e);
      panelError = describeCryptoError(e);
    });

  // Keeps this device's key in sync with LATER changes too, not just the
  // first-ever resolution above -- e.g. the manual "Recover from backup"
  // escape hatch in Account Settings, which can run while this component
  // is already mounted and already using the device's OLD key. A `Promise`
  // (like `deviceEncryptionReady()`) can only ever resolve once, so that
  // case is only visible through this reactive store (see
  // `replaceActiveKeypair` in `lib/recovery.ts`); subscribing to it means
  // an open conversation picks up the recovered key immediately, with no
  // reload required.
  // Tracks which device_id this component has already seen from
  // `activeDeviceKeypair`, so the reactive block below can tell the store's
  // very FIRST settling (the normal initial resolution, already handled by
  // `loadMessages()`'s own `await deviceEncryptionReady()`) apart from a
  // LATER change to a *different* device_id (only possible via the manual
  // "Recover from backup" escape hatch's `replaceActiveKeypair()` -- see
  // `lib/recovery.ts`). `null` means "haven't seen a value yet"; it's never
  // reassigned to `null` afterward, so a same-value re-set (there isn't one
  // today, but belt-and-suspenders) can't be mistaken for a real change.
  let lastSeenDeviceId: string | null = null;

  $: if ($activeDeviceKeypair) {
    myPrivateKey = $activeDeviceKeypair.privateKey;
    myDeviceId = $activeDeviceKeypair.deviceId;
    if (lastSeenDeviceId !== null && lastSeenDeviceId !== $activeDeviceKeypair.deviceId) {
      // The device identity changed out from under an already-loaded
      // conversation. Swapping the key in-place (above) is enough for
      // decryption going forward, but `rawMessages` itself is stale: it
      // was fetched from the history endpoint filtered to the OLD
      // device_id (see `get_conversation_messages`'s `device_id_filter` in
      // `conversations.rs`), so every message's `recipients` array simply
      // never has an entry for the newly-active device_id -- that data was
      // never requested. Only a full refetch, now filtered to the new id,
      // can recover it.
      void loadMessages();
    }
    lastSeenDeviceId = $activeDeviceKeypair.deviceId;
  }

  const DECRYPT_FAILED_PLACEHOLDER = '[Unable to decrypt this message]';
  const SENT_BEFORE_DEVICE_ADDED_PLACEHOLDER = '[Sent before this device was added]';
  const UNEXPECTED_MESSAGE_ERROR_PLACEHOLDER = '[This message could not be displayed due to an unexpected error]';

  // Decrypting a message depends on which model it was sent under:
  // - Not encrypted: show `content` as-is.
  // - Legacy (single-device-era): `is_encrypted` true, `content` set.
  //   Decrypt with (the OTHER participant's public key, MY OWN private
  //   key) -- X25519 key agreement is symmetric, so this works whether we
  //   sent it or received it.
  // - Fan-out (new multi-device model): `is_encrypted` true, `content`
  //   null. Look for the entry in `recipients` addressed to THIS device
  //   and decrypt it with (that entry's sender_public_key, MY OWN private
  //   key). No matching entry means this device wasn't registered yet
  //   when the message was sent -- including for a message THIS device
  //   itself just sent: it encrypts and sends a copy to itself too (see
  //   `encryptAndSend`), so there's always a real `message_recipients` row
  //   for the sending device, decrypted via this exact same path as any
  //   other device.
  // Wrapped in try/catch, unlike the rest of this module's decrypt path:
  // this is called from the `messages` derivation below, which runs during
  // Svelte's reactive update whenever `rawMessages` changes -- a throw here
  // (e.g. `message.recipients` coming back as something other than an
  // array, from a corrupted row or a server bug) would otherwise escape
  // this component entirely rather than just this one message. One bad row
  // degrades to a placeholder on that row alone; it's deliberately NOT
  // escalated to `panelError` (which would take out the whole
  // conversation), since nothing about every other message is affected.
  function toDisplayMessage(message: ConversationMessage, ratchetState: Record<string, RatchetDecryptState>): DisplayMessage {
    try {
      if (!message.is_encrypted) {
        return { ...message, displayContent: message.content ?? '' };
      }
      if (!myPrivateKey) {
        return { ...message, displayContent: DECRYPT_FAILED_PLACEHOLDER };
      }
      if (message.content !== null && message.content !== undefined) {
        // Legacy single-device-era message.
        if (!participantPublicKey || !message.nonce) {
          return { ...message, displayContent: DECRYPT_FAILED_PLACEHOLDER };
        }
        const decrypted = decryptFromSender(message.content, message.nonce, participantPublicKey, myPrivateKey);
        return { ...message, displayContent: decrypted ?? DECRYPT_FAILED_PLACEHOLDER };
      }
      // Fan-out message: find this device's own entry. Guards against
      // `recipients` being present but not actually an array (malformed
      // row) -- `?.find` alone wouldn't catch that, since a non-array
      // truthy value still passes the `?.` check and only throws once
      // `.find` is actually called.
      const recipients = Array.isArray(message.recipients) ? message.recipients : [];
      const mine = myDeviceId ? recipients.find(r => r.device_id === myDeviceId) : undefined;
      if (!mine) {
        return { ...message, displayContent: SENT_BEFORE_DEVICE_ADDED_PLACEHOLDER };
      }
      if (mine.ratchet_header_json) {
        // Decrypted asynchronously by `ensureRatchetMessageDecrypted`,
        // kicked off by the reactive block below -- this function itself
        // stays synchronous and just reads whatever's been populated so
        // far, same pattern `ensureAttachmentDecrypted` uses for files.
        const state = ratchetState[message.id];
        if (!state || state.status === 'loading') {
          return { ...message, displayContent: RATCHET_DECRYPTING_PLACEHOLDER };
        }
        return { ...message, displayContent: state.text ?? DECRYPT_FAILED_PLACEHOLDER };
      }
      const decrypted = decryptFromSender(mine.ciphertext, mine.nonce, mine.sender_public_key, myPrivateKey);
      return { ...message, displayContent: decrypted ?? DECRYPT_FAILED_PLACEHOLDER };
    } catch (e) {
      console.error('Unexpected error while preparing a DM for display:', e);
      return { ...message, displayContent: UNEXPECTED_MESSAGE_ERROR_PLACEHOLDER };
    }
  }

  /** Decrypts one ratchet-encrypted message's text and stores the result in
   * `ratchetDecryptState`, triggering `toDisplayMessage` to re-render it on
   * the next reactive pass (see the `messages` derivation below, which
   * reads `ratchetDecryptState` directly so Svelte tracks it as a
   * dependency). Needs `participantDevices` to map the entry's
   * `sender_public_key` back to a device id -- `ratchet.ts`'s
   * `decryptMessage` is keyed by device id, not public key, since a
   * session is per (device, peer device), not per public key. */
  async function ensureRatchetMessageDecrypted(message: ConversationMessage, mine: MessageRecipientEntry): Promise<void> {
    ratchetDecryptState = { ...ratchetDecryptState, [message.id]: { status: 'loading' } };
    try {
      let senderDeviceId = participantDevices.find(d => d.public_key === mine.sender_public_key)?.device_id;
      if (!senderDeviceId) {
        // `participantDevices` is a point-in-time snapshot (fetched once on
        // mount/conversation-select -- see `loadParticipantDevices`), with
        // no live push when the OTHER participant registers a device mid-
        // session: there's no "device added" WebSocket event, unlike every
        // other piece of conversation state here. The SEND path already
        // self-heals from this exact staleness (a 400 naming the unknown
        // device_id triggers a `loadParticipantDevices()` retry -- see
        // `isStaleDeviceListError` below); the RECEIVE path had no
        // equivalent, so a message legitimately encrypted for a just-added
        // sender device looked permanently undecryptable even though
        // nothing is actually wrong -- a fresh fetch would have resolved
        // it. One retry, not a loop: if the device still isn't known after
        // refetching, it really doesn't exist (removed, or a bogus
        // sender_public_key), and this message stays undecryptable.
        await loadParticipantDevices();
        senderDeviceId = participantDevices.find(d => d.public_key === mine.sender_public_key)?.device_id;
      }
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
      ratchetDecryptState = { ...ratchetDecryptState, [message.id]: { status: 'done', text: plaintext } };
    } catch (e) {
      console.error('Failed to decrypt a ratchet-encrypted direct message:', e);
      ratchetDecryptState = { ...ratchetDecryptState, [message.id]: { status: 'done', text: null } };
    }
  }

  // Re-derived whenever the raw messages, our key, or their key changes --
  // e.g. `myPrivateKey` arriving asynchronously after messages were already
  // loaded shouldn't leave them stuck showing the decrypt-failed placeholder.
  //
  // The `map` itself is also guarded: `toDisplayMessage` already catches
  // per-message, but this is the last line of defense against anything
  // escaping it (or failing some other way, e.g. `rawMessages` itself ever
  // becoming something unexpected) during Svelte's reactive update --
  // which is exactly the kind of uncaught exception that could otherwise
  // propagate past this component. See the error-boundary note above.
  let messages: DisplayMessage[] = [];
  $: {
    try {
      messages = rawMessages.map(m => toDisplayMessage(m, ratchetDecryptState));
    } catch (e) {
      console.error('Unexpected error building the DM message list:', e);
      messages = [];
      if (!panelError) panelError = 'Encrypted messaging is currently unavailable due to an unexpected error.';
    }
  }

  // Kicks off `ensureRatchetMessageDecrypted` for any ratchet-encrypted
  // message not yet attempted. Gated on `participantDevices` actually
  // being loaded (needed to resolve a sender's device id -- see that
  // function) so a message isn't permanently marked "failed" just because
  // this ran before `loadParticipantDevices()` finished.
  $: {
    if (myDeviceId && participantDevices.length > 0) {
      for (const m of rawMessages) {
        if (!m.is_encrypted || (m.content !== null && m.content !== undefined)) continue;
        const recipients = Array.isArray(m.recipients) ? m.recipients : [];
        const mine = recipients.find(r => r.device_id === myDeviceId);
        if (mine?.ratchet_header_json && !ratchetDecryptState[m.id]) {
          void ensureRatchetMessageDecrypted(m, mine);
        }
      }
    }
  }

  // Decrypting an attachment is real work (a network fetch plus unwrapping
  // the file key and decrypting the blob), so it's done lazily, once per
  // message, rather than for every attachment in a loaded page up front.
  // Re-runs whenever `messages` changes (new page loaded, new message
  // arrived, or `myPrivateKey`/`myDeviceId` just became available) and
  // kicks off decryption for anything not already attempted.
  $: {
    for (const m of messages) {
      if (m.attachment_url && m.is_encrypted && m.attachment_nonce && !attachmentState[m.id]) {
        void ensureAttachmentDecrypted(m);
      }
    }
  }

  async function ensureAttachmentDecrypted(message: DisplayMessage): Promise<void> {
    // Claim this message immediately (before any `await`) so the reactive
    // block above never starts a second, overlapping decrypt for the same
    // message while the first is still in flight.
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
      const fileKey = unwrapFileKey(mine.attachment_key_ciphertext, mine.attachment_key_nonce, mine.sender_public_key, myPrivateKey);
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
      // `.slice()` copies into a fresh, exact-sized `ArrayBuffer` -- `Blob`'s
      // type signature doesn't accept the more general `ArrayBufferLike`
      // (which also covers `SharedArrayBuffer`) a typed array's `.buffer`
      // normally has.
      const blob = new Blob([plaintextBytes.slice()], { type: mimeType });
      const objectUrl = URL.createObjectURL(blob);
      createdObjectUrls.push(objectUrl);
      attachmentState = { ...attachmentState, [message.id]: { status: 'ready', objectUrl, mimeType } };
    } catch (e) {
      console.error('Unexpected error decrypting a DM attachment:', e);
      fail(e instanceof TimeoutError ? e.message : 'Failed to decrypt attachment');
    }
  }

  // History is loaded a page at a time; scrolling to the top loads more.
  const PAGE_SIZE = 50;
  let container: HTMLDivElement;
  let hasMore = false;
  let loadingOlder = false;

  // Every registered device of both participants, fetched fresh for each
  // conversation -- the sending client needs this to know exactly which
  // devices to encrypt a copy for (see `handleSendMessage`), and to decide
  // whether sending is even possible at all (the other participant must
  // have at least one device registered).
  let participantDevices: ParticipantDevice[] = [];

  $: if (conversationId) {
    loadMessages();
    loadParticipantDevices();
  }

  async function loadParticipantDevices() {
    const forConversation = conversationId;
    try {
      const devices = await fetchParticipantDevices(forConversation);
      if (forConversation !== conversationId) return;
      participantDevices = devices;
      participantDevicesLoadFailed = false;
    } catch (e) {
      if (forConversation !== conversationId) return;
      console.error('Failed to load participant devices:', e);
      // Leaves `participantDevices` empty, same as before -- `canSend`
      // below still blocks sending either way -- but flags the specific
      // reason (a failed/timed-out lookup) so the input area doesn't
      // falsely tell the user the other participant has no encrypted
      // devices at all when we simply couldn't check.
      participantDevices = [];
      participantDevicesLoadFailed = true;
    }
  }

  function onNewDirectMessage(data: ConversationMessage) {
    if (data.conversation_id !== conversationId) return;
    addMessage(data);
    scrollToBottom();
  }

  // The sender gets their message both from the POST response and from the
  // WebSocket broadcast, so skip ids we already have.
  function addMessage(message: ConversationMessage) {
    if (rawMessages.some(m => m.id === message.id)) return;
    rawMessages = [...rawMessages, message];
  }

  onMount(() => {
    wsClient.connect();
    wsClient.on('new_direct_message', onNewDirectMessage);
  });

  onDestroy(() => {
    wsClient.off('new_direct_message', onNewDirectMessage);
    for (const url of createdObjectUrls) URL.revokeObjectURL(url);
  });

  async function loadMessages() {
    const forConversation = conversationId;
    loading = true;
    hasMore = false;
    try {
      // Wait for this device's own id before fetching: without it, every
      // fan-out message in the page would come back with no ciphertext at
      // all (same as an unrecognized device id -- see `HistoryQuery`),
      // which would needlessly show "sent before this device was added"
      // for messages this device can actually read.
      const { deviceId } = await deviceEncryptionReady();
      if (forConversation !== conversationId) return;
      const fetched = await fetchConversationMessages(forConversation, { limit: PAGE_SIZE, deviceId });
      if (forConversation !== conversationId) return;
      rawMessages = fetched;
      hasMore = fetched.length === PAGE_SIZE;
      loading = false;
      await scrollToBottom(true);
    } catch (e) {
      if (forConversation !== conversationId) return;
      console.error('Failed to load messages:', e);
      loading = false;
      // Both failure points above (`deviceEncryptionReady()` and
      // `fetchConversationMessages()`, which now has its own bounded
      // timeout -- see `lib/conversations.ts`) land here. Previously, a
      // failed `fetchConversationMessages()` call with `myPrivateKey`
      // already set just silently left the history empty (indistinguishable
      // from "no messages yet"), and a hung network call left `loading`
      // (and the "Loading messages..." spinner) stuck forever with no
      // bound at all. Now that the fetch itself can't hang indefinitely,
      // always surface a clear, specific error here instead of a
      // misleadingly empty conversation.
      if (!panelError) panelError = describeCryptoError(e);
    }
  }

  /** Loads the page of messages before the oldest one shown, keeping the view in place. */
  async function loadOlder() {
    if (loadingOlder || !hasMore || rawMessages.length === 0) return;
    const forConversation = conversationId;
    loadingOlder = true;
    try {
      const older = await fetchConversationMessages(forConversation, {
        before: rawMessages[0].id,
        limit: PAGE_SIZE,
        deviceId: myDeviceId,
      });
      if (forConversation !== conversationId) return;
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

  // Whether the view is at (or near) the newest message. New messages only
  // pull the view down while it is, so reading older history isn't interrupted.
  let nearBottom = true;

  function onScroll() {
    if (!container) return;
    nearBottom = container.scrollHeight - container.scrollTop - container.clientHeight < 80;
    if (loading) return;
    if (container.scrollTop < 120) loadOlder();
  }

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

  // Encrypts `content` for one recipient device, preferring the Double
  // Ratchet (`ratchet.ts`) when that device supports it -- forward secrecy
  // and post-compromise security beat the legacy stateless scheme whenever
  // it's available -- and falling back to the legacy per-device key
  // (`crypto.ts`) when it doesn't (no published signed prekey yet).
  // `ratchetHeaderJson` carries the envelope's non-ciphertext fields (`dh`/
  // `pn`/`n`, plus `initial` on a brand-new session's first message) as one
  // opaque JSON blob the server only stores and returns verbatim -- see
  // migration 0040.
  async function encryptForDevice(
    d: ParticipantDevice,
    content: string
  ): Promise<{ deviceId: string; ciphertext: string; nonce: string; ratchetHeaderJson?: string }> {
    // This device's own entry (the sending device's required copy of its
    // own sent message -- see `encryptAndSend`'s doc comment) is excluded
    // from the ratchet: `ratchet.ts`'s session model is keyed by (device,
    // peer device), and "this device talking to itself" would otherwise
    // bootstrap a degenerate self-session that consumes one of this
    // device's own one-time prekeys for no real benefit -- the plaintext
    // never actually travels anywhere a ratchet session would protect. The
    // legacy per-device key already covers this case exactly as well.
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
      if (!(err instanceof RatchetNotSupportedError)) throw err;
      const { ciphertext, nonce } = encryptForRecipient(content, d.public_key, myPrivateKey as string);
      return { deviceId: d.device_id, ciphertext, nonce };
    }
  }

  // Encrypts `content` and sends it to EVERY device in `devices` --
  // including this device's own current device. There's no
  // special-casing of "my own device" here:
  // the sending device gets a real encrypted copy and a real
  // `message_recipients` row just like every other device, so it decrypts
  // its own sent message the exact same way any other device would (see
  // `toDisplayMessage`). Shared by the initial attempt and the
  // stale-device-list retry below so both encrypt against whatever device
  // list they were actually given.
  async function encryptAndSend(
    content: string,
    devices: ParticipantDevice[],
    file: File | null
  ): Promise<ConversationMessage> {
    // No attachment: exactly the original behavior, one ciphertext per
    // device, nothing attachment-related sent at all -- just now routed
    // through `encryptForDevice` instead of calling `encryptForRecipient`
    // directly, so each device gets the ratchet when it supports one.
    if (!file) {
      const encryptedFor = await Promise.all(devices.map(d => encryptForDevice(d, content)));
      return sendDirectMessage(conversationId, null, null, {
        encryptedFor,
        senderDeviceId: myDeviceId as string,
      });
    }

    // Hybrid encryption (see `lib/crypto.ts`): the file is encrypted ONCE
    // with a fresh random symmetric key, then that small key is wrapped
    // once per recipient device -- same device list, same per-device
    // ciphertext-fan-out as the message text uses, just applied to the key
    // instead of the whole file.
    const fileBytes = new Uint8Array(await file.arrayBuffer());
    const { ciphertext: fileCiphertext, nonce: attachmentNonce, fileKey } = encryptFileForFanout(fileBytes);

    // The uploaded blob's own Content-Type is deliberately generic
    // (ciphertext isn't a valid image/video/whatever anymore) -- the TRUE
    // original type travels as plaintext message metadata instead (see
    // `attachment_mime_type` below), same tier as the filename always has
    // been on this path (see `send_fanout_message`'s validation in
    // `conversations.rs`, which never treats attachment metadata as
    // something needing per-device encryption).
    const encryptedBlob = new File([fileCiphertext.slice()], file.name, { type: 'application/octet-stream' });
    const uploaded = await uploadFile(encryptedBlob);

    // The attachment's wrapped file key stays on the legacy per-device
    // X25519 scheme regardless of whether the message TEXT goes through
    // the ratchet -- it's a one-shot key wrap for a blob that's already
    // uploaded and shared across every recipient, not an evolving message
    // stream, so there's no forward-secrecy benefit to ratcheting it, and
    // keeping it independent avoids coupling the attachment path to
    // whether a session happens to exist yet.
    const encryptedFor = await Promise.all(
      devices.map(async d => {
        const textResult = await encryptForDevice(d, content);
        const wrapped = wrapFileKey(fileKey, d.public_key, myPrivateKey as string);
        return { ...textResult, attachmentKeyCiphertext: wrapped.ciphertext, attachmentKeyNonce: wrapped.nonce };
      })
    );

    return sendDirectMessage(
      conversationId,
      null,
      { url: uploaded.url, filename: file.name, size: file.size, mime_type: file.type || 'application/octet-stream' },
      {
        encryptedFor,
        senderDeviceId: myDeviceId as string,
        attachmentNonce,
      }
    );
  }

  // Whether a failed send was caused by `participantDevices` going stale
  // (the other participant added/removed a device while this chat stayed
  // open) -- the server rejects the whole send with a 400 naming the bad
  // `device_id` in that case (see `send_fanout_message`'s validation).
  function isStaleDeviceListError(e: unknown): boolean {
    return (
      e instanceof SendDirectMessageError &&
      e.status === 400 &&
      !!e.serverMessage &&
      e.serverMessage.includes('device_id')
    );
  }

  function pickFile() {
    attachmentError = null;
    fileInputEl?.click();
  }

  function onFileChosen(e: Event) {
    const file = (e.target as HTMLInputElement).files?.[0] ?? null;
    attachmentError = null;
    if (file && file.size > MAX_ATTACHMENT_BYTES) {
      attachmentError = `File exceeds the ${Math.floor(MAX_ATTACHMENT_BYTES / (1024 * 1024))}MB size limit`;
      selectedFile = null;
    } else {
      selectedFile = file;
    }
    // Reset so choosing the exact same file again still fires `change`.
    (e.target as HTMLInputElement).value = '';
  }

  function clearSelectedFile() {
    selectedFile = null;
    attachmentError = null;
  }

  async function handleSendMessage(e: Event) {
    e.preventDefault();
    const content = newMessage.trim();
    if ((!content && !selectedFile) || sending) return;

    // The single most important invariant: never send plaintext when
    // encryption was supposed to happen. If the other participant has no
    // device registered, or our own keypair isn't ready yet, sending is
    // blocked outright -- there is no silent plaintext fallback.
    if (!canSend || !myPrivateKey || !myDeviceId) return;

    const fileToSend = selectedFile;
    sending = true;
    try {
      // Encrypt once per device that should get a copy: every device of
      // the OTHER participant (mandatory -- skipping any of them leaves
      // that device unable to read this message), every OTHER device of
      // our own (so our other sessions can read what we just sent), AND
      // this device's own current device -- see `encryptAndSend`. Any
      // WebSocket echo of this exact send that arrives before the HTTP
      // response does is handled by nothing more than `addMessage`'s
      // ordinary dedup-by-id, same as it is for every other message.
      let created: ConversationMessage;
      try {
        created = await encryptAndSend(content, participantDevices, fileToSend);
      } catch (err) {
        // `participantDevices` is only fetched once per conversation (see
        // the `conversationId` watcher above), so it goes stale if the
        // other participant adds/removes a device while this window stays
        // open on the same conversation -- refetch and retry exactly once
        // with the fresh list rather than dropping the message outright.
        if (!isStaleDeviceListError(err)) throw err;
        await loadParticipantDevices();
        created = await encryptAndSend(content, participantDevices, fileToSend);
      }
      addMessage(created);
      newMessage = '';
      selectedFile = null;
      scrollToBottom(true);
    } catch (e) {
      console.error('Failed to send direct message:', e);
      if (isStaleDeviceListError(e)) {
        alert("Couldn't send: the recipient's devices changed, please try again");
      } else if (e instanceof CryptoLibraryError || e instanceof DeviceSetupError) {
        // Encryption itself broke mid-session (vs. a network hiccup) --
        // nothing sent, same as every other path here, but worth
        // surfacing as a panel-level failure since retrying "send" again
        // won't help until this is fixed.
        panelError = describeCryptoError(e);
      } else if (e instanceof TimeoutError) {
        // `sendDirectMessage` now has its own bounded timeout (see
        // `lib/conversations.ts`), so this used to be able to hang here
        // forever with `sending` stuck `true` and no feedback at all --
        // the `finally` below still always clears `sending`, but say
        // specifically what happened rather than the generic network-error
        // message, since retrying is very likely to help here.
        alert('Timed out sending message. Please try again.');
      } else {
        alert('Network error while sending message');
      }
    } finally {
      sending = false;
    }
  }

  // Whether we're able to send an encrypted message right now: the other
  // participant must have at least one device registered, our own keypair
  // must have finished loading/generating, AND nothing has gone wrong at
  // the panel level. (`participantDevices` includes our own devices too,
  // so this specifically checks for any entry that ISN'T ours.) The
  // `!panelError` clause is belt-and-suspenders: every path that sets
  // `panelError` already clears/never-sets `myPrivateKey`/`myDeviceId`
  // too, so this alone wouldn't yet be reachable as a false positive --
  // but sending must stay hard-blocked on ANY of these failures, so it's
  // checked explicitly rather than relying on that staying true forever.
  $: canSend = !panelError && !!myPrivateKey && !!myDeviceId && participantDevices.some(d => !d.is_me);

  function formatTime(ts: string): string {
    return new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }
</script>

<div class="flex-1 min-w-0 flex flex-col bg-black border-l-2 border-[#00ff00]">
  <!-- Header -->
  <div class="h-12 border-b-2 border-[#00ff00] flex items-center px-4 gap-2">
    <!-- Mobile only: DMs are their own full-screen pane there (see
         App.svelte), so it needs its own way back to the DM list. -->
    <button
      type="button"
      class="md:hidden w-7 h-7 flex-shrink-0 flex items-center justify-center border border-[#00ff00] text-[#00ff00] hover:bg-[#00ff00] hover:text-black transition-all terminal-glow"
      aria-label="Back to conversations"
      on:click={() => dispatch('back')}
    >
      ←
    </button>

    <div class="flex-1 min-w-0">
      <h3 class="text-sm font-bold text-[#00ff00] terminal-glow truncate">
        {'>'} {participantUsername || 'Direct Message'}
      </h3>
    </div>

    {#if participantId}
      <button
        type="button"
        class="w-7 h-7 flex-shrink-0 flex items-center justify-center border border-[#00ff00] text-[#00ff00] hover:bg-[#00ff00] hover:text-black transition-all terminal-glow"
        aria-label="Voice call"
        title="Voice call"
        on:click={() => startCall(participantId, participantUsername, false)}
      >
        📞
      </button>
      <button
        type="button"
        class="w-7 h-7 flex-shrink-0 flex items-center justify-center border border-[#00ff00] text-[#00ff00] hover:bg-[#00ff00] hover:text-black transition-all terminal-glow"
        aria-label="Video call"
        title="Video call"
        on:click={() => startCall(participantId, participantUsername, true)}
      >
        🎥
      </button>
    {/if}
  </div>

  <!-- Messages -->
  <div class="flex-1 overflow-y-auto p-4 custom-scrollbar messages-container" bind:this={container} on:scroll={onScroll}>
    {#if panelError}
      <!-- The DM-specific error boundary: this swaps out the whole
           conversation view, but only this one -- the server rail, channel
           list, and every other part of the app keep working normally. -->
      <div class="flex flex-col items-center justify-center h-full text-center px-6" role="alert">
        <div class="text-4xl mb-4">⚠</div>
        <div class="text-sm text-[#ffaa00] terminal-glow">{'>'} Encrypted messaging is currently unavailable</div>
        <div class="text-xs text-[#00aa00] mt-2 max-w-md">{panelError}</div>
      </div>
    {:else if loading}
      <div class="flex items-center justify-center h-full">
        <div class="text-[#00aa00] animate-pulse terminal-glow">{'>'} Loading messages...</div>
      </div>
    {:else if messages.length === 0}
      <div class="flex flex-col items-center justify-center h-full text-[#00aa00] terminal-glow">
        <div class="text-4xl mb-4">💬</div>
        <div class="text-sm">{'>'} No messages yet. Say hello!</div>
      </div>
    {:else}
      <div class="text-center text-xs text-[#00aa00] py-2">
        {#if loadingOlder}
          <span class="animate-pulse">{'>'} Loading older messages...</span>
        {:else if hasMore}
          <button type="button" class="underline hover:text-[#00ff00]" on:click={loadOlder}>Load older messages</button>
        {:else}
          {'>'} This is the beginning of your conversation.
        {/if}
      </div>
      <div class="space-y-1">
        {#each messages as message, i (message.id)}
          {@const prev = messages[i - 1]}
          {@const showHeader = i === 0 || prev.user_id !== message.user_id}
          <div class="px-2 py-1 rounded hover:bg-[rgba(0,255,0,0.05)]">
            {#if showHeader}
              <div class="flex items-baseline gap-2">
                <span class="font-bold text-[#00ff00] text-sm terminal-glow">{message.username}</span>
                <span class="text-[10px] text-[#00aa00]">{formatTime(message.created_at)}</span>
                {#if message.is_edited}
                  <span class="text-[10px] text-[#00aa00] italic">(edited)</span>
                {/if}
              </div>
            {/if}
            {#if message.displayContent}
              <div class="text-sm text-[#00dd00] whitespace-pre-wrap break-words">{message.displayContent}</div>
            {/if}
            {#if message.attachment_url && message.is_encrypted && message.attachment_nonce}
              {@const att = attachmentState[message.id]}
              {#if !att || att.status === 'loading'}
                <div class="text-xs text-[#00aa00] mt-1 animate-pulse">{'>'} Decrypting attachment...</div>
              {:else if att.status === 'error'}
                <div class="text-xs text-[#ffaa00] mt-1">{'>'} {att.message}</div>
              {:else if att.mimeType.startsWith('image/')}
                <a href={att.objectUrl} target="_blank" rel="noopener noreferrer" class="block mt-1">
                  <img src={att.objectUrl} alt={message.attachment_filename || 'Attachment'} class="max-w-xs max-h-64 border border-[#00ff00]" />
                </a>
              {:else}
                <a
                  href={att.objectUrl}
                  download={message.attachment_filename || 'attachment'}
                  class="inline-block mt-1 text-xs text-[#00aa00] underline hover:text-[#00ff00]"
                >
                  📎 {message.attachment_filename || 'Attachment'}
                </a>
              {/if}
            {:else if message.attachment_url}
              <!-- Plaintext/legacy attachment -- never produced by this
                   client (every fan-out send encrypts its attachment), but
                   kept so any such row still renders as a plain link
                   rather than silently vanishing. -->
              <a
                href={fileUrl(message.attachment_url)}
                target="_blank"
                rel="noopener noreferrer"
                class="inline-block mt-1 text-xs text-[#00aa00] underline hover:text-[#00ff00]"
              >
                📎 {message.attachment_filename || 'Attachment'}
              </a>
            {/if}
          </div>
        {/each}
      </div>
    {/if}
  </div>

  <!-- Input Area -->
  <div class="border-t-2 border-[#00ff00] p-4">
    {#if panelError}
      <div class="text-xs text-[#ffaa00] mb-2 terminal-glow">{'>'} {panelError}</div>
    {:else if participantDevicesLoadFailed}
      <div class="text-xs text-[#ffaa00] mb-2 terminal-glow">
        {'>'} Couldn't check whether this user has encrypted messaging set up (network error) &mdash; you can't send them a message right now.
      </div>
    {:else if !participantDevices.some(d => !d.is_me)}
      <div class="text-xs text-[#ffaa00] mb-2 terminal-glow">
        {'>'} This user hasn't set up encrypted messaging on any device yet &mdash; you can't send them a message.
      </div>
    {/if}
    {#if attachmentError}
      <div class="text-xs text-[#ffaa00] mb-2 terminal-glow">{'>'} {attachmentError}</div>
    {/if}
    {#if selectedFile}
      <div class="flex items-center gap-2 mb-2 text-xs text-[#00aa00]">
        <span>📎 {selectedFile.name}</span>
        <button
          type="button"
          on:click={clearSelectedFile}
          disabled={sending}
          class="text-[#ffaa00] hover:text-[#ff0000] disabled:opacity-50"
          aria-label="Remove attachment"
        >
          ✕
        </button>
      </div>
    {/if}
    <form on:submit={handleSendMessage} class="flex gap-2">
      <input bind:this={fileInputEl} type="file" class="hidden" on:change={onFileChosen} disabled={sending || !canSend} />
      <button
        type="button"
        on:click={pickFile}
        disabled={sending || !canSend}
        class="px-3 py-2 border border-[#00ff00] text-[#00ff00] hover:bg-[rgba(0,255,0,0.1)] transition-all disabled:opacity-50 disabled:cursor-not-allowed"
        aria-label="Attach file"
      >
        📎
      </button>
      <input
        bind:value={newMessage}
        type="text"
        class="flex-1 min-w-0 bg-[#0a0e0a] border border-[#00ff00] px-4 py-2 text-[#00ff00] focus:outline-none focus:shadow-[0_0_10px_rgba(0,255,0,0.3)] disabled:opacity-50"
        placeholder={canSend ? 'Type a message...' : 'Encrypted messaging unavailable'}
        disabled={sending || !canSend}
      />
      <button
        type="submit"
        disabled={sending || !canSend || (!newMessage.trim() && !selectedFile)}
        class="px-6 py-2 bg-[#00ff00] text-black font-bold hover:bg-[#00aa00] transition-all terminal-glow disabled:opacity-50 disabled:cursor-not-allowed"
      >
        {sending ? '...' : 'Send'}
      </button>
    </form>
  </div>
</div>
