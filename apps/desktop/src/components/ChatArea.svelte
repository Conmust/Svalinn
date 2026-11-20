<script lang="ts">
  import { onMount, onDestroy, createEventDispatcher, tick } from 'svelte';
  import { getAuthHeaders, apiFetch, apiBase } from '../lib/api';
  import { wsClient } from '../lib/websocket';
  import MessageItem from './MessageItem.svelte';
  import InlineEmojiPicker from './InlineEmojiPicker.svelte';
  import ConfirmModal from './ConfirmModal.svelte';
  import {
    type Message,
    deleteMessage, hideMessage, unhideMessage, lockMessage, unlockMessage,
    pinMessage, unpinMessage, addReaction, removeReaction,
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
  let attachmentFile: File | null = null;
  let selectionMode = false;
  let selectedMessages: string[] = [];
  let highlightedMessageId: string | null = null;
  let messageInput: HTMLInputElement;
  let myRole = 'member';
  let showPinnedOnly = false;
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
  function toDisplayMessage(message: Message, attachmentState: Record<string, AttachmentState>): Message {
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
          } else {
            const decrypted = decryptFromSender(mine.ciphertext, mine.nonce, mine.sender_public_key, myPrivateKey);
            displayed = { ...message, content: decrypted ?? DECRYPT_FAILED_PLACEHOLDER };
          }
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

  // Re-derived whenever the raw messages, our key, or an attachment's
  // decryption state changes. The `map` itself is also guarded, as the
  // last line of defense against anything escaping `toDisplayMessage`
  // (see the identical note in `DMChatArea.svelte`).
  let messages: Message[] = [];
  $: {
    try {
      messages = rawMessages.map(m => toDisplayMessage(m, attachmentState));
    } catch (e) {
      console.error('Unexpected error building the channel message list:', e);
      messages = [];
      if (!panelError) panelError = 'Encrypted messaging is currently unavailable due to an unexpected error.';
    }
  }

  // Triggers attachment decryption off the RAW messages (never the
  // already-decrypted `messages` above, which itself depends on
  // `attachmentState` -- scanning that here would be circular).
  $: {
    for (const m of rawMessages) {
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
      const blob = new Blob([plaintextBytes.slice()], { type: mimeType });
      const objectUrl = URL.createObjectURL(blob);
      createdObjectUrls.push(objectUrl);
      attachmentState = { ...attachmentState, [message.id]: { status: 'ready', objectUrl, mimeType } };
    } catch (e) {
      console.error('Unexpected error decrypting a channel attachment:', e);
      fail(e instanceof TimeoutError ? e.message : 'Failed to decrypt attachment');
    }
  }

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
  $: pinnedCount = messages.filter(m => m.is_pinned).length;
  $: if (pinnedCount === 0) showPinnedOnly = false;
  $: visibleMessages = showPinnedOnly ? messages.filter(m => m.is_pinned) : messages;
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
    await (m.is_pinned ? unpinMessage(m.id) : pinMessage(m.id));
    patchMessage(m.id, { is_pinned: !m.is_pinned });
  });

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
  }

  // Named handlers so onDestroy removes only this component's listeners
  // (ChannelList listens to the same events).
  function onNewMessage(data: Message) {
    if (data.channel_id !== channelId) return;
    addMessage(data);
    scrollToBottom();
  }

  function onMessageDeleted(data: { message_id: string }) {
    rawMessages = rawMessages.filter(m => m.id !== data.message_id);
  }

  function onMessageUpdated(data: Message) {
    rawMessages = rawMessages.map(m => m.id === data.id ? { ...m, ...data } : m);
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
  });

  onDestroy(() => {
    wsClient.off('new_message', onNewMessage);
    wsClient.off('message_deleted', onMessageDeleted);
    wsClient.off('message_updated', onMessageUpdated);
    wsClient.off('member_updated', onMemberUpdated);
    for (const url of createdObjectUrls) URL.revokeObjectURL(url);
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
    if (!file) {
      const encryptedFor = devices.map(d => {
        const { ciphertext, nonce } = encryptForRecipient(content, d.public_key, myPrivateKey as string);
        return { deviceId: d.device_id, ciphertext, nonce };
      });
      return sendChannelMessage(channelId, null, { encryptedFor, senderDeviceId: myDeviceId as string });
    }

    // Hybrid encryption, same as the DM attachment flow: the file is
    // encrypted ONCE with a fresh random symmetric key, then that small
    // key is wrapped once per recipient device.
    const fileBytes = new Uint8Array(await file.arrayBuffer());
    const { ciphertext: fileCiphertext, nonce: attachmentNonce, fileKey } = encryptFileForFanout(fileBytes);
    const encryptedBlob = new File([fileCiphertext.slice()], file.name, { type: 'application/octet-stream' });
    const uploaded = await uploadFile(encryptedBlob);

    const encryptedFor = devices.map(d => {
      const { ciphertext, nonce } = encryptForRecipient(content, d.public_key, myPrivateKey as string);
      const wrapped = wrapFileKey(fileKey, d.public_key, myPrivateKey as string);
      return {
        deviceId: d.device_id,
        ciphertext,
        nonce,
        attachmentKeyCiphertext: wrapped.ciphertext,
        attachmentKeyNonce: wrapped.nonce,
      };
    });

    return sendChannelMessage(
      channelId,
      { url: uploaded.url, filename: file.name, size: file.size, mime_type: file.type || 'application/octet-stream' },
      { encryptedFor, senderDeviceId: myDeviceId as string, attachmentNonce }
    );
  }

  // Whether a failed send was caused by `channelMemberDevices` going stale
  // (a member joined/left, or added/removed a device, while this channel
  // stayed open) -- the server rejects the whole send with a 400 naming
  // the bad `device_id` in that case.
  function isStaleDeviceListError(e: unknown): boolean {
    return (
      e instanceof SendChannelMessageError &&
      e.status === 400 &&
      !!e.serverMessage &&
      e.serverMessage.includes('device_id')
    );
  }

  async function handleSendMessage(e: Event) {
    e.preventDefault();
    const content = newMessage.trim();
    if ((!content && !attachmentFile) || sending) return;

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
      } else if (e instanceof CryptoLibraryError || e instanceof DeviceSetupError) {
        panelError = describeCryptoError(e);
      } else if (e instanceof TimeoutError) {
        alert('Timed out sending message. Please try again.');
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
            {canModerate}
            {showHeader}
            {selectionMode}
            isSelected={selectedMessages.includes(message.id)}
            isHighlighted={highlightedMessageId === message.id}
            on:select={handleSelectMessage}
            on:userClicked={(e) => handleUserClick(e.detail)}
            on:toggleReaction={handleToggleReaction}
            on:pin={handlePin}
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
    {#if attachmentFile}
      <div class="mb-2 flex items-center gap-2 text-xs text-[#00aa00] bg-[#0a0e0a] p-2 rounded border border-[#00ff00]">
        <span class="truncate flex-1">📎 {attachmentFile.name}</span>
        <button type="button" class="text-red-500 hover:text-red-400 font-bold" on:click={clearAttachment}>✕</button>
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
        class="flex-1 bg-[#0a0e0a] border border-[#00ff00] px-4 py-2 text-[#00ff00] focus:outline-none focus:shadow-[0_0_10px_rgba(0,255,0,0.3)]"
        placeholder={canSend ? 'Type a message...' : 'Encrypted messaging unavailable'}
        disabled={sending || !canSend}
      />

      <!-- Send Button -->
      <button
        type="submit"
        disabled={sending || !canSend || (!newMessage.trim() && !attachmentFile)}
        class="px-6 py-2 bg-[#00ff00] text-black font-bold hover:bg-[#00aa00] transition-all terminal-glow disabled:opacity-50 disabled:cursor-not-allowed"
      >
        {sending ? '...' : 'Send'}
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
