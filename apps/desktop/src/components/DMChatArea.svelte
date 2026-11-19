<script lang="ts">
  import { onMount, onDestroy, tick } from 'svelte';
  import { wsClient } from '../lib/websocket';
  import {
    type ConversationMessage,
    fetchConversationMessages,
    sendDirectMessage,
    SendDirectMessageError,
  } from '../lib/conversations';
  import { encryptForRecipient, decryptFromSender } from '../lib/crypto';
  import { activeDeviceKeypair, deviceEncryptionReady } from '../lib/recovery';
  import { fetchParticipantDevices, type ParticipantDevice } from '../lib/devices';

  export let conversationId: string;
  export let participantUsername: string = '';
  export let participantPublicKey: string | null | undefined = null;
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
    .catch(e => console.error('Failed to set up encryption keys:', e));

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
  function toDisplayMessage(message: ConversationMessage): DisplayMessage {
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
    // Fan-out message: find this device's own entry.
    const mine = myDeviceId ? message.recipients?.find(r => r.device_id === myDeviceId) : undefined;
    if (!mine) {
      return { ...message, displayContent: SENT_BEFORE_DEVICE_ADDED_PLACEHOLDER };
    }
    const decrypted = decryptFromSender(mine.ciphertext, mine.nonce, mine.sender_public_key, myPrivateKey);
    return { ...message, displayContent: decrypted ?? DECRYPT_FAILED_PLACEHOLDER };
  }

  // Re-derived whenever the raw messages, our key, or their key changes --
  // e.g. `myPrivateKey` arriving asynchronously after messages were already
  // loaded shouldn't leave them stuck showing the decrypt-failed placeholder.
  let messages: DisplayMessage[] = [];
  $: messages = rawMessages.map(toDisplayMessage);

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
    } catch (e) {
      if (forConversation !== conversationId) return;
      console.error('Failed to load participant devices:', e);
      participantDevices = [];
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

  // Encrypts `content` and sends it to EVERY device in `devices` --
  // including this device's own current device. There's no
  // special-casing of "my own device" here:
  // the sending device gets a real encrypted copy and a real
  // `message_recipients` row just like every other device, so it decrypts
  // its own sent message the exact same way any other device would (see
  // `toDisplayMessage`). Shared by the initial attempt and the
  // stale-device-list retry below so both encrypt against whatever device
  // list they were actually given.
  async function encryptAndSend(content: string, devices: ParticipantDevice[]): Promise<ConversationMessage> {
    const encryptedFor = devices.map(d => {
      // A fresh random nonce is generated inside `encryptForRecipient` on
      // every call, including this one for our own device -- never reused
      // across the devices in this same batch.
      const { ciphertext, nonce } = encryptForRecipient(content, d.public_key, myPrivateKey as string);
      return { deviceId: d.device_id, ciphertext, nonce };
    });

    return sendDirectMessage(conversationId, null, null, {
      encryptedFor,
      senderDeviceId: myDeviceId as string,
    });
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

  async function handleSendMessage(e: Event) {
    e.preventDefault();
    const content = newMessage.trim();
    if (!content || sending) return;

    // The single most important invariant: never send plaintext when
    // encryption was supposed to happen. If the other participant has no
    // device registered, or our own keypair isn't ready yet, sending is
    // blocked outright -- there is no silent plaintext fallback.
    if (!canSend || !myPrivateKey || !myDeviceId) return;

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
        created = await encryptAndSend(content, participantDevices);
      } catch (err) {
        // `participantDevices` is only fetched once per conversation (see
        // the `conversationId` watcher above), so it goes stale if the
        // other participant adds/removes a device while this window stays
        // open on the same conversation -- refetch and retry exactly once
        // with the fresh list rather than dropping the message outright.
        if (!isStaleDeviceListError(err)) throw err;
        await loadParticipantDevices();
        created = await encryptAndSend(content, participantDevices);
      }
      addMessage(created);
      newMessage = '';
      scrollToBottom(true);
    } catch (e) {
      console.error('Failed to send direct message:', e);
      if (isStaleDeviceListError(e)) {
        alert("Couldn't send: the recipient's devices changed, please try again");
      } else {
        alert('Network error while sending message');
      }
    } finally {
      sending = false;
    }
  }

  // Whether we're able to send an encrypted message right now: the other
  // participant must have at least one device registered, and our own
  // keypair must have finished loading/generating. (`participantDevices`
  // includes our own devices too, so this specifically checks for any
  // entry that ISN'T ours.)
  $: canSend = !!myPrivateKey && !!myDeviceId && participantDevices.some(d => !d.is_me);

  function formatTime(ts: string): string {
    return new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }
</script>

<div class="flex-1 flex flex-col bg-black border-l-2 border-[#00ff00]">
  <!-- Header -->
  <div class="h-12 border-b-2 border-[#00ff00] flex items-center px-4 gap-2">
    <div class="flex-1">
      <h3 class="text-sm font-bold text-[#00ff00] terminal-glow">
        {'>'} {participantUsername || 'Direct Message'}
      </h3>
    </div>
  </div>

  <!-- Messages -->
  <div class="flex-1 overflow-y-auto p-4 custom-scrollbar messages-container" bind:this={container} on:scroll={onScroll}>
    {#if loading}
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
            {#if message.attachment_url}
              <a
                href={message.attachment_url}
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
    {#if !participantDevices.some(d => !d.is_me)}
      <div class="text-xs text-[#ffaa00] mb-2 terminal-glow">
        {'>'} This user hasn't set up encrypted messaging on any device yet &mdash; you can't send them a message.
      </div>
    {/if}
    <form on:submit={handleSendMessage} class="flex gap-2">
      <input
        bind:value={newMessage}
        type="text"
        class="flex-1 bg-[#0a0e0a] border border-[#00ff00] px-4 py-2 text-[#00ff00] focus:outline-none focus:shadow-[0_0_10px_rgba(0,255,0,0.3)] disabled:opacity-50"
        placeholder={canSend ? 'Type a message...' : 'Encrypted messaging unavailable'}
        disabled={sending || !canSend}
      />
      <button
        type="submit"
        disabled={sending || !canSend || !newMessage.trim()}
        class="px-6 py-2 bg-[#00ff00] text-black font-bold hover:bg-[#00aa00] transition-all terminal-glow disabled:opacity-50 disabled:cursor-not-allowed"
      >
        {sending ? '...' : 'Send'}
      </button>
    </form>
  </div>
</div>

<style>
  .custom-scrollbar::-webkit-scrollbar { width: 6px; }
  .custom-scrollbar::-webkit-scrollbar-track { background: #0a0e0a; border-radius: 3px; }
  .custom-scrollbar::-webkit-scrollbar-thumb { background: #00ff00; border-radius: 3px; }
  .custom-scrollbar::-webkit-scrollbar-thumb:hover { background: #00aa00; }
  .custom-scrollbar { scrollbar-width: thin; scrollbar-color: #00ff00 #0a0e0a; }
  .terminal-glow {
    text-shadow: 0 0 5px rgba(0, 255, 0, 0.5);
  }
</style>
