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
  } from '../lib/messages';

  export let channelId: string;
  export let serverId: string;
  export let currentUser: { id: string } | null = null;
  export let showRoster = false;

  const dispatch = createEventDispatcher();

  let messages: Message[] = [];
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
    messages = messages.map(m => (m.id === id ? { ...m, ...changes } : m));
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
      messages = messages.filter(x => x.id !== m.id);
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
  }

  // Named handlers so onDestroy removes only this component's listeners
  // (ChannelList listens to the same events).
  function onNewMessage(data: Message) {
    if (data.channel_id !== channelId) return;
    addMessage(data);
    scrollToBottom();
  }

  function onMessageDeleted(data: { message_id: string }) {
    messages = messages.filter(m => m.id !== data.message_id);
  }

  function onMessageUpdated(data: Message) {
    messages = messages.map(m => m.id === data.id ? { ...m, ...data } : m);
  }

  // The sender gets their message both from the POST response and from the
  // WebSocket broadcast, so skip ids we already have.
  function addMessage(message: Message) {
    if (messages.some(m => m.id === message.id)) return;
    messages = [...messages, message];
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
    if (loadingOlder || !hasMore || messages.length === 0) return;
    const forChannel = channelId;
    loadingOlder = true;
    try {
      const res = await apiFetch(
        `${apiBase()}/api/v1/channels/${forChannel}/messages?before=${messages[0].id}&limit=${PAGE_SIZE}`,
      );
      if (!res.ok || forChannel !== channelId) return;
      const older: Message[] = await res.json();
      hasMore = older.length === PAGE_SIZE;
      const fresh = older.filter(o => !messages.some(m => m.id === o.id));
      if (fresh.length === 0) return;

      const heightBefore = container?.scrollHeight ?? 0;
      const topBefore = container?.scrollTop ?? 0;
      messages = [...fresh, ...messages];
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
      const response = await apiFetch(`${apiBase()}/api/v1/channels/${forChannel}/messages?limit=${PAGE_SIZE}`, {
        headers: getAuthHeaders(),
      });
      // Ignore the answer if the user has switched channels meanwhile.
      if (forChannel !== channelId) return;
      if (response.ok) {
        messages = await response.json();
        hasMore = messages.length === PAGE_SIZE;
        loading = false;
        await scrollToBottom(true);
      } else if (response.status === 401) {
        localStorage.clear();
        location.reload();
      }
    } catch (e) {
      console.error('Failed to load messages:', e);
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

    async function handleSendMessage(e: Event) {
    e.preventDefault();
    if ((!newMessage.trim() && !attachmentFile) || sending) return;

    sending = true;
    try {
      const formData = new FormData();
      formData.append('content', newMessage.trim());
      if (attachmentFile) {
        formData.append('file', attachmentFile);
      }

      const response = await apiFetch(`${apiBase()}/api/v1/channels/${channelId}/messages`, {
        method: 'POST',
        headers: getAuthHeaders(),
        body: formData,
      });

      if (response.ok) {
        // 1. Get the newly created message object from the backend
        const createdMessage = await response.json();
        
        // 2. Immediately add it to the local array so it shows up instantly!
        addMessage(createdMessage);
        
        // 3. Clean up the input
        newMessage = '';
        clearAttachment();
        scrollToBottom(true);
      } else if (response.status === 401) {
        localStorage.clear();
        location.reload();
      } else {
        const err = await response.json().catch(() => ({}));
        alert(err.error || 'Failed to send message');
      }
    } catch (e) {
      console.error('Failed to send message:', e);
      alert('Network error while sending message');
    } finally {
      sending = false;
    }
  }
  
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

<div class="flex-1 flex flex-col bg-black border-l-2 border-[#00ff00]">
  <!-- Header -->
  <div class="h-12 border-b-2 border-[#00ff00] flex items-center px-4 gap-2">
    <div class="flex-1">
      <h3 class="text-sm font-bold text-[#00ff00] terminal-glow">
        {'>'} Channel Chat
      </h3>
    </div>

    {#if pinnedCount > 0}
      <button
        type="button"
        class="px-3 py-1 border border-[#00ff00] text-xs transition-all terminal-glow {showPinnedOnly ? 'bg-[#00ff00] text-black' : 'text-[#00ff00] hover:bg-[#00ff00] hover:text-black'}"
        title={showPinnedOnly ? 'Show all messages' : 'Show only pinned messages'}
        on:click={() => (showPinnedOnly = !showPinnedOnly)}
      >
        📌 Pinned ({pinnedCount})
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
    {#if loading}
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
        <input type="file" class="hidden" accept="image/*,video/*,.pdf,.txt" on:change={handleFileSelect} />
      </label>

      <!-- Emoji Picker -->
      <InlineEmojiPicker on:select={insertEmoji} />

      <!-- Text Input -->
      <input
        bind:this={messageInput}
        bind:value={newMessage}
        type="text"
        class="flex-1 bg-[#0a0e0a] border border-[#00ff00] px-4 py-2 text-[#00ff00] focus:outline-none focus:shadow-[0_0_10px_rgba(0,255,0,0.3)]"
        placeholder="Type a message..."
        disabled={sending}
      />

      <!-- Send Button -->
      <button
        type="submit"
        disabled={sending || (!newMessage.trim() && !attachmentFile)}
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