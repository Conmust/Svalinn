<script lang="ts">
  import { onMount, onDestroy, createEventDispatcher } from 'svelte';
  import { getAuthHeaders } from '../lib/api';
  import { wsClient } from '../lib/websocket';
  import MessageItem from './MessageItem.svelte';

  export let channelId: string;

  const dispatch = createEventDispatcher();

  interface Message {
    id: string;
    channel_id: string;
    user_id: string;
    username: string;
    content: string;
    attachment_url?: string;
    attachment_filename?: string;
    attachment_mime_type?: string;
    attachment_size?: number;
    is_edited: boolean;
    is_locked: boolean;
    is_pinned: boolean;
    created_at: string;
  }

  let messages: Message[] = [];
  let loading = true;
  let newMessage = '';
  let sending = false;
  let attachmentFile: File | null = null;
  let selectionMode = false;
  let selectedMessages: string[] = [];
  let highlightedMessageId: string | null = null;

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

  onMount(() => {
    wsClient.connect();
    wsClient.on('new_message', onNewMessage);
    wsClient.on('message_deleted', onMessageDeleted);
    wsClient.on('message_updated', onMessageUpdated);
  });

  onDestroy(() => {
    wsClient.off('new_message', onNewMessage);
    wsClient.off('message_deleted', onMessageDeleted);
    wsClient.off('message_updated', onMessageUpdated);
  });

  async function loadMessages() {
    loading = true;
    try {
      const response = await fetch(`http://localhost:3001/api/v1/channels/${channelId}/messages`, {
        headers: getAuthHeaders(),
      });
      if (response.ok) {
        messages = await response.json();
        scrollToBottom();
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

  function handleFileSelect(event: Event) {
    const target = event.target as HTMLInputElement;
    attachmentFile = target.files?.[0] || null;
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

      const response = await fetch(`http://localhost:3001/api/v1/channels/${channelId}/messages`, {
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
        scrollToBottom();
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

    for (const messageId of selectedMessages) {
      try {
        await fetch(`http://localhost:3001/api/v1/messages/${messageId}`, {
          method: 'DELETE',
          headers: getAuthHeaders(),
        });
      } catch (e) {
        console.error('Failed to delete message:', e);
      }
    }

    selectedMessages = [];
    selectionMode = false;
    await loadMessages();
  }

  function handleUserClick(userId: string) {
    dispatch('userClicked', userId);
  }

  function scrollToBottom() {
    setTimeout(() => {
      const container = document.querySelector('.messages-container');
      if (container) {
        container.scrollTop = container.scrollHeight;
      }
    }, 100);
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
  </div>

  <!-- Messages -->
  <div class="flex-1 overflow-y-auto p-4 custom-scrollbar messages-container">
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
      <div class="space-y-1">
        {#each messages as message, i}
          {@const showHeader = i === 0 || messages[i - 1].user_id !== message.user_id}
          <MessageItem
            {message}
            isOwnMessage={false}
            {showHeader}
            {selectionMode}
            isSelected={selectedMessages.includes(message.id)}
            isHighlighted={highlightedMessageId === message.id}
            isPinned={message.is_pinned || false}
            on:messageDeleted={loadMessages}
            on:messageUpdated={loadMessages}
            on:select={handleSelectMessage}
            on:userClicked={(e) => handleUserClick(e.detail)}
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

      <!-- Emoji Button -->
      <button type="button" class="px-3 py-2 border border-[#00ff00] text-[#00ff00] hover:bg-[#00ff00] hover:text-black transition-all terminal-glow flex items-center justify-center" title="Emoji (Coming Soon)">
        <svg xmlns="http://www.w3.org/2000/svg" class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.828 14.828a4 4 0 01-5.656 0M9 10h.01M15 10h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
      </button>

      <!-- Text Input -->
      <input
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