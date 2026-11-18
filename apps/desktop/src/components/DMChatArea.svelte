<script lang="ts">
  import { onMount, onDestroy, tick } from 'svelte';
  import { wsClient } from '../lib/websocket';
  import {
    type ConversationMessage,
    fetchConversationMessages,
    sendDirectMessage,
  } from '../lib/conversations';

  export let conversationId: string;
  export let participantUsername: string = '';
  export let currentUser: { id: string } | null = null;

  let messages: ConversationMessage[] = [];
  let loading = true;
  let newMessage = '';
  let sending = false;

  // History is loaded a page at a time; scrolling to the top loads more.
  const PAGE_SIZE = 50;
  let container: HTMLDivElement;
  let hasMore = false;
  let loadingOlder = false;

  $: if (conversationId) {
    loadMessages();
  }

  function onNewDirectMessage(data: ConversationMessage) {
    if (data.conversation_id !== conversationId) return;
    addMessage(data);
    scrollToBottom();
  }

  // The sender gets their message both from the POST response and from the
  // WebSocket broadcast, so skip ids we already have.
  function addMessage(message: ConversationMessage) {
    if (messages.some(m => m.id === message.id)) return;
    messages = [...messages, message];
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
      const fetched = await fetchConversationMessages(forConversation, { limit: PAGE_SIZE });
      if (forConversation !== conversationId) return;
      messages = fetched;
      hasMore = messages.length === PAGE_SIZE;
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
    if (loadingOlder || !hasMore || messages.length === 0) return;
    const forConversation = conversationId;
    loadingOlder = true;
    try {
      const older = await fetchConversationMessages(forConversation, {
        before: messages[0].id,
        limit: PAGE_SIZE,
      });
      if (forConversation !== conversationId) return;
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

  async function handleSendMessage(e: Event) {
    e.preventDefault();
    const content = newMessage.trim();
    if (!content || sending) return;

    sending = true;
    try {
      const created = await sendDirectMessage(conversationId, content);
      addMessage(created);
      newMessage = '';
      scrollToBottom(true);
    } catch (e) {
      console.error('Failed to send direct message:', e);
      alert('Network error while sending message');
    } finally {
      sending = false;
    }
  }

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
            {#if message.content}
              <div class="text-sm text-[#00dd00] whitespace-pre-wrap break-words">{message.content}</div>
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
    <form on:submit={handleSendMessage} class="flex gap-2">
      <input
        bind:value={newMessage}
        type="text"
        class="flex-1 bg-[#0a0e0a] border border-[#00ff00] px-4 py-2 text-[#00ff00] focus:outline-none focus:shadow-[0_0_10px_rgba(0,255,0,0.3)]"
        placeholder="Type a message..."
        disabled={sending}
      />
      <button
        type="submit"
        disabled={sending || !newMessage.trim()}
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
