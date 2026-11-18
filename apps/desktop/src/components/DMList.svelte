<script lang="ts">
  import { onMount, createEventDispatcher } from 'svelte';
  import { getAuthHeaders, apiFetch } from '../lib/api';
  import { getCurrentUser } from '../lib/auth';
  import PatronBadge from './PatronBadge.svelte';

  export let activeConversation: string | null = null;

  const dispatch = createEventDispatcher();

  interface Conversation {
    id: string;
    created_at: string;
    has_unread: boolean;
    participant?: {
      id: string;
      username: string;
      patron_tier?: string;
      status: string;
    };
  }

  let conversations: Conversation[] = [];
  let loading = true;
  let currentUser = getCurrentUser();

  const statusConfig = {
    online: { color: '#00ff00', glow: '0 0 8px #00ff00' },
    idle: { color: '#ffaa00', glow: '0 0 8px #ffaa00' },
    busy: { color: '#ff0000', glow: '0 0 8px #ff0000' },
    away: { color: '#ff6600', glow: '0 0 8px #ff6600' },
    invisible: { color: '#666666', glow: '0 0 8px #666666' },
    offline: { color: '#444444', glow: 'none' }
  };

  function getStatusStyle(status: string | undefined) {
    const config = status && status in statusConfig ? statusConfig[status as keyof typeof statusConfig] : statusConfig.offline;
    return `background-color: ${config.color}; box-shadow: ${config.glow};`;
  }

  onMount(() => {
    loadConversations();
  });

  async function loadConversations() {
    loading = true;
    try {
      const response = await apiFetch('http://localhost:3001/api/v1/conversations', {
        headers: getAuthHeaders(),
      });
      if (response.ok) {
        conversations = await response.json();
      }
    } catch (e) {
      console.error('Failed to load conversations:', e);
    } finally {
      loading = false;
    }
  }

  function handleConversationClick(conversationId: string) {
    dispatch('conversationSelected', conversationId);
  }
</script>

<aside class="w-60 bg-[#0a0e0a] border-r-2 border-[#00ff00] flex flex-col h-full">
  <!-- Header -->
  <div class="p-4 border-b-2 border-[#00ff00]">
    <h3 class="text-xs font-semibold text-[#00aa00] uppercase tracking-widest terminal-glow">
      {'>'} Direct Messages
    </h3>
  </div>

  <!-- Conversation List -->
  <div class="flex-1 overflow-y-auto p-2 custom-scrollbar">
    {#if loading}
      <div class="flex items-center justify-center py-8">
        <div class="animate-pulse border-2 border-[#00ff00] w-6 h-6"></div>
      </div>
    {:else if conversations.length === 0}
      <div class="text-center text-[#00aa00] text-sm py-8 px-4 terminal-glow">
        {'>'} No conversations yet
      </div>
    {:else}
      {#each conversations as conversation}
        <button
          type="button"
          class="w-full text-left px-3 py-2 mb-1 rounded hover:bg-[rgba(0,255,0,0.1)] transition-all flex items-center gap-2 group {conversation.id === activeConversation ? 'bg-[rgba(0,255,0,0.15)] border-l-2 border-[#00ff00]' : (conversation.has_unread ? 'bg-[rgba(0,255,0,0.05)]' : '')}"
          on:click={() => handleConversationClick(conversation.id)}
        >
          <!-- Avatar with Status -->
          <div class="relative flex-shrink-0">
            <div class="w-8 h-8 border-2 border-[#00ff00] flex items-center justify-center font-bold text-sm terminal-glow">
              {conversation.participant?.username[0].toUpperCase() || '?'}
            </div>
            <div
              class="absolute bottom-0 right-0 w-3 h-3 border-2 border-[#0a0e0a] rounded-full"
              style={getStatusStyle(conversation.participant?.status)}
            ></div>
          </div>

          <!-- Unread Indicator -->
          {#if conversation.has_unread}
            <div class="w-2 h-2 bg-[#00ff00] rounded-full shadow-[0_0_8px_#00ff00] flex-shrink-0 animate-pulse"></div>
          {:else}
            <div class="w-2 h-2 flex-shrink-0"></div>
          {/if}

          <!-- Username -->
          <div class="flex-1 min-w-0 flex items-center gap-1">
            <div class="text-sm terminal-glow truncate {conversation.has_unread ? 'text-[#00ff00] font-bold' : 'text-[#00aa00]'}">
              {conversation.participant?.username || 'Unknown User'}
            </div>
            {#if conversation.participant?.patron_tier && conversation.participant.patron_tier !== 'free'}
              <PatronBadge tier={conversation.participant.patron_tier} size="small" />
            {/if}
          </div>
        </button>
      {/each}
    {/if}
  </div>
</aside>

<style>
  .custom-scrollbar::-webkit-scrollbar { width: 6px; }
  .custom-scrollbar::-webkit-scrollbar-track { background: #0a0e0a; border-radius: 3px; }
  .custom-scrollbar::-webkit-scrollbar-thumb { background: #00ff00; border-radius: 3px; }
  .custom-scrollbar::-webkit-scrollbar-thumb:hover { background: #00aa00; }
  .custom-scrollbar { scrollbar-width: thin; scrollbar-color: #00ff00 #0a0e0a; }
</style>
