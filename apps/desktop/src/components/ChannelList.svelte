<script lang="ts">
  import { onMount, onDestroy, createEventDispatcher } from 'svelte';
  import { getAuthHeaders, apiFetch, apiBase } from '../lib/api';
  import { logout } from '../lib/auth';
  import { wsClient } from '../lib/websocket';
  import ServerSettings from './ServerSettings.svelte';

  export let currentUser: any;
  export let activeServer: string | null = null;
  export let activeChannel: string | null = null;

  const dispatch = createEventDispatcher();

  interface Channel {
    id: string;
    server_id: string;
    name: string;
    created_at: string;
    has_unread: boolean;
  }

  let channels: Channel[] = [];
  let loading = true;
  let showServerSettings = false;
  let showCreateChannelModal = false;
  let newChannelName = '';
  let createChannelError = '';

  $: if (activeServer) {
    loadChannels(activeServer);
  }

  function onNewMessage(data: { channel_id?: string; user_id?: string }) {
    if (!data.channel_id || data.channel_id === activeChannel) return;
    if (data.user_id === currentUser?.id) return;
    channels = channels.map(c =>
      c.id === data.channel_id ? { ...c, has_unread: true } : c
    );
  }

  onMount(() => {
    wsClient.connect();
    wsClient.on('new_message', onNewMessage);
  });

  onDestroy(() => {
    wsClient.off('new_message', onNewMessage);
  });

   async function loadChannels(serverId: string) {
    loading = true;
    try {
      const response = await apiFetch(`${apiBase()}/api/v1/servers/${serverId}/channels`, {
        headers: getAuthHeaders(), // <-- THIS LINE IS CRUCIAL
      });
      
      if (response.ok) {
        channels = await response.json();
      } else if (response.status === 401) {
        console.error("Unauthorized: Token missing or invalid");
        localStorage.clear();
        location.reload();
      } else {
        const errText = await response.text();
        console.error(`Failed to load channels: ${response.status}`, errText);
      }
    } catch (e) {
      console.error('Failed to load channels:', e);
    } finally {
      loading = false;
    }
  }

  function handleChannelClick(channelId: string) {
    dispatch('channelSelected', channelId);
    channels = channels.map(c => 
      c.id === channelId ? { ...c, has_unread: false } : c
    );
  }

  async function handleCreateChannel(e: Event) {
    e.preventDefault();
    if (!newChannelName.trim() || !activeServer) return;

    createChannelError = '';
    try {
      const response = await apiFetch(`${apiBase()}/api/v1/servers/${activeServer}/channels`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...getAuthHeaders()
        },
        body: JSON.stringify({ name: newChannelName.trim() }),
      });

      if (response.ok) {
        const newChannel = await response.json();
        channels = [...channels, newChannel];
        newChannelName = '';
        showCreateChannelModal = false;
        // Optionally auto-select the new channel
        dispatch('channelSelected', newChannel.id);
      } else {
        const err = await response.json();
        createChannelError = err.error || 'Failed to create channel';
      }
    } catch (e: any) {
      createChannelError = e.message || 'Network error';
    }
  }

  function handleLogout() {
    logout();
    dispatch('logout');
  }
</script>

<aside class="w-60 bg-[#0a0e0a] border-r-2 border-[#00ff00] flex flex-col h-full">
  <!-- Server Header -->
  <div class="p-4 border-b-2 border-[#00ff00] flex items-center justify-between">
    <div class="flex-1 min-w-0">
      <h3 class="text-xs font-semibold text-[#00aa00] uppercase tracking-widest terminal-glow truncate">
        {'>'} Channels
      </h3>
    </div>
    <div class="flex gap-2">
      <!-- Settings Button -->
      <button
        type="button"
        class="w-6 h-6 border border-[#00ff00] flex items-center justify-center hover:bg-[#00ff00] hover:text-black transition-all terminal-glow flex-shrink-0"
        on:click={() => showServerSettings = true}
        title="Server Settings"
      >
        <svg xmlns="http://www.w3.org/2000/svg" style="width: 14px !important; height: 14px !important; display: block !important;" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
        </svg>
      </button>
      
      <!-- Create Channel Button -->
      <button
        type="button"
        class="w-6 h-6 border border-[#00ff00] flex items-center justify-center hover:bg-[#00ff00] hover:text-black transition-all terminal-glow flex-shrink-0"
        on:click={() => showCreateChannelModal = true}
        title="Create Channel"
      >
        <svg xmlns="http://www.w3.org/2000/svg" style="width: 14px !important; height: 14px !important; display: block !important;" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4" />
        </svg>
      </button>
    </div>
  </div>

  <!-- Channel List -->
  <div class="flex-1 overflow-y-auto p-2 custom-scrollbar">
    {#if loading}
      <div class="flex items-center justify-center py-8">
        <div class="animate-pulse border-2 border-[#00ff00] w-6 h-6"></div>
      </div>
    {:else if channels.length === 0}
      <div class="text-center text-[#00aa00] text-sm py-8 px-4 terminal-glow">
        {'>'} No channels yet
      </div>
    {:else}
      {#each channels as channel}
        <button
          type="button"
          class="w-full text-left px-3 py-2 mb-1 rounded hover:bg-[rgba(0,255,0,0.1)] transition-all flex items-center gap-2 group {channel.has_unread ? 'bg-[rgba(0,255,0,0.05)]' : ''}"
          on:click={() => handleChannelClick(channel.id)}
        >
          {#if channel.has_unread}
            <div class="w-2 h-2 bg-[#00ff00] rounded-full shadow-[0_0_8px_#00ff00] flex-shrink-0 animate-pulse"></div>
          {:else}
            <div class="w-2 h-2 flex-shrink-0"></div>
          {/if}

          <div class="flex-1 min-w-0">
            <div class="text-sm terminal-glow truncate {channel.has_unread ? 'text-[#00ff00] font-bold' : 'text-[#00aa00]'}">
              # {channel.name}
            </div>
          </div>
        </button>
      {/each}
    {/if}
  </div>

  <!-- User Footer -->
  <div class="p-3 border-t-2 border-[#00ff00] bg-black">
    <div class="flex items-center gap-2 mb-2">
      <div class="w-8 h-8 border-2 border-[#00ff00] flex items-center justify-center font-bold text-sm terminal-glow">
        {currentUser.username[0].toUpperCase()}
      </div>
      <div class="flex-1 min-w-0">
        <div class="text-xs text-[#00ff00] truncate terminal-glow">{currentUser.username}</div>
        <div class="text-[10px] text-[#00aa00] terminal-glow">Online</div>
      </div>
    </div>
    <button
      type="button"
      class="w-full px-3 py-1.5 bg-black border border-[#00ff00] text-[#00ff00] text-xs hover:bg-[#00ff00] hover:text-black transition-all terminal-glow"
      on:click={handleLogout}
    >
      Logout
    </button>
  </div>

  <!-- Create Channel Modal -->
  {#if showCreateChannelModal}
    <div 
      class="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm" 
      on:click={() => showCreateChannelModal = false}
      on:keydown={(e) => e.key === 'Escape' && (showCreateChannelModal = false)}
      role="dialog" aria-modal="true" tabindex="-1"
    >
      <div 
        class="relative w-[400px] bg-black border-2 border-[#00ff00] shadow-[0_0_30px_rgba(0,255,0,0.4)] p-6" 
        on:click|stopPropagation role="document"
      >
        <h3 class="text-lg font-bold text-[#00ff00] uppercase tracking-widest mb-4 terminal-glow">{'>'} Create Channel</h3>
        <form on:submit={handleCreateChannel} class="space-y-4">
          <div>
            <label for="new-channel-name" class="block text-xs text-[#00aa00] uppercase tracking-wider mb-1">Channel Name</label>
            <input 
              id="new-channel-name" bind:value={newChannelName} type="text" 
              class="w-full bg-[#0a0e0a] border border-[#00ff00] px-3 py-2 text-[#00ff00] focus:outline-none focus:shadow-[0_0_10px_rgba(0,255,0,0.3)]" 
              placeholder="e.g., general" required autofocus
            />
          </div>
          {#if createChannelError}
            <div class="text-xs text-red-500 terminal-glow">{'>'} {createChannelError}</div>
          {/if}
          <div class="flex gap-2 pt-2">
            <button type="button" class="flex-1 py-2 border border-[#00aa00] text-[#00aa00] hover:bg-[#00aa00]/10 transition-all text-sm" on:click={() => showCreateChannelModal = false}>Cancel</button>
            <button type="submit" class="flex-1 py-2 bg-[#00ff00] text-black font-bold hover:bg-[#00aa00] transition-all text-sm terminal-glow">Create</button>
          </div>
        </form>
      </div>
    </div>
  {/if}

  <!-- Server Settings Modal -->
  {#if showServerSettings && activeServer}
    <ServerSettings 
      serverId={activeServer} 
      on:close={() => showServerSettings = false}
      on:saved={() => { showServerSettings = false; }}
    />
  {/if}
</aside>

<style>
  .custom-scrollbar::-webkit-scrollbar { width: 6px; }
  .custom-scrollbar::-webkit-scrollbar-track { background: #0a0e0a; border-radius: 3px; }
  .custom-scrollbar::-webkit-scrollbar-thumb { background: #00ff00; border-radius: 3px; }
  .custom-scrollbar::-webkit-scrollbar-thumb:hover { background: #00aa00; }
  .custom-scrollbar { scrollbar-width: thin; scrollbar-color: #00ff00 #0a0e0a; }
</style>