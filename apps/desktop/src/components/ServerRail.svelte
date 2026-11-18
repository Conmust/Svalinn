<script lang="ts">
  import { onMount, createEventDispatcher } from 'svelte';
  import { getAuthHeaders } from '../lib/api';

  const dispatch = createEventDispatcher();

  interface Server {
    id: string;
    name: string;
    icon_url?: string;
  }

  let servers: Server[] = [];
  let loading = true;
  let showCreateModal = false;
  let newServerName = '';
  let createError = '';

  onMount(async () => {
    await loadServers();
  });

  async function loadServers() {
  loading = true;
  try {
    const response = await fetch('http://localhost:3001/api/v1/servers', {
      headers: getAuthHeaders(), // ← This must be here
    });
    if (response.ok) {
      servers = await response.json();
      if (servers.length > 0) {
        dispatch('serverSelected', servers[0].id);
      }
    } else if (response.status === 401) {
      // Token is invalid, force logout
      localStorage.clear();
      location.reload();
    }
  } catch (e) {
    console.error('Failed to load servers:', e);
  } finally {
    loading = false;
  }
}

  async function handleCreateServer(e: Event) {
    e.preventDefault();
    if (!newServerName.trim()) return;

    createError = '';
    try {
      const response = await fetch('http://localhost:3001/api/v1/servers', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
        body: JSON.stringify({ name: newServerName.trim() }),
      });

      if (response.ok) {
        const newServer = await response.json();
        servers = [...servers, newServer];
        newServerName = '';
        showCreateModal = false;
        dispatch('serverSelected', newServer.id);
      } else {
        const err = await response.json();
        createError = err.error || 'Failed to create server';
      }
    } catch (e: any) {
      createError = e.message || 'Network error';
    }
  }
</script>

<aside class="w-[72px] bg-[#050805] border-r-2 border-[#00ff00] flex flex-col items-center py-4 gap-3 h-full overflow-y-auto custom-scrollbar">
  <!-- DMs Button -->
  <button
    type="button"
    class="w-12 h-12 bg-black border-2 border-[#00ff00] rounded-xl flex items-center justify-center hover:rounded-lg transition-all terminal-glow group relative"
    title="Direct Messages"
    on:click={() => dispatch('serverSelected', null)}
  >
    <svg xmlns="http://www.w3.org/2000/svg" class="w-6 h-6 text-[#00ff00] group-hover:text-black transition-colors" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
    </svg>
  </button>

  <div class="w-8 h-[2px] bg-[#00aa00]/30 rounded-full"></div>

  <!-- Server List -->
  {#if loading}
    <div class="w-12 h-12 border-2 border-[#00ff00] rounded-xl animate-pulse"></div>
  {:else}
    {#each servers as server}
      <button
        type="button"
        class="w-12 h-12 bg-black border-2 border-[#00ff00] rounded-xl flex items-center justify-center hover:rounded-lg transition-all terminal-glow group relative overflow-hidden"
        title={server.name}
        on:click={() => dispatch('serverSelected', server.id)}
      >
        {#if server.icon_url}
          <img src="http://localhost:3001{server.icon_url}" alt={server.name} class="w-full h-full object-cover" />
        {:else}
          <span class="text-[#00ff00] font-bold text-lg group-hover:text-black transition-colors">
            {server.name[0].toUpperCase()}
          </span>
        {/if}
      </button>
    {/each}
  {/if}

  <!-- Create Server Button (Pinned to bottom) -->
  <button
    type="button"
    class="w-12 h-12 bg-black border-2 border-dashed border-[#00ff00] rounded-xl flex items-center justify-center hover:bg-[#00ff00] hover:border-solid transition-all terminal-glow group mt-auto mb-2"
    title="Create a Server"
    on:click={() => showCreateModal = true}
  >
    <svg xmlns="http://www.w3.org/2000/svg" class="w-6 h-6 text-[#00ff00] group-hover:text-black transition-colors" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4" />
    </svg>
  </button>

  <!-- Create Server Modal -->
  {#if showCreateModal}
    <div 
      class="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm" 
      on:click={() => showCreateModal = false}
      on:keydown={(e) => e.key === 'Escape' && (showCreateModal = false)}
      role="dialog" aria-modal="true" tabindex="-1"
    >
      <div 
        class="relative w-[400px] bg-black border-2 border-[#00ff00] shadow-[0_0_30px_rgba(0,255,0,0.4)] p-6" 
        on:click|stopPropagation role="document"
      >
        <h3 class="text-lg font-bold text-[#00ff00] uppercase tracking-widest mb-4 terminal-glow">{'>'} Create Server</h3>
        <form on:submit={handleCreateServer} class="space-y-4">
          <div>
            <label for="new-server-name" class="block text-xs text-[#00aa00] uppercase tracking-wider mb-1">Server Name</label>
            <input 
              id="new-server-name" bind:value={newServerName} type="text" 
              class="w-full bg-[#0a0e0a] border border-[#00ff00] px-3 py-2 text-[#00ff00] focus:outline-none focus:shadow-[0_0_10px_rgba(0,255,0,0.3)]" 
              placeholder="e.g., My Awesome Community" required autofocus
            />
          </div>
          {#if createError}
            <div class="text-xs text-red-500 terminal-glow">{'>'} {createError}</div>
          {/if}
          <div class="flex gap-2 pt-2">
            <button type="button" class="flex-1 py-2 border border-[#00aa00] text-[#00aa00] hover:bg-[#00aa00]/10 transition-all text-sm" on:click={() => showCreateModal = false}>Cancel</button>
            <button type="submit" class="flex-1 py-2 bg-[#00ff00] text-black font-bold hover:bg-[#00aa00] transition-all text-sm terminal-glow">Create</button>
          </div>
        </form>
      </div>
    </div>
  {/if}
</aside>
