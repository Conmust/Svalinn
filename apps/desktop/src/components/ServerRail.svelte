<script lang="ts">
  import { onMount, onDestroy, createEventDispatcher } from 'svelte';
  import { wsClient } from '../lib/websocket';
  import { getAuthHeaders, apiFetch, fileUrl, apiBase, endSession } from '../lib/api';
  import { autofocus } from '../lib/actions';

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

  // Create / join dialog
  let modalMode: 'create' | 'join' = 'create';
  let inviteInput = '';
  let invitePreview: { code: string; server_id: string; server_name: string; member_count: number; already_member: boolean } | null = null;
  let joinError = '';
  let joinBusy = false;

  function openModal(mode: 'create' | 'join') {
    modalMode = mode;
    createError = joinError = '';
    invitePreview = null;
    inviteInput = '';
    showCreateModal = true;
  }

  async function errorFrom(res: Response, fallback: string): Promise<string> {
    const err = await res.json().catch(() => ({}));
    return err.error || fallback;
  }

  async function handleLookupInvite(e: Event) {
    e.preventDefault();
    const code = inviteInput.trim();
    if (!code) return;
    joinError = '';
    invitePreview = null;
    joinBusy = true;
    try {
      const res = await apiFetch(`${apiBase()}/api/v1/invites/${encodeURIComponent(code)}`);
      if (res.ok) invitePreview = await res.json();
      else joinError = await errorFrom(res, 'Invite not found');
    } catch (err: any) {
      joinError = err.message || 'Network error';
    } finally {
      joinBusy = false;
    }
  }

  async function handleJoin() {
    if (!invitePreview) return;
    joinError = '';
    joinBusy = true;
    try {
      const res = await apiFetch(`${apiBase()}/api/v1/invites/${encodeURIComponent(invitePreview.code)}`, { method: 'POST' });
      if (!res.ok) {
        joinError = await errorFrom(res, 'Could not join');
        return;
      }
      const server: Server = await res.json();
      if (!servers.some(s => s.id === server.id)) servers = [...servers, server];
      showCreateModal = false;
      dispatch('serverSelected', server.id);
    } catch (err: any) {
      joinError = err.message || 'Network error';
    } finally {
      joinBusy = false;
    }
  }

  // Kicked, banned or left: drop the server from the list.
  function onRemoved(data: { server_id: string }) {
    servers = servers.filter(s => s.id !== data.server_id);
  }

  onMount(async () => {
    wsClient.on('removed_from_server', onRemoved);
    await loadServers();
  });

  onDestroy(() => wsClient.off('removed_from_server', onRemoved));

  async function loadServers() {
  loading = true;
  try {
    const response = await apiFetch(`${apiBase()}/api/v1/servers`, {
      headers: getAuthHeaders(), // ← This must be here
    });
    if (response.ok) {
      servers = await response.json();
      if (servers.length > 0) {
        dispatch('serverSelected', servers[0].id);
      }
    } else if (response.status === 401) {
      // Token is invalid, force logout. Only the session (token/refresh_token/
      // user) -- not a blanket localStorage.clear(), which would also wipe
      // this device's E2EE identity (keypair, ratchet signing key, sessions)
      // and force it to re-establish encryption with every peer.
      endSession('Session expired');
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
      const response = await apiFetch(`${apiBase()}/api/v1/servers`, {
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
          <img src={fileUrl(server.icon_url)} alt={server.name} class="w-full h-full object-cover" />
        {:else}
          <span class="text-[#00ff00] font-bold text-lg group-hover:text-black transition-colors">
            {server.name[0].toUpperCase()}
          </span>
        {/if}
      </button>
    {/each}
  {/if}

  <!-- Account settings (pinned to bottom, above Create) -->
  <button
    type="button"
    class="w-12 h-12 bg-black border-2 border-[#00ff00] rounded-xl flex items-center justify-center hover:bg-[#00ff00] hover:text-black text-[#00ff00] transition-all terminal-glow mt-auto"
    title="Account settings"
    aria-label="Account settings"
    on:click={() => dispatch('openAccountSettings')}
  >
    <svg xmlns="http://www.w3.org/2000/svg" style="width: 22px; height: 22px;" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
    </svg>
  </button>

  <!-- Create Server Button (Pinned to bottom) -->
  <button
    type="button"
    class="w-12 h-12 bg-black border-2 border-dashed border-[#00ff00] rounded-xl flex items-center justify-center hover:bg-[#00ff00] hover:border-solid transition-all terminal-glow group mb-2"
    title="Create or join a server"
    on:click={() => openModal('create')}
  >
    <svg xmlns="http://www.w3.org/2000/svg" class="w-6 h-6 text-[#00ff00] group-hover:text-black transition-colors" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4" />
    </svg>
  </button>

  <!-- Create Server Modal -->
  {#if showCreateModal}
    <!-- svelte-ignore a11y-no-noninteractive-element-interactions -->
    <div
      class="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm"
      on:click={() => showCreateModal = false}
      on:keydown={(e) => e.key === 'Escape' && (showCreateModal = false)}
      role="dialog" aria-modal="true" tabindex="-1"
    >
      <!-- svelte-ignore a11y-no-noninteractive-element-interactions -->
      <!-- svelte-ignore a11y-click-events-have-key-events -->
      <div
        class="relative w-[400px] bg-black border-2 border-[#00ff00] shadow-[0_0_30px_rgba(0,255,0,0.4)] p-6"
        on:click|stopPropagation role="document"
      >
        <div class="flex mb-4 border-b border-[#00aa00]/40" role="tablist">
          <button type="button" role="tab" aria-selected={modalMode === 'create'}
            class="flex-1 py-2 text-sm font-bold uppercase tracking-widest {modalMode === 'create' ? 'text-[#00ff00] border-b-2 border-[#00ff00]' : 'text-[#00aa00] hover:text-[#00ff00]'}"
            on:click={() => (modalMode = 'create')}>Create</button>
          <button type="button" role="tab" aria-selected={modalMode === 'join'}
            class="flex-1 py-2 text-sm font-bold uppercase tracking-widest {modalMode === 'join' ? 'text-[#00ff00] border-b-2 border-[#00ff00]' : 'text-[#00aa00] hover:text-[#00ff00]'}"
            on:click={() => (modalMode = 'join')}>Join</button>
        </div>

        {#if modalMode === 'create'}
        <form on:submit={handleCreateServer} class="space-y-4">
          <div>
            <label for="new-server-name" class="block text-xs text-[#00aa00] uppercase tracking-wider mb-1">Server Name</label>
            <input 
              id="new-server-name" bind:value={newServerName} type="text" 
              class="w-full bg-[#0a0e0a] border border-[#00ff00] px-3 py-2 text-[#00ff00] focus:outline-none focus:shadow-[0_0_10px_rgba(0,255,0,0.3)]" 
              placeholder="e.g., My Awesome Community" required use:autofocus
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
        {:else}
        <form on:submit={handleLookupInvite} class="space-y-4">
          <div>
            <label for="invite-code" class="block text-xs text-[#00aa00] uppercase tracking-wider mb-1">Invite code or link</label>
            <input
              id="invite-code" bind:value={inviteInput} type="text"
              class="w-full bg-[#0a0e0a] border border-[#00ff00] px-3 py-2 text-[#00ff00] font-mono focus:outline-none focus:shadow-[0_0_10px_rgba(0,255,0,0.3)]"
              placeholder="e.g., aB3dEf9hJk" required
              on:input={() => (invitePreview = null)}
            />
          </div>
          {#if invitePreview}
            <div class="border border-[#00ff00] bg-[#0a0e0a] p-3 text-sm">
              <div class="text-[#00ff00] font-bold">{invitePreview.server_name}</div>
              <div class="text-xs text-[#00aa00]">
                {invitePreview.member_count} member{invitePreview.member_count === 1 ? '' : 's'}{invitePreview.already_member ? ' · you are already a member' : ''}
              </div>
            </div>
          {/if}
          {#if joinError}
            <div class="text-xs text-red-500 terminal-glow">{'>'} {joinError}</div>
            {#if joinError.includes('Verify your email')}
              <button
                type="button"
                class="text-xs text-[#00ff00] underline"
                on:click={() => { showCreateModal = false; dispatch('openAccountSettings'); }}
              >
                Go to account settings to resend it
              </button>
            {/if}
          {/if}
          <div class="flex gap-2 pt-2">
            <button type="button" class="flex-1 py-2 border border-[#00aa00] text-[#00aa00] hover:bg-[#00aa00]/10 transition-all text-sm" on:click={() => showCreateModal = false}>Cancel</button>
            {#if invitePreview}
              <button type="button" disabled={joinBusy} class="flex-1 py-2 bg-[#00ff00] text-black font-bold hover:bg-[#00aa00] transition-all text-sm terminal-glow disabled:opacity-50" on:click={handleJoin}>
                {invitePreview.already_member ? 'Open' : 'Join'}
              </button>
            {:else}
              <button type="submit" disabled={joinBusy} class="flex-1 py-2 bg-[#00ff00] text-black font-bold hover:bg-[#00aa00] transition-all text-sm terminal-glow disabled:opacity-50">Look up</button>
            {/if}
          </div>
        </form>
        {/if}
      </div>
    </div>
  {/if}
</aside>
