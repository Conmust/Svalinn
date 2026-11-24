<script lang="ts">
  import { onMount, onDestroy, createEventDispatcher } from 'svelte';
  import { getAuthHeaders, apiFetch, apiBase } from '../lib/api';
  import { logout } from '../lib/auth';
  import { wsClient } from '../lib/websocket';
  import { selfAvatarUrl } from '../lib/selfProfile';
  import { fetchMyProfile } from '../lib/users';
  import { voiceRosters, loadVoiceRosters } from '../lib/voiceChannel';
  import { myServerPermissions } from '../lib/roles';
  import { autofocus } from '../lib/actions';
  import ServerSettings from './ServerSettings.svelte';
  import ChannelOverwrites from './ChannelOverwrites.svelte';
  import Avatar from './Avatar.svelte';

  export let currentUser: any;
  export let activeServer: string | null = null;
  export let activeChannel: string | null = null;

  const dispatch = createEventDispatcher();

  interface Channel {
    id: string;
    server_id: string;
    name: string;
    channel_type: string;
    created_at: string;
    has_unread: boolean;
  }

  let channels: Channel[] = [];
  let loading = true;
  let showServerSettings = false;
  let showCreateChannelModal = false;
  let newChannelName = '';
  let newChannelType = 'text';
  let createChannelError = '';

  // Admins and above can rename and delete channels.
  let myRank = 1;
  $: canManageChannels = myRank >= 3;
  let renaming: Channel | null = null;
  let renameValue = '';
  let deleting: Channel | null = null;
  let channelActionError = '';
  let managingPermissions: Channel | null = null;

  // Per-channel overwrites need manage_channels or manage_roles -- same
  // server-wide resolved permissions the overwrite endpoints themselves
  // check (require_channel_overwrite_management in roles.rs), not just the
  // legacy rank myRank already covers.
  let myPermissions: string[] = [];
  $: canManageOverwrites =
    myPermissions.includes('administrator') ||
    myPermissions.includes('manage_channels') ||
    myPermissions.includes('manage_roles');

  $: if (activeServer) {
    loadChannels(activeServer);
    loadRank(activeServer);
    loadVoiceRosters(activeServer);
    loadMyPermissions(activeServer);
  }

  async function loadRank(serverId: string) {
    try {
      const res = await apiFetch(`${apiBase()}/api/v1/servers/${serverId}/role`);
      if (res.ok) myRank = (await res.json()).rank ?? 1;
    } catch {
      myRank = 1;
    }
  }

  async function loadMyPermissions(serverId: string) {
    try {
      myPermissions = await myServerPermissions(serverId);
    } catch {
      myPermissions = [];
    }
  }

  function startRename(channel: Channel) {
    renaming = channel;
    renameValue = channel.name;
    channelActionError = '';
  }

  async function submitRename(e: Event) {
    e.preventDefault();
    if (!renaming) return;
    const res = await apiFetch(`${apiBase()}/api/v1/channels/${renaming.id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: renameValue }),
    });
    if (res.ok) {
      const { id, name } = await res.json();
      channels = channels.map(c => (c.id === id ? { ...c, name } : c));
      renaming = null;
    } else {
      channelActionError = (await res.json().catch(() => ({}))).error || 'Could not rename channel';
    }
  }

  async function confirmDelete() {
    if (!deleting) return;
    const channel = deleting;
    const res = await apiFetch(`${apiBase()}/api/v1/channels/${channel.id}`, { method: 'DELETE' });
    if (res.ok) {
      removeChannel(channel.id);
      deleting = null;
    } else {
      channelActionError = (await res.json().catch(() => ({}))).error || 'Could not delete channel';
    }
  }

  function removeChannel(id: string) {
    channels = channels.filter(c => c.id !== id);
    if (id === activeChannel) dispatch('channelDeleted', id);
  }

  // Live channel changes from other people.
  function onChannelCreated(data: Channel) {
    if (data.server_id !== activeServer || channels.some(c => c.id === data.id)) return;
    channels = [...channels, { ...data, has_unread: false }];
  }
  function onChannelUpdated(data: { id: string; name: string }) {
    channels = channels.map(c => (c.id === data.id ? { ...c, name: data.name } : c));
  }
  function onChannelDeleted(data: { id: string }) {
    removeChannel(data.id);
  }
  function onMemberUpdated(data: { server_id: string; user_id: string }) {
    if (data.server_id === activeServer && data.user_id === currentUser?.id) loadRank(activeServer);
  }

  // A channel overwrite, a role's own permission bits, or a role being
  // created/deleted can all change which channels I can see or what I can
  // do with them -- re-derive everything for this server rather than
  // trying to work out client-side whether this particular change
  // actually affects me. These are infrequent admin actions, so an extra
  // fetch is cheap; sitting on a stale channel list (showing something I
  // just lost access to, or hiding something I just gained) is worse.
  function onPermissionsMayHaveChanged(data: { server_id: string }) {
    if (data.server_id !== activeServer) return;
    loadChannels(activeServer);
    loadRank(activeServer);
    loadMyPermissions(activeServer);
  }

  // Assigning/unassigning a role only matters here if it's MY role that
  // changed -- someone else gaining or losing a role doesn't affect what
  // I can see.
  function onMemberRoleChanged(data: { server_id: string; user_id: string }) {
    if (data.server_id === activeServer && data.user_id === currentUser?.id) {
      loadChannels(activeServer);
      loadRank(activeServer);
      loadMyPermissions(activeServer);
    }
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
    wsClient.on('channel_created', onChannelCreated);
    wsClient.on('channel_updated', onChannelUpdated);
    wsClient.on('channel_deleted', onChannelDeleted);
    wsClient.on('member_updated', onMemberUpdated);
    wsClient.on('channel_overwrite_changed', onPermissionsMayHaveChanged);
    wsClient.on('role_updated', onPermissionsMayHaveChanged);
    wsClient.on('role_deleted', onPermissionsMayHaveChanged);
    wsClient.on('member_role_assigned', onMemberRoleChanged);
    wsClient.on('member_role_unassigned', onMemberRoleChanged);
    // Seeds the self-avatar store with a freshly-signed URL -- a cached
    // one from an earlier login would have an expired signature.
    fetchMyProfile().then(p => selfAvatarUrl.set(p.avatar_url ?? null)).catch(() => {});
  });

  onDestroy(() => {
    wsClient.off('new_message', onNewMessage);
    wsClient.off('channel_created', onChannelCreated);
    wsClient.off('channel_updated', onChannelUpdated);
    wsClient.off('channel_deleted', onChannelDeleted);
    wsClient.off('member_updated', onMemberUpdated);
    wsClient.off('channel_overwrite_changed', onPermissionsMayHaveChanged);
    wsClient.off('role_updated', onPermissionsMayHaveChanged);
    wsClient.off('role_deleted', onPermissionsMayHaveChanged);
    wsClient.off('member_role_assigned', onMemberRoleChanged);
    wsClient.off('member_role_unassigned', onMemberRoleChanged);
  });

   async function loadChannels(serverId: string) {
    loading = true;
    try {
      const response = await apiFetch(`${apiBase()}/api/v1/servers/${serverId}/channels`, {
        headers: getAuthHeaders(), // <-- THIS LINE IS CRUCIAL
      });
      
      if (response.ok) {
        channels = await response.json();
        // If a permission change (or anything else) just dropped the
        // channel I was looking at out of this list, navigate away from
        // it rather than leaving its (now inaccessible) view on screen.
        if (activeChannel && !channels.some(c => c.id === activeChannel)) {
          dispatch('channelDeleted', activeChannel);
        }
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

  function handleChannelClick(channel: Channel) {
    dispatch('channelSelected', channel);
    channels = channels.map(c =>
      c.id === channel.id ? { ...c, has_unread: false } : c
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
        body: JSON.stringify({ name: newChannelName.trim(), channel_type: newChannelType }),
      });

      if (response.ok) {
        const newChannel = await response.json();
        if (!channels.some(c => c.id === newChannel.id)) channels = [...channels, newChannel];
        newChannelName = '';
        newChannelType = 'text';
        showCreateChannelModal = false;
        // Optionally auto-select the new channel
        dispatch('channelSelected', newChannel);
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

<aside class="flex-1 min-w-0 md:w-60 md:flex-none bg-[#0a0e0a] border-r-2 border-[#00ff00] flex flex-col h-full">
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
      {#each channels as channel (channel.id)}
        <div class="relative group mb-1">
        <button
          type="button"
          class="w-full text-left px-3 py-2 rounded border-l-2 transition-all flex items-center gap-2 {channel.id === activeChannel ? 'bg-[rgba(0,255,0,0.15)] border-[#00ff00]' : 'border-transparent hover:bg-[rgba(0,255,0,0.1)] ' + (channel.has_unread ? 'bg-[rgba(0,255,0,0.05)]' : '')} {canManageChannels && canManageOverwrites ? 'pr-20' : canManageChannels || canManageOverwrites ? 'pr-14' : ''}"
          aria-current={channel.id === activeChannel ? 'page' : undefined}
          on:click={() => handleChannelClick(channel)}
        >
          {#if channel.has_unread}
            <div class="w-2 h-2 bg-[#00ff00] rounded-full shadow-[0_0_8px_#00ff00] flex-shrink-0 animate-pulse"></div>
          {:else}
            <div class="w-2 h-2 flex-shrink-0"></div>
          {/if}

          <div class="flex-1 min-w-0">
            <!-- This highlight is the only indicator of which channel is open
                 (ChatArea's header no longer names it), so make "active"
                 look as distinct as "unread", not just a faint tint. -->
            <div class="text-sm terminal-glow truncate {channel.id === activeChannel || channel.has_unread ? 'text-[#00ff00] font-bold' : 'text-[#00aa00]'}">
              {channel.channel_type === 'voice' ? '🔊' : '#'} {channel.name}
            </div>
            {#if channel.channel_type === 'voice' && ($voiceRosters.get(channel.id)?.length ?? 0) > 0}
              <!-- Who's currently in this voice channel, Discord-style --
                   shown whether or not it's the active selection, since
                   "active" here only means "its panel is open", not
                   "connected" (see VoiceChannelView.svelte). -->
              <div class="text-xs text-[#006600] truncate pl-1">
                {#each $voiceRosters.get(channel.id) ?? [] as p (p.userId)}
                  <span class="mr-1">{p.muted ? '🔇' : '🎤'} {p.username}</span>
                {/each}
              </div>
            {/if}
          </div>
        </button>
        {#if canManageChannels || canManageOverwrites}
          <div class="absolute right-1 top-1/2 -translate-y-1/2 hidden group-hover:flex group-focus-within:flex gap-1">
            {#if canManageOverwrites}
              <button type="button" class="px-1.5 text-xs text-[#00aa00] hover:text-[#00ff00]" title="Channel permissions" aria-label="Permissions for {channel.name}" on:click={() => (managingPermissions = channel)}>🔒</button>
            {/if}
            {#if canManageChannels}
              <button type="button" class="px-1.5 text-xs text-[#00aa00] hover:text-[#00ff00]" title="Rename channel" aria-label="Rename {channel.name}" on:click={() => startRename(channel)}>✎</button>
              <button type="button" class="px-1.5 text-xs text-red-500 hover:text-red-400" title="Delete channel" aria-label="Delete {channel.name}" on:click={() => { deleting = channel; channelActionError = ''; }}>✕</button>
            {/if}
          </div>
        {/if}
        </div>
      {/each}
    {/if}
  </div>

  <!-- User Footer -->
  <div class="p-3 border-t-2 border-[#00ff00] bg-black">
    <div class="flex items-center gap-2">
      <Avatar
        url={$selfAvatarUrl}
        label={currentUser.username}
        className="w-8 h-8 border-2 border-[#00ff00] font-bold text-sm terminal-glow"
      />
      <div class="flex-1 min-w-0">
        <div class="text-xs text-[#00ff00] truncate terminal-glow">{currentUser.username}</div>
        <div class="text-[10px] text-[#00aa00] terminal-glow">Online</div>
      </div>
      <button
        type="button"
        class="w-7 h-7 flex-shrink-0 border border-[#00ff00] text-[#00ff00] flex items-center justify-center hover:bg-[#00ff00] hover:text-black transition-all terminal-glow"
        title="Logout"
        aria-label="Logout"
        on:click={handleLogout}
      >
        <svg xmlns="http://www.w3.org/2000/svg" class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18.36 6.64a9 9 0 1 1-12.73 0" />
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 2v10" />
        </svg>
      </button>
    </div>
  </div>

  <!-- Create Channel Modal -->
  {#if showCreateChannelModal}
    <!-- svelte-ignore a11y-no-noninteractive-element-interactions -->
    <div
      class="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm"
      on:click={() => showCreateChannelModal = false}
      on:keydown={(e) => e.key === 'Escape' && (showCreateChannelModal = false)}
      role="dialog" aria-modal="true" tabindex="-1"
    >
      <!-- svelte-ignore a11y-no-noninteractive-element-interactions -->
      <!-- svelte-ignore a11y-click-events-have-key-events -->
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
              placeholder="e.g., general" required use:autofocus
            />
          </div>
          <fieldset>
            <legend class="block text-xs text-[#00aa00] uppercase tracking-wider mb-1">Channel Type</legend>
            <div class="flex gap-4">
              <label class="flex items-center gap-1.5 text-sm text-[#00ff00]">
                <input type="radio" name="new-channel-type" value="text" bind:group={newChannelType} />
                # Text
              </label>
              <label class="flex items-center gap-1.5 text-sm text-[#00ff00]">
                <input type="radio" name="new-channel-type" value="voice" bind:group={newChannelType} />
                🔊 Voice
              </label>
            </div>
          </fieldset>
          {#if createChannelError}
            <div class="text-xs text-red-500 terminal-glow">{'>'} {createChannelError}</div>
          {/if}
          <div class="flex gap-2 pt-2">
            <button type="button" class="flex-1 py-2 border border-[#00aa00] text-[#00aa00] hover:bg-[#00aa00]/10 transition-all text-sm" on:click={() => { showCreateChannelModal = false; newChannelType = 'text'; }}>Cancel</button>
            <button type="submit" class="flex-1 py-2 bg-[#00ff00] text-black font-bold hover:bg-[#00aa00] transition-all text-sm terminal-glow">Create</button>
          </div>
        </form>
      </div>
    </div>
  {/if}

  {#if renaming}
    <div class="fixed inset-0 z-50 flex items-center justify-center bg-black/80" role="dialog" aria-modal="true" aria-labelledby="rename-title">
      <form class="w-[400px] max-w-[90vw] bg-black border-2 border-[#00ff00] p-6 space-y-4" on:submit={submitRename}>
        <h3 id="rename-title" class="text-sm font-bold text-[#00ff00] uppercase tracking-widest">{'>'} Rename #{renaming.name}</h3>
        <input bind:value={renameValue} aria-label="Channel name" maxlength="100" required class="w-full bg-[#0a0e0a] border border-[#00ff00] px-3 py-2 text-[#00ff00] focus:outline-none" />
        {#if channelActionError}<div class="text-xs text-red-500">{'>'} {channelActionError}</div>{/if}
        <div class="flex gap-2">
          <button type="button" class="flex-1 py-2 border border-[#00aa00] text-[#00aa00] text-sm" on:click={() => (renaming = null)}>Cancel</button>
          <button type="submit" class="flex-1 py-2 bg-[#00ff00] text-black font-bold text-sm">Rename</button>
        </div>
      </form>
    </div>
  {/if}

  {#if deleting}
    <div class="fixed inset-0 z-50 flex items-center justify-center bg-black/80" role="dialog" aria-modal="true" aria-labelledby="delete-channel-title">
      <div class="w-[400px] max-w-[90vw] bg-black border-2 border-red-500 p-6 space-y-4">
        <h3 id="delete-channel-title" class="text-sm font-bold text-red-500 uppercase tracking-widest">{'>'} Delete #{deleting.name}</h3>
        <p class="text-xs text-[#00aa00]">All messages and files in this channel will be deleted for everyone. This can't be undone.</p>
        {#if channelActionError}<div class="text-xs text-red-500">{'>'} {channelActionError}</div>{/if}
        <div class="flex gap-2">
          <button type="button" class="flex-1 py-2 border border-[#00aa00] text-[#00aa00] text-sm" on:click={() => (deleting = null)}>Cancel</button>
          <button type="button" class="flex-1 py-2 border-2 border-red-500 text-red-500 font-bold text-sm hover:bg-red-500 hover:text-black" on:click={confirmDelete}>Delete channel</button>
        </div>
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

  <!-- Channel Permissions Modal -->
  {#if managingPermissions && activeServer}
    <ChannelOverwrites
      channelId={managingPermissions.id}
      channelName={managingPermissions.name}
      serverId={activeServer}
      on:close={() => (managingPermissions = null)}
    />
  {/if}
</aside>
