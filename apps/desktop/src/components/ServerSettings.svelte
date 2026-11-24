<script lang="ts">
  import { createEventDispatcher, onMount } from 'svelte';
  import { getAuthHeaders, apiFetch, fileUrl, apiBase } from '../lib/api';
  import { wsClient } from '../lib/websocket';
  import { fetchServerEmojis, uploadEmoji, deleteEmoji, type CustomEmoji } from '../lib/emojis';
  import {
    listRoles,
    createRole,
    updateRole,
    deleteRole,
    myServerPermissions,
    PERMISSION_INFO,
    type Role,
  } from '../lib/roles';

  export let serverId: string;
  export let serverName: string = '';
  export let serverDescription: string = '';
  export let serverIconUrl: string = '';

  const dispatch = createEventDispatcher();

  let activeTab: 'overview' | 'emojis' | 'invites' | 'bans' | 'roles' = 'overview';

  // Your rank here: 4 owner, 3 admin, 2 moderator, 1 member.
  let myRank = 1;
  let isServerOwner = false;
  $: canModerate = myRank >= 2;
  $: canEditServer = myRank >= 3;

  // Resolved permission names (see permissions.rs) -- rank alone doesn't
  // account for a custom role granting MANAGE_ROLES to someone below admin
  // rank, so the Roles tab is gated on this instead of myRank.
  let myPermissions: string[] = [];
  $: canManageRoles = myPermissions.includes('administrator') || myPermissions.includes('manage_roles');

  interface Invite {
    code: string;
    created_by: string | null;
    created_at: string;
    expires_at: string | null;
    max_uses: number | null;
    uses: number;
  }
  interface Ban {
    user_id: string;
    username: string;
    reason: string | null;
    banned_by: string | null;
    created_at: string;
  }

  let invites: Invite[] = [];
  let bans: Ban[] = [];
  let inviteExpiryHours = '24';   // '' = never
  let inviteMaxUses = '';         // '' = unlimited
  let tabError = '';
  let copiedCode = '';
  let confirmLeave = false;
  let showDelete = false;
  let deleteConfirmName = '';
  let deletePassword = '';
  let deleteError = '';
  let deleteBusy = false;
  $: canDeleteServer = isServerOwner || myRank >= 5;

  async function deleteServer(e: Event) {
    e.preventDefault();
    deleteError = '';
    deleteBusy = true;
    try {
      const res = await apiFetch(`${apiBase()}/api/v1/servers/${serverId}`, {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ current_password: deletePassword }),
      });
      if (res.ok) {
        wsClient.emit('removed_from_server', { server_id: serverId, server_name: serverName, reason: 'deleted' });
        dispatch('close');
      } else {
        deleteError = await errorFrom(res, 'Could not delete server');
      }
    } catch (err: any) {
      deleteError = err.message || 'Network error';
    } finally {
      deleteBusy = false;
    }
  }

  async function errorFrom(res: Response, fallback: string): Promise<string> {
    const err = await res.json().catch(() => ({}));
    return err.error || fallback;
  }

  async function loadInvites() {
    tabError = '';
    const res = await apiFetch(`${apiBase()}/api/v1/servers/${serverId}/invites`);
    if (res.ok) invites = await res.json();
    else tabError = await errorFrom(res, 'Failed to load invites');
  }

  async function createInvite(e: Event) {
    e.preventDefault();
    tabError = '';
    const res = await apiFetch(`${apiBase()}/api/v1/servers/${serverId}/invites`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        expires_in_hours: inviteExpiryHours ? Number(inviteExpiryHours) : null,
        max_uses: inviteMaxUses ? Number(inviteMaxUses) : null,
      }),
    });
    if (res.ok) {
      const invite: Invite = await res.json();
      invites = [invite, ...invites];
      copyCode(invite.code);
    } else {
      tabError = await errorFrom(res, 'Failed to create invite');
    }
  }

  async function revokeInvite(code: string) {
    tabError = '';
    const res = await apiFetch(`${apiBase()}/api/v1/servers/${serverId}/invites/${code}`, { method: 'DELETE' });
    if (res.ok) invites = invites.filter(i => i.code !== code);
    else tabError = await errorFrom(res, 'Failed to revoke invite');
  }

  async function copyCode(code: string) {
    try {
      await navigator.clipboard.writeText(code);
      copiedCode = code;
      setTimeout(() => { if (copiedCode === code) copiedCode = ''; }, 2000);
    } catch {
      // Clipboard unavailable: the code is shown on screen to copy by hand.
    }
  }

  async function loadBans() {
    tabError = '';
    const res = await apiFetch(`${apiBase()}/api/v1/servers/${serverId}/bans`);
    if (res.ok) bans = await res.json();
    else tabError = await errorFrom(res, 'Failed to load bans');
  }

  async function unban(userId: string) {
    tabError = '';
    const res = await apiFetch(`${apiBase()}/api/v1/servers/${serverId}/bans/${userId}`, { method: 'DELETE' });
    if (res.ok) bans = bans.filter(b => b.user_id !== userId);
    else tabError = await errorFrom(res, 'Failed to lift ban');
  }

  async function leaveServer() {
    tabError = '';
    const res = await apiFetch(`${apiBase()}/api/v1/servers/${serverId}/members/me`, { method: 'DELETE' });
    if (res.ok) {
      // Same event the server sends, so every part of the app updates now.
      wsClient.emit('removed_from_server', { server_id: serverId, server_name: serverName, reason: 'left' });
      dispatch('close');
    } else {
      confirmLeave = false;
      tabError = await errorFrom(res, 'Failed to leave server');
    }
  }

  function formatExpiry(invite: Invite): string {
    if (!invite.expires_at) return 'never expires';
    const hours = (new Date(invite.expires_at).getTime() - Date.now()) / 3_600_000;
    if (hours < 1) return 'expires in under an hour';
    if (hours < 48) return `expires in ${Math.round(hours)}h`;
    return `expires in ${Math.round(hours / 24)} days`;
  }

  function switchTab(tab: typeof activeTab) {
    activeTab = tab;
    tabError = '';
    if (tab === 'emojis') loadEmojis();
    if (tab === 'invites') loadInvites();
    if (tab === 'bans') loadBans();
    if (tab === 'roles') loadRoles();
  }
  let emojis: CustomEmoji[] = [];
  let loading = false;
  let uploadName = '';
  let uploadFile: File | null = null;
  let uploadError = '';

  let loaded = false;

  onMount(async () => {
    try {
      const res = await apiFetch(`${apiBase()}/api/v1/servers/${serverId}/role`);
      if (res.ok) {
        const role = await res.json();
        myRank = role.rank ?? 1;
        isServerOwner = !!role.is_owner;
      }
    } catch {
      // keep the member view
    }
    try {
      myPermissions = await myServerPermissions(serverId);
    } catch {
      // Roles tab just stays hidden if this fails.
    }
    // Load the current values first. Saving the form sends every field, so
    // saving with unloaded defaults would wipe the server's real name/icon.
    try {
      const res = await apiFetch(`${apiBase()}/api/v1/servers/${serverId}`, {
        headers: getAuthHeaders(),
      });
      if (res.ok) {
        const server = await res.json();
        serverName = server.name ?? '';
        serverDescription = server.description ?? '';
        serverIconUrl = server.icon_url ?? '';
      }
    } catch (e) {
      console.error('Failed to load server settings:', e);
    } finally {
      loaded = true;
    }
    if (activeTab === 'emojis') loadEmojis();
  });

  async function loadEmojis() {
    loading = true;
    try {
      emojis = await fetchServerEmojis(serverId);
    } catch (e) {
      console.error(e);
    } finally {
      loading = false;
    }
  }

  async function handleSaveOverview(e: Event) {
    e.preventDefault();
    if (!loaded) return;
    const res = await apiFetch(`${apiBase()}/api/v1/servers/${serverId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
      body: JSON.stringify({
        name: serverName,
        description: serverDescription,
        icon_url: serverIconUrl
      })
    });
    if (res.ok) {
      dispatch('saved');
    } else {
      const err = await res.json().catch(() => ({}));
      alert(err.error || 'Failed to save server settings');
    }
  }

  // --- FIX: Dedicated handler for file input to avoid inline 'as' casting ---
  function handleFileChange(event: Event) {
    const target = event.target as HTMLInputElement;
    uploadFile = target.files?.[0] || null;
  }

  async function handleEmojiUpload(e: Event) {
    e.preventDefault();
    if (!uploadFile || !uploadName.trim()) return;
    
    uploadError = '';
    loading = true;
    try {
      await uploadEmoji(serverId, uploadName.trim(), uploadFile);
      uploadName = '';
      uploadFile = null;
      
      // Reset the file input visually
      const fileInput = document.getElementById('emoji-file-input') as HTMLInputElement;
      if (fileInput) fileInput.value = '';
      
      await loadEmojis();
    } catch (e: any) {
      uploadError = e.message;
    } finally {
      loading = false;
    }
  }

  async function handleDeleteEmoji(emojiId: string) {
    if (!confirm('Delete this emoji?')) return;
    try {
      await deleteEmoji(serverId, emojiId);
      await loadEmojis();
    } catch (e: any) {
      alert(e.message);
    }
  }

  // --- Roles ---

  let roles: Role[] = [];
  let rolesLoading = false;
  let rolesError = '';

  // null = form closed; otherwise the role being edited, or 'new' for create.
  let editingRole: Role | 'new' | null = null;
  let formName = '';
  let formColor = '#99aab5';
  let formPermissions = new Set<string>();
  let roleFormError = '';
  let roleFormBusy = false;

  // Only permissions the actor holds themselves are offered -- the server
  // rejects granting a bit you don't hold yourself (see reject_ungranted_bits
  // in roles.rs), so there's no point showing a checkbox that would just error.
  $: grantablePermissions = PERMISSION_INFO.filter(
    p => myPermissions.includes('administrator') || myPermissions.includes(p.name),
  );

  async function loadRoles() {
    rolesLoading = true;
    rolesError = '';
    try {
      roles = await listRoles(serverId);
    } catch (e: any) {
      rolesError = e.message;
    } finally {
      rolesLoading = false;
    }
  }

  function openCreateRole() {
    editingRole = 'new';
    formName = '';
    formColor = '#99aab5';
    formPermissions = new Set();
    roleFormError = '';
  }

  function openEditRole(role: Role) {
    editingRole = role;
    formName = role.name;
    formColor = role.color || '#99aab5';
    formPermissions = new Set(role.permissions);
    roleFormError = '';
  }

  function closeRoleForm() {
    editingRole = null;
    roleFormError = '';
  }

  function togglePermission(name: string) {
    const next = new Set(formPermissions);
    if (next.has(name)) next.delete(name);
    else next.add(name);
    formPermissions = next;
  }

  async function saveRole(e: Event) {
    e.preventDefault();
    const name = formName.trim();
    if (!name) return;
    roleFormBusy = true;
    roleFormError = '';
    try {
      const payload = { name, color: formColor, permissions: Array.from(formPermissions) };
      if (editingRole === 'new') {
        await createRole(serverId, payload);
      } else if (editingRole) {
        await updateRole(serverId, editingRole.id, payload);
      }
      editingRole = null;
      await loadRoles();
    } catch (e: any) {
      roleFormError = e.message;
    } finally {
      roleFormBusy = false;
    }
  }

  async function handleDeleteRole(role: Role) {
    if (!confirm(`Delete the "${role.name}" role? Members who have it will lose its permissions.`)) return;
    rolesError = '';
    try {
      await deleteRole(serverId, role.id);
      await loadRoles();
    } catch (e: any) {
      rolesError = e.message;
    }
  }

  // Moves a role up/down by swapping its position with its neighbor in the
  // (position DESC) list -- the default role is excluded (its position is
  // fixed server-side) and is always last, so it's never a swap target.
  async function moveRole(index: number, direction: -1 | 1) {
    const other = index + direction;
    if (other < 0 || other >= roles.length) return;
    const a = roles[index];
    const b = roles[other];
    if (a.is_default || b.is_default) return;
    rolesError = '';
    try {
      await Promise.all([
        updateRole(serverId, a.id, { position: b.position }),
        updateRole(serverId, b.id, { position: a.position }),
      ]);
      await loadRoles();
    } catch (e: any) {
      rolesError = e.message;
    }
  }
</script>

<!-- Outer Backdrop: Added on:keydown for A11y -->
<div 
  class="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm" 
  on:click={() => dispatch('close')} 
  on:keydown={(e) => e.key === 'Escape' && dispatch('close')}
  role="dialog" 
  aria-modal="true"
  tabindex="-1"
>
  <!-- Inner Modal Content -->
  <div 
    class="relative w-[600px] max-w-[90vw] max-h-[80vh] bg-black border-2 border-[#00ff00] shadow-[0_0_30px_rgba(0,255,0,0.4)] flex flex-col" 
    on:click|stopPropagation 
    on:keydown|stopPropagation
    role="document"
  >
    
    <!-- Header -->
    <div class="p-4 border-b border-[#00ff00] flex items-center justify-between">
      <h3 class="font-bold uppercase tracking-widest text-sm terminal-glow text-[#00ff00]">{'>'} Server Settings</h3>
      <button 
        class="text-[#00ff00] hover:text-red-500 terminal-glow transition-colors" 
        on:click={() => dispatch('close')}
        aria-label="Close settings"
      >
        ✕
      </button>
    </div>

    <!-- Tabs -->
    <div class="flex border-b border-[#00aa00]/30">
      <button 
        class="flex-1 py-3 text-sm font-semibold {activeTab === 'overview' ? 'text-[#00ff00] border-b-2 border-[#00ff00] bg-[rgba(0,255,0,0.05)]' : 'text-[#00aa00] hover:text-[#00ff00]'}" 
        on:click={() => switchTab('overview')}
      >
        Overview
      </button>
      <button 
        class="flex-1 py-3 text-sm font-semibold {activeTab === 'emojis' ? 'text-[#00ff00] border-b-2 border-[#00ff00] bg-[rgba(0,255,0,0.05)]' : 'text-[#00aa00] hover:text-[#00ff00]'}" 
        on:click={() => switchTab('emojis')}
      >
        Emojis
      </button>
      {#if canModerate}
        <button
          class="flex-1 py-3 text-sm font-semibold {activeTab === 'invites' ? 'text-[#00ff00] border-b-2 border-[#00ff00] bg-[rgba(0,255,0,0.05)]' : 'text-[#00aa00] hover:text-[#00ff00]'}"
          on:click={() => switchTab('invites')}
        >
          Invites
        </button>
        <button
          class="flex-1 py-3 text-sm font-semibold {activeTab === 'bans' ? 'text-[#00ff00] border-b-2 border-[#00ff00] bg-[rgba(0,255,0,0.05)]' : 'text-[#00aa00] hover:text-[#00ff00]'}"
          on:click={() => switchTab('bans')}
        >
          Bans
        </button>
      {/if}
      {#if canManageRoles}
        <button
          class="flex-1 py-3 text-sm font-semibold {activeTab === 'roles' ? 'text-[#00ff00] border-b-2 border-[#00ff00] bg-[rgba(0,255,0,0.05)]' : 'text-[#00aa00] hover:text-[#00ff00]'}"
          on:click={() => switchTab('roles')}
        >
          Roles
        </button>
      {/if}
    </div>

    <!-- Content -->
    <div class="flex-1 overflow-y-auto p-6 custom-scrollbar">
      {#if activeTab === 'overview'}
        <form on:submit={handleSaveOverview} class="space-y-4">
          <div>
            <label for="server-name" class="block text-xs text-[#00aa00] uppercase tracking-wider mb-1">Server Name</label>
            <input id="server-name" disabled={!canEditServer} bind:value={serverName} type="text" class="w-full bg-[#0a0e0a] border border-[#00ff00] px-3 py-2 text-[#00ff00] focus:outline-none focus:shadow-[0_0_10px_rgba(0,255,0,0.3)]" required />
          </div>
          <div>
            <label for="server-desc" class="block text-xs text-[#00aa00] uppercase tracking-wider mb-1">Description</label>
            <textarea id="server-desc" disabled={!canEditServer} bind:value={serverDescription} rows="3" class="w-full bg-[#0a0e0a] border border-[#00ff00] px-3 py-2 text-[#00ff00] focus:outline-none focus:shadow-[0_0_10px_rgba(0,255,0,0.3)] resize-none"></textarea>
          </div>
          <div>
            <label for="server-icon" class="block text-xs text-[#00aa00] uppercase tracking-wider mb-1">Icon URL</label>
            <input id="server-icon" disabled={!canEditServer} bind:value={serverIconUrl} type="text" class="w-full bg-[#0a0e0a] border border-[#00ff00] px-3 py-2 text-[#00ff00] focus:outline-none focus:shadow-[0_0_10px_rgba(0,255,0,0.3)]" placeholder="https://example.com/icon.png" />
          </div>
          {#if canEditServer}
            <button type="submit" class="w-full py-2 bg-black border-2 border-[#00ff00] text-[#00ff00] font-semibold uppercase tracking-wider hover:bg-[#00ff00] hover:text-black transition-all terminal-glow">Save Changes</button>
          {:else}
            <p class="text-xs text-[#00aa00]">{'>'} Only admins can change these settings.</p>
          {/if}
        </form>

        {#if tabError}
          <div class="mt-4 text-xs text-red-500">{'>'} {tabError}</div>
        {/if}

        {#if loaded && !isServerOwner}
          <div class="mt-8 pt-4 border-t border-red-500/40">
            {#if confirmLeave}
              <p class="text-xs text-red-400 mb-2">{'>'} Leave {serverName}? You'll need a new invite to come back.</p>
              <div class="flex gap-2">
                <button type="button" class="flex-1 py-2 border border-[#00aa00] text-[#00aa00] text-sm hover:bg-[#00aa00]/10" on:click={() => (confirmLeave = false)}>Cancel</button>
                <button type="button" class="flex-1 py-2 border-2 border-red-500 text-red-500 text-sm font-bold hover:bg-red-500 hover:text-black" on:click={leaveServer}>Leave</button>
              </div>
            {:else}
              <button type="button" class="w-full py-2 border border-red-500 text-red-500 text-sm uppercase tracking-wider hover:bg-red-500 hover:text-black transition-all" on:click={() => (confirmLeave = true)}>Leave server</button>
            {/if}
          </div>
        {/if}
        {#if loaded && canDeleteServer}
          <div class="mt-8 pt-4 border-t border-red-500/40">
            {#if showDelete}
              <form on:submit={deleteServer} class="space-y-3">
                <p class="text-xs text-red-400">{'>'} This deletes {serverName} for everyone: all channels, messages, files, emojis and invites. It can't be undone.</p>
                <div>
                  <label for="delete-confirm-name" class="block text-xs text-[#00aa00] uppercase tracking-wider mb-1">Type the server name to confirm</label>
                  <input id="delete-confirm-name" bind:value={deleteConfirmName} autocomplete="off" class="w-full bg-[#0a0e0a] border border-red-500 px-3 py-2 text-[#00ff00] text-sm focus:outline-none" placeholder={serverName} />
                </div>
                <div>
                  <label for="delete-password" class="block text-xs text-[#00aa00] uppercase tracking-wider mb-1">Your password</label>
                  <input id="delete-password" type="password" bind:value={deletePassword} autocomplete="current-password" class="w-full bg-[#0a0e0a] border border-red-500 px-3 py-2 text-[#00ff00] text-sm focus:outline-none" />
                </div>
                {#if deleteError}<div class="text-xs text-red-500">{'>'} {deleteError}</div>{/if}
                <div class="flex gap-2">
                  <button type="button" class="flex-1 py-2 border border-[#00aa00] text-[#00aa00] text-sm" on:click={() => { showDelete = false; deleteConfirmName = deletePassword = ''; }}>Cancel</button>
                  <button type="submit" disabled={deleteBusy || deleteConfirmName !== serverName || !deletePassword} class="flex-1 py-2 border-2 border-red-500 text-red-500 font-bold text-sm hover:bg-red-500 hover:text-black disabled:opacity-40">Delete server</button>
                </div>
              </form>
            {:else}
              <button type="button" class="w-full py-2 border border-red-500 text-red-500 text-sm uppercase tracking-wider hover:bg-red-500 hover:text-black transition-all" on:click={() => (showDelete = true)}>Delete server</button>
            {/if}
          </div>
        {/if}
      {:else if activeTab === 'emojis'}
        <!-- Emoji Upload -->
        <form on:submit={handleEmojiUpload} class="mb-6 p-4 border border-[#00aa00]/30 bg-[#0a0e0a]">
          <h4 class="text-xs text-[#00aa00] uppercase tracking-wider mb-3">Upload New Emoji</h4>
          <div class="flex gap-2 mb-2">
            <input 
              bind:value={uploadName} 
              type="text" 
              placeholder="emoji_name" 
              class="flex-1 bg-black border border-[#00ff00] px-3 py-2 text-[#00ff00] text-sm focus:outline-none" 
              required 
              pattern="[a-z0-9_]+" 
              title="Lowercase letters, numbers, and underscores only" 
            />
            <!-- FIX: Uses the dedicated handleFileChange function instead of inline 'as' -->
            <input 
              id="emoji-file-input"
              type="file" 
              accept="image/*" 
              on:change={handleFileChange} 
              class="flex-1 text-xs text-[#00aa00] file:mr-2 file:py-1 file:px-2 file:rounded file:border file:border-[#00ff00] file:bg-black file:text-[#00ff00] file:cursor-pointer" 
              required 
            />
          </div>
          {#if uploadError}
            <div class="text-xs text-red-500 mb-2">{uploadError}</div>
          {/if}
          <button type="submit" disabled={loading || !uploadFile} class="px-4 py-1.5 bg-black border border-[#00ff00] text-[#00ff00] text-xs hover:bg-[#00ff00] hover:text-black transition-all disabled:opacity-50">Upload</button>
        </form>

        <!-- Emoji Grid -->
        {#if loading}
          <div class="text-[#00aa00] text-xs animate-pulse">{'>'} Loading emojis...</div>
        {:else if emojis.length === 0}
          <div class="text-[#00aa00] text-xs">{'>'} No custom emojis yet.</div>
        {:else}
          <div class="grid grid-cols-4 gap-4">
            {#each emojis as emoji}
              <div class="relative group bg-[#0a0e0a] border border-[#00aa00]/30 p-2 flex flex-col items-center">
                <img src={fileUrl(emoji.url)} alt={emoji.name} class="w-12 h-12 object-contain mb-2" />
                <span class="text-[10px] text-[#00aa00] text-center truncate w-full">:{emoji.name}:</span>
                <button 
                  class="absolute top-1 right-1 text-red-500 hover:text-red-400 opacity-0 group-hover:opacity-100 transition-opacity" 
                  on:click={() => handleDeleteEmoji(emoji.id)} 
                  title="Delete"
                  aria-label="Delete emoji"
                >
                  ✕
                </button>
              </div>
            {/each}
          </div>
        {/if}
      {:else if activeTab === 'invites'}
        <form on:submit={createInvite} class="flex flex-wrap items-end gap-3 mb-6">
          <div>
            <label for="invite-expiry" class="block text-xs text-[#00aa00] uppercase tracking-wider mb-1">Expires</label>
            <select id="invite-expiry" bind:value={inviteExpiryHours} class="bg-[#0a0e0a] border border-[#00ff00] px-2 py-1.5 text-[#00ff00] text-sm">
              <option value="1">After 1 hour</option>
              <option value="24">After 1 day</option>
              <option value="168">After 7 days</option>
              <option value="720">After 30 days</option>
              <option value="">Never</option>
            </select>
          </div>
          <div>
            <label for="invite-uses" class="block text-xs text-[#00aa00] uppercase tracking-wider mb-1">Max uses</label>
            <select id="invite-uses" bind:value={inviteMaxUses} class="bg-[#0a0e0a] border border-[#00ff00] px-2 py-1.5 text-[#00ff00] text-sm">
              <option value="">No limit</option>
              <option value="1">1 use</option>
              <option value="5">5 uses</option>
              <option value="10">10 uses</option>
              <option value="25">25 uses</option>
              <option value="100">100 uses</option>
            </select>
          </div>
          <button type="submit" class="px-4 py-1.5 bg-[#00ff00] text-black text-sm font-bold hover:bg-[#00aa00] transition-all">Create invite</button>
        </form>

        {#if tabError}
          <div class="mb-4 text-xs text-red-500">{'>'} {tabError}</div>
        {/if}

        {#if invites.length === 0}
          <div class="text-[#00aa00] text-xs">{'>'} No active invites. Create one and share the code.</div>
        {:else}
          <ul class="space-y-2">
            {#each invites as invite (invite.code)}
              <li class="flex items-center gap-3 bg-[#0a0e0a] border border-[#00aa00]/30 px-3 py-2">
                <code class="text-[#00ff00] text-base tracking-wider select-all">{invite.code}</code>
                <span class="flex-1 text-[11px] text-[#00aa00]">
                  {invite.uses}{invite.max_uses ? ` / ${invite.max_uses}` : ''} used · {formatExpiry(invite)}{invite.created_by ? ` · by ${invite.created_by}` : ''}
                </span>
                <button type="button" class="px-2 py-1 text-xs border border-[#00ff00] text-[#00ff00] hover:bg-[#00ff00] hover:text-black" on:click={() => copyCode(invite.code)}>
                  {copiedCode === invite.code ? 'Copied' : 'Copy'}
                </button>
                <button type="button" class="px-2 py-1 text-xs border border-red-500 text-red-500 hover:bg-red-500 hover:text-black" on:click={() => revokeInvite(invite.code)}>Revoke</button>
              </li>
            {/each}
          </ul>
        {/if}
      {:else if activeTab === 'bans'}
        {#if tabError}
          <div class="mb-4 text-xs text-red-500">{'>'} {tabError}</div>
        {/if}
        {#if bans.length === 0}
          <div class="text-[#00aa00] text-xs">{'>'} Nobody is banned from this server. Ban people from the member list.</div>
        {:else}
          <ul class="space-y-2">
            {#each bans as ban (ban.user_id)}
              <li class="flex items-center gap-3 bg-[#0a0e0a] border border-[#00aa00]/30 px-3 py-2">
                <div class="flex-1 min-w-0">
                  <div class="text-sm text-[#00ff00]">{ban.username}</div>
                  <div class="text-[11px] text-[#00aa00] truncate">
                    {ban.reason ? ban.reason : 'No reason given'} · {new Date(ban.created_at).toLocaleDateString()}{ban.banned_by ? ` · by ${ban.banned_by}` : ''}
                  </div>
                </div>
                <button type="button" class="px-2 py-1 text-xs border border-[#00ff00] text-[#00ff00] hover:bg-[#00ff00] hover:text-black" on:click={() => unban(ban.user_id)}>Unban</button>
              </li>
            {/each}
          </ul>
        {/if}
      {:else if activeTab === 'roles'}
        {#if rolesError}
          <div class="mb-4 text-xs text-red-500">{'>'} {rolesError}</div>
        {/if}

        {#if editingRole}
          <!-- Create/edit role form -->
          <form on:submit={saveRole} class="mb-6 p-4 border border-[#00aa00]/30 bg-[#0a0e0a] space-y-3">
            <h4 class="text-xs text-[#00aa00] uppercase tracking-wider">
              {editingRole === 'new' ? 'New Role' : `Edit "${editingRole.name}"`}
            </h4>
            <div class="flex gap-3 items-end">
              <div class="flex-1">
                <label for="role-name" class="block text-xs text-[#00aa00] uppercase tracking-wider mb-1">Name</label>
                <input id="role-name" bind:value={formName} type="text" maxlength="50" required
                  class="w-full bg-black border border-[#00ff00] px-3 py-2 text-[#00ff00] text-sm focus:outline-none" />
              </div>
              <div>
                <label for="role-color" class="block text-xs text-[#00aa00] uppercase tracking-wider mb-1">Color</label>
                <input id="role-color" bind:value={formColor} type="color"
                  class="w-12 h-[38px] bg-black border border-[#00ff00] cursor-pointer" />
              </div>
            </div>
            <div>
              <div class="block text-xs text-[#00aa00] uppercase tracking-wider mb-2">Permissions</div>
              <div class="grid grid-cols-2 gap-x-4 gap-y-1 max-h-48 overflow-y-auto pr-2 custom-scrollbar">
                {#each grantablePermissions as perm}
                  <label class="flex items-start gap-2 text-xs text-[#00ff00] py-1 cursor-pointer" title={perm.description}>
                    <input
                      type="checkbox"
                      checked={formPermissions.has(perm.name)}
                      on:change={() => togglePermission(perm.name)}
                      class="mt-0.5 accent-[#00ff00]"
                    />
                    <span>{perm.label}</span>
                  </label>
                {/each}
              </div>
              {#if grantablePermissions.length < PERMISSION_INFO.length}
                <p class="text-[10px] text-[#00aa00]/70 mt-2">{'>'} Only showing permissions you hold yourself -- you can't grant what you don't have.</p>
              {/if}
            </div>
            {#if roleFormError}
              <div class="text-xs text-red-500">{'>'} {roleFormError}</div>
            {/if}
            <div class="flex gap-2">
              <button type="button" class="flex-1 py-2 border border-[#00aa00] text-[#00aa00] text-sm" on:click={closeRoleForm}>Cancel</button>
              <button type="submit" disabled={roleFormBusy || !formName.trim()} class="flex-1 py-2 bg-[#00ff00] text-black font-bold text-sm hover:bg-[#00aa00] disabled:opacity-40">
                {editingRole === 'new' ? 'Create role' : 'Save changes'}
              </button>
            </div>
          </form>
        {:else}
          <button type="button" class="w-full mb-4 py-2 bg-black border-2 border-[#00ff00] text-[#00ff00] font-semibold uppercase tracking-wider hover:bg-[#00ff00] hover:text-black transition-all terminal-glow" on:click={openCreateRole}>
            + New Role
          </button>
        {/if}

        {#if rolesLoading}
          <div class="text-[#00aa00] text-xs animate-pulse">{'>'} Loading roles...</div>
        {:else if roles.length === 0}
          <div class="text-[#00aa00] text-xs">{'>'} No custom roles yet.</div>
        {:else}
          <ul class="space-y-2">
            {#each roles as role, i (role.id)}
              <li class="flex items-center gap-3 bg-[#0a0e0a] border border-[#00aa00]/30 px-3 py-2">
                <span class="w-3 h-3 rounded-full flex-shrink-0" style="background-color: {role.color || '#99aab5'}"></span>
                <div class="flex-1 min-w-0">
                  <div class="text-sm text-[#00ff00] truncate">{role.name}{role.is_default ? ' (default)' : ''}</div>
                  <div class="text-[11px] text-[#00aa00] truncate">
                    {role.permissions.length === 0 ? 'No permissions' : role.permissions.join(', ')}
                  </div>
                </div>
                {#if !role.is_default}
                  <div class="flex flex-col">
                    <button type="button" class="text-[#00aa00] hover:text-[#00ff00] disabled:opacity-20 leading-none" disabled={i === 0} on:click={() => moveRole(i, -1)} title="Move up" aria-label="Move role up">▲</button>
                    <button type="button" class="text-[#00aa00] hover:text-[#00ff00] disabled:opacity-20 leading-none" disabled={i === roles.length - 1 || roles[i + 1]?.is_default} on:click={() => moveRole(i, 1)} title="Move down" aria-label="Move role down">▼</button>
                  </div>
                {/if}
                <button type="button" class="px-2 py-1 text-xs border border-[#00ff00] text-[#00ff00] hover:bg-[#00ff00] hover:text-black" on:click={() => openEditRole(role)}>Edit</button>
                {#if !role.is_default}
                  <button type="button" class="px-2 py-1 text-xs border border-red-500 text-red-500 hover:bg-red-500 hover:text-black" on:click={() => handleDeleteRole(role)}>Delete</button>
                {/if}
              </li>
            {/each}
          </ul>
        {/if}
      {/if}
    </div>
  </div>
</div>
