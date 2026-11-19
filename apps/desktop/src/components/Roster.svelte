<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { getAuthHeaders, apiFetch, apiBase } from '../lib/api';
  import { wsClient } from '../lib/websocket';
  import { fetchUserProfile, type UserProfile } from '../lib/users';
  import PatronBadge from './PatronBadge.svelte';
  import UserProfileModal from './UserProfileModal.svelte';

  export let serverId: string | null = null;
  export let currentUser: any = null;

  interface Member {
    id: string;
    username: string;
    is_online: boolean;
    status: string;
    role: string;
    is_owner: boolean;
    is_site_owner: boolean;
    patron_tier: string;
  }

  let members: Member[] = [];
  let loading = true;
  let myRank = 1;

  // Viewing a member's profile (read-only; separate from the Manage dialog).
  let viewingProfile: UserProfile | null = null;
  let profileError = '';
  // Guards against a slower earlier request clobbering a faster later one
  // if someone clicks two different members in quick succession -- only the
  // most recently issued request is allowed to apply its result.
  let profileRequestId = 0;

  async function openProfile(member: Member) {
    const requestId = ++profileRequestId;
    profileError = '';
    try {
      const profile = await fetchUserProfile(member.id);
      if (requestId === profileRequestId) viewingProfile = profile;
    } catch (err: any) {
      if (requestId === profileRequestId) profileError = err.message || 'Failed to load profile';
    }
  }

  // owner > admin > moderator > member; you can only act on lower ranks.
  function rankOf(m: Member): number {
    if (m.is_site_owner) return 5;
    if (m.is_owner || m.role === 'owner') return 4;
    return m.role === 'admin' ? 3 : m.role === 'moderator' ? 2 : 1;
  }
  function roleLabel(m: Member): string {
    if (m.is_site_owner) return 'Site owner';
    return m.is_owner ? 'Owner' : m.role;
  }
  $: canActOn = (m: Member) => myRank >= 2 && m.id !== currentUser?.id && rankOf(m) < myRank;

  // Manage-member dialog: role, kick, ban, transfer ownership.
  let isServerOwner = false;
  let managing: Member | null = null;
  let mode: 'menu' | 'kick' | 'ban' | 'transfer' = 'menu';
  let newRole = 'member';
  let banReason = '';
  let transferPassword = '';
  let actionError = '';
  let actionBusy = false;

  // Roles you can give: strictly below your own rank.
  $: assignableRoles = [
    { value: 'member', label: 'Member', rank: 1 },
    { value: 'moderator', label: 'Moderator', rank: 2 },
    { value: 'admin', label: 'Admin', rank: 3 },
  ].filter(r => r.rank < myRank);
  $: canChangeRoles = myRank >= 3;
  $: canTransfer = isServerOwner || myRank >= 5;

  function openManage(member: Member) {
    managing = member;
    mode = 'menu';
    newRole = member.role === 'owner' ? 'admin' : member.role;
    banReason = transferPassword = actionError = '';
  }

  async function act(request: () => Promise<Response>, onSuccess: () => void) {
    actionBusy = true;
    actionError = '';
    try {
      const res = await request();
      if (res.ok) {
        onSuccess();
        managing = null;
      } else {
        actionError = (await res.json().catch(() => ({}))).error || 'Something went wrong';
      }
    } catch (e: any) {
      actionError = e.message || 'Network error';
    } finally {
      actionBusy = false;
    }
  }

  const base = () => `${apiBase()}/api/v1/servers/${serverId}`;
  const json = (method: string, body: unknown) => ({ method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });

  function saveRole() {
    const m = managing!;
    act(() => apiFetch(`${base()}/members/${m.id}/role`, json('PATCH', { role: newRole })),
      () => (members = members.map(x => (x.id === m.id ? { ...x, role: newRole } : x))));
  }
  function kick() {
    const m = managing!;
    act(() => apiFetch(`${base()}/members/${m.id}`, { method: 'DELETE' }),
      () => (members = members.filter(x => x.id !== m.id)));
  }
  function ban() {
    const m = managing!;
    act(() => apiFetch(`${base()}/bans`, json('POST', { user_id: m.id, reason: banReason.trim() || null })),
      () => (members = members.filter(x => x.id !== m.id)));
  }
  function transfer() {
    const m = managing!;
    act(() => apiFetch(`${base()}/transfer`, json('POST', { user_id: m.id, current_password: transferPassword })),
      () => { if (serverId) { loadMembers(serverId); loadMyRank(serverId); } });
  }

  async function loadMyRank(id: string) {
    try {
      const res = await apiFetch(`${apiBase()}/api/v1/servers/${id}/role`);
      if (res.ok) {
        const role = await res.json();
        myRank = role.rank ?? 1;
        isServerOwner = !!role.is_owner;
      }
    } catch {
      myRank = 1;
    }
  }

  const statusOrder = ['online', 'idle', 'busy', 'away', 'invisible', 'offline'];

  const statusConfig = {
    online: { label: 'Online', color: '#00ff00', glow: '0 0 8px #00ff00' },
    idle: { label: 'Idle', color: '#ffaa00', glow: '0 0 8px #ffaa00' },
    busy: { label: 'Busy', color: '#ff0000', glow: '0 0 8px #ff0000' },
    away: { label: 'Away', color: '#ff6600', glow: '0 0 8px #ff6600' },
    invisible: { label: 'Invisible', color: '#666666', glow: '0 0 8px #666666' },
    offline: { label: 'Offline', color: '#444444', glow: 'none' }
  };

  $: if (serverId) {
    loadMembers(serverId);
    loadMyRank(serverId);
  }

  // Someone joined, left, was kicked, banned or had their role changed.
  function onMembershipChange(data: { server_id: string; user_id?: string }) {
    if (!serverId || data.server_id !== serverId) return;
    loadMembers(serverId);
    if (data.user_id === currentUser?.id) loadMyRank(serverId);
  }

  // Someone came online, went offline or changed status.
  function onPresence(data: { user_id: string; status: string }) {
    members = members.map(m =>
      m.id === data.user_id ? { ...m, status: data.status, is_online: data.status !== 'offline' } : m
    );
  }

  onMount(() => {
    wsClient.connect();
    wsClient.on('presence_updated', onPresence);
    wsClient.on('member_joined', onMembershipChange);
    wsClient.on('member_left', onMembershipChange);
    wsClient.on('member_updated', onMembershipChange);
  });

  onDestroy(() => {
    wsClient.off('presence_updated', onPresence);
    wsClient.off('member_joined', onMembershipChange);
    wsClient.off('member_left', onMembershipChange);
    wsClient.off('member_updated', onMembershipChange);
  });

  $: groupedMembers = statusOrder.map(status => ({
    status,
    config: statusConfig[status as keyof typeof statusConfig],
    members: members.filter(m => m.status === status)
  })).filter(group => group.members.length > 0);

  async function loadMembers(id: string) {
    loading = members.length === 0;
    try {
      const response = await apiFetch(`${apiBase()}/api/v1/servers/${id}/members`, {
        headers: getAuthHeaders(),
      });
      if (response.ok) {
        members = await response.json();
      }
    } catch (e) {
      console.error('Failed to load members:', e);
    } finally {
      loading = false;
    }
  }
</script>

<aside class="w-60 bg-[#0a0e0a] border-l-2 border-[#00ff00] flex flex-col h-full shadow-[-10px_0_30px_rgba(0,255,0,0.2)]">
  <!-- Header -->
  <div class="p-4 border-b-2 border-[#00ff00] flex items-center">
    <h3 class="text-xs font-semibold text-[#00aa00] uppercase tracking-widest terminal-glow">
      {'>'} Members — {members.length}
    </h3>
  </div>

  <div class="flex-1 overflow-y-auto p-2 custom-scrollbar">
    {#if loading}
      <div class="flex items-center justify-center py-8">
        <div class="animate-pulse border-2 border-[#00ff00] w-6 h-6"></div>
      </div>
    {:else if members.length === 0}
      <div class="text-center text-[#00aa00] text-sm py-8 px-4 terminal-glow">
        {'>'} No members found
      </div>
    {:else}
      {#each groupedMembers as group}
        <!-- Status Section Header -->
        <div class="px-2 py-2 mt-3 mb-1">
          <h4 class="text-xs font-semibold uppercase tracking-wider terminal-glow" style="color: {group.config.color};">
            {'>'} {group.config.label} — {group.members.length}
          </h4>
        </div>

        <!-- Members in this status -->
        {#each group.members as member}
          <div
            class="group flex items-center gap-3 px-2 py-2 rounded hover:bg-[rgba(0,255,0,0.05)] transition-colors cursor-pointer"
            role="button"
            tabindex="0"
            aria-label="View {member.username}'s profile"
            on:click={() => openProfile(member)}
            on:keydown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), openProfile(member))}
          >
            <div class="relative">
              <div class="w-8 h-8 border-2 border-[#00ff00] flex items-center justify-center font-bold text-sm terminal-glow">
                {member.username[0].toUpperCase()}
              </div>

              <!-- Status Indicator -->
              <div
                class="absolute bottom-0 right-0 w-3 h-3 border-2 border-[#0a0e0a] rounded-full"
                style="background-color: {group.config.color}; box-shadow: {group.config.glow};"
              ></div>
            </div>

            <div class="flex-1 min-w-0 flex items-center gap-1">
              <div class="text-sm font-medium text-[#00ff00] truncate terminal-glow">
                {member.username}
              </div>
              {#if member.patron_tier && member.patron_tier !== 'free'}
                <PatronBadge tier={member.patron_tier} size="small" />
              {/if}
            </div>

            <div class="flex items-center gap-2">
              <div class="text-xs text-[#00aa00] capitalize terminal-glow group-hover:hidden">
                {roleLabel(member)}
              </div>
              {#if canActOn(member)}
                <button type="button" class="hidden group-hover:block group-focus-within:block text-[10px] px-1.5 py-0.5 border border-[#00ff00] text-[#00ff00] hover:bg-[#00ff00] hover:text-black" aria-label="Manage {member.username}" on:click|stopPropagation={() => openManage(member)}>Manage</button>
              {:else}
                <div class="hidden group-hover:block text-xs text-[#00aa00] capitalize terminal-glow">{roleLabel(member)}</div>
              {/if}
            </div>
          </div>
        {/each}
      {/each}
    {/if}
  </div>

  {#if managing}
    {@const m = managing}
    <div class="fixed inset-0 z-[100] flex items-center justify-center bg-black/80" role="dialog" aria-modal="true" aria-labelledby="manage-title">
      <div class="w-[420px] max-w-[92vw] bg-black border-2 {mode === 'ban' || mode === 'transfer' ? 'border-red-500' : mode === 'kick' ? 'border-[#ffaa00]' : 'border-[#00ff00]'} p-6 space-y-4">
        <div class="flex items-center justify-between">
          <h3 id="manage-title" class="font-bold uppercase tracking-widest text-sm text-[#00ff00]">{'>'} {m.username}</h3>
          <span class="text-xs text-[#00aa00] capitalize">{roleLabel(m)}</span>
        </div>

        {#if mode === 'menu'}
          {#if canChangeRoles && assignableRoles.length > 0}
            <div class="flex items-end gap-2">
              <div class="flex-1">
                <label for="member-role" class="block text-xs text-[#00aa00] uppercase tracking-wider mb-1">Role</label>
                <select id="member-role" bind:value={newRole} class="w-full bg-[#0a0e0a] border border-[#00ff00] px-2 py-1.5 text-[#00ff00] text-sm">
                  {#each assignableRoles as r}<option value={r.value}>{r.label}</option>{/each}
                </select>
              </div>
              <button type="button" disabled={actionBusy || newRole === m.role} class="px-3 py-1.5 bg-[#00ff00] text-black text-sm font-bold disabled:opacity-40" on:click={saveRole}>Save role</button>
            </div>
          {/if}
          <div class="grid grid-cols-2 gap-2">
            <button type="button" class="py-2 border border-[#ffaa00] text-[#ffaa00] text-sm hover:bg-[#ffaa00] hover:text-black" on:click={() => (mode = 'kick')}>Kick</button>
            <button type="button" class="py-2 border border-red-500 text-red-500 text-sm hover:bg-red-500 hover:text-black" on:click={() => (mode = 'ban')}>Ban</button>
          </div>
          {#if canTransfer && !m.is_owner}
            <button type="button" class="w-full py-2 border border-red-500/60 text-red-400 text-xs uppercase tracking-wider hover:bg-red-500 hover:text-black" on:click={() => (mode = 'transfer')}>Transfer ownership to {m.username}</button>
          {/if}
        {:else if mode === 'kick'}
          <p class="text-xs text-[#00aa00]">{m.username} will be removed from the server. They can rejoin with an invite.</p>
        {:else if mode === 'ban'}
          <p class="text-xs text-[#00aa00]">{m.username} will be removed and can't rejoin until the ban is lifted in Server Settings.</p>
          <div>
            <label for="ban-reason" class="block text-xs text-[#00aa00] uppercase tracking-wider mb-1">Reason (optional)</label>
            <input id="ban-reason" bind:value={banReason} maxlength="500" class="w-full bg-[#0a0e0a] border border-[#00ff00] px-3 py-2 text-[#00ff00] text-sm focus:outline-none" />
          </div>
        {:else if mode === 'transfer'}
          <p class="text-xs text-[#00aa00]">{m.username} will become the owner of this server. You'll stay on as an admin and can't undo this yourself.</p>
          <div>
            <label for="transfer-password" class="block text-xs text-[#00aa00] uppercase tracking-wider mb-1">Your password</label>
            <input id="transfer-password" type="password" bind:value={transferPassword} autocomplete="current-password" class="w-full bg-[#0a0e0a] border border-[#00ff00] px-3 py-2 text-[#00ff00] text-sm focus:outline-none" />
          </div>
        {/if}

        {#if actionError}<div class="text-xs text-red-500">{'>'} {actionError}</div>{/if}

        <div class="flex gap-2">
          <button type="button" class="flex-1 py-2 border border-[#00aa00] text-[#00aa00] text-sm hover:bg-[#00aa00]/10" on:click={() => (mode === 'menu' ? (managing = null) : (mode = 'menu'))}>
            {mode === 'menu' ? 'Close' : 'Back'}
          </button>
          {#if mode === 'kick'}
            <button type="button" disabled={actionBusy} class="flex-1 py-2 border-2 border-[#ffaa00] text-[#ffaa00] font-bold text-sm hover:bg-[#ffaa00] hover:text-black disabled:opacity-50" on:click={kick}>Kick</button>
          {:else if mode === 'ban'}
            <button type="button" disabled={actionBusy} class="flex-1 py-2 border-2 border-red-500 text-red-500 font-bold text-sm hover:bg-red-500 hover:text-black disabled:opacity-50" on:click={ban}>Ban</button>
          {:else if mode === 'transfer'}
            <button type="button" disabled={actionBusy || !transferPassword} class="flex-1 py-2 border-2 border-red-500 text-red-500 font-bold text-sm hover:bg-red-500 hover:text-black disabled:opacity-50" on:click={transfer}>Transfer</button>
          {/if}
        </div>
      </div>
    </div>
  {/if}

  {#if profileError}
    <div class="fixed bottom-2 right-2 z-[150] px-3 py-2 bg-black border border-red-500 text-red-500 text-xs">
      {'>'} {profileError}
    </div>
  {/if}
  <UserProfileModal user={viewingProfile} on:close={() => (viewingProfile = null)} />
</aside>