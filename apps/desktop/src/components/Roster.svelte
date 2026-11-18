<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { getAuthHeaders, apiFetch, apiBase } from '../lib/api';
  import { wsClient } from '../lib/websocket';
  import PatronBadge from './PatronBadge.svelte';

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

  // Kick / ban dialog
  let pending: { member: Member; action: 'kick' | 'ban' } | null = null;
  let banReason = '';
  let actionError = '';
  let actionBusy = false;

  function startAction(member: Member, action: 'kick' | 'ban') {
    pending = { member, action };
    banReason = '';
    actionError = '';
  }

  async function confirmAction() {
    if (!pending || !serverId) return;
    const { member, action } = pending;
    actionBusy = true;
    actionError = '';
    try {
      const res = action === 'kick'
        ? await apiFetch(`${apiBase()}/api/v1/servers/${serverId}/members/${member.id}`, { method: 'DELETE' })
        : await apiFetch(`${apiBase()}/api/v1/servers/${serverId}/bans`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ user_id: member.id, reason: banReason.trim() || null }),
          });
      if (res.ok) {
        members = members.filter(m => m.id !== member.id);
        pending = null;
      } else {
        actionError = (await res.json().catch(() => ({}))).error || `Failed to ${action}`;
      }
    } catch (e: any) {
      actionError = e.message || 'Network error';
    } finally {
      actionBusy = false;
    }
  }

  async function loadMyRank(id: string) {
    try {
      const res = await apiFetch(`${apiBase()}/api/v1/servers/${id}/role`);
      if (res.ok) myRank = (await res.json()).rank ?? 1;
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

  // Someone joined, left, was kicked or banned.
  function onMembershipChange(data: { server_id: string }) {
    if (serverId && data.server_id === serverId) loadMembers(serverId);
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
  });

  onDestroy(() => {
    wsClient.off('presence_updated', onPresence);
    wsClient.off('member_joined', onMembershipChange);
    wsClient.off('member_left', onMembershipChange);
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
          <div class="group flex items-center gap-3 px-2 py-2 rounded hover:bg-[rgba(0,255,0,0.05)] transition-colors ">
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
                <div class="hidden group-hover:flex gap-1">
                  <button type="button" class="text-[10px] px-1.5 py-0.5 border border-[#ffaa00] text-[#ffaa00] hover:bg-[#ffaa00] hover:text-black" title="Remove from server (they can rejoin with an invite)" on:click={() => startAction(member, 'kick')}>Kick</button>
                  <button type="button" class="text-[10px] px-1.5 py-0.5 border border-red-500 text-red-500 hover:bg-red-500 hover:text-black" title="Remove and stop them rejoining" on:click={() => startAction(member, 'ban')}>Ban</button>
                </div>
              {:else}
                <div class="hidden group-hover:block text-xs text-[#00aa00] capitalize terminal-glow">{roleLabel(member)}</div>
              {/if}
            </div>
          </div>
        {/each}
      {/each}
    {/if}
  </div>

  {#if pending}
    <div class="fixed inset-0 z-[100] flex items-center justify-center bg-black/80" role="dialog" aria-modal="true" aria-labelledby="member-action-title">
      <div class="w-96 max-w-[90vw] bg-black border-2 {pending.action === 'ban' ? 'border-red-500' : 'border-[#ffaa00]'} p-6">
        <h3 id="member-action-title" class="font-bold uppercase tracking-widest text-sm mb-3 {pending.action === 'ban' ? 'text-red-500' : 'text-[#ffaa00]'}">
          {'>'} {pending.action === 'ban' ? 'Ban' : 'Kick'} {pending.member.username}
        </h3>
        <p class="text-xs text-[#00aa00] mb-4">
          {pending.action === 'ban'
            ? "They'll be removed and can't rejoin until the ban is lifted in Server Settings."
            : 'They will be removed from the server. They can rejoin with an invite.'}
        </p>
        {#if pending.action === 'ban'}
          <label for="ban-reason" class="block text-xs text-[#00aa00] uppercase tracking-wider mb-1">Reason (optional)</label>
          <input id="ban-reason" bind:value={banReason} maxlength="500" class="w-full mb-4 bg-[#0a0e0a] border border-[#00ff00] px-3 py-2 text-[#00ff00] text-sm focus:outline-none" />
        {/if}
        {#if actionError}
          <div class="mb-3 text-xs text-red-500">{'>'} {actionError}</div>
        {/if}
        <div class="flex gap-2">
          <button type="button" class="flex-1 py-2 border border-[#00aa00] text-[#00aa00] text-sm hover:bg-[#00aa00]/10" on:click={() => (pending = null)}>Cancel</button>
          <button type="button" disabled={actionBusy}
            class="flex-1 py-2 border-2 text-sm font-bold disabled:opacity-50 {pending.action === 'ban' ? 'border-red-500 text-red-500 hover:bg-red-500' : 'border-[#ffaa00] text-[#ffaa00] hover:bg-[#ffaa00]'} hover:text-black"
            on:click={confirmAction}>
            {pending.action === 'ban' ? 'Ban' : 'Kick'}
          </button>
        </div>
      </div>
    </div>
  {/if}
</aside>