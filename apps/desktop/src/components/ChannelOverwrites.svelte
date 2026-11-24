<script lang="ts">
  import { createEventDispatcher, onMount } from 'svelte';
  import { getAuthHeaders, apiFetch, apiBase } from '../lib/api';
  import {
    listChannelOverwrites,
    setRoleOverwrite,
    deleteRoleOverwrite,
    setMemberOverwrite,
    deleteMemberOverwrite,
    listRoles,
    PERMISSION_INFO,
    type ChannelOverwrites,
    type Role,
  } from '../lib/roles';

  // Per-channel permission overwrites: who can see/use this one channel,
  // beyond their ordinary server-wide role permissions. See
  // crates/svalinn-server/src/routes/roles.rs's overwrite endpoints and
  // permissions.rs's resolve_channel for how these actually apply.

  export let channelId: string;
  export let channelName: string;
  export let serverId: string;

  const dispatch = createEventDispatcher();

  interface MemberOption {
    id: string;
    username: string;
  }

  let overwrites: ChannelOverwrites = { roles: [], members: [] };
  let roles: Role[] = [];
  let members: MemberOption[] = [];
  let loading = true;
  let error = '';

  // Which (kind, id, permission) is mid-request, so only that one button
  // shows busy instead of locking the whole panel.
  let busyKey = '';

  let addRoleId = '';
  let addMemberId = '';

  type OverwriteState = 'inherit' | 'allow' | 'deny';

  function bitsToState(allow: string[], deny: string[], name: string): OverwriteState {
    if (allow.includes(name)) return 'allow';
    if (deny.includes(name)) return 'deny';
    return 'inherit';
  }

  // Inherit -> Allow -> Deny -> Inherit.
  function nextState(state: OverwriteState): OverwriteState {
    if (state === 'inherit') return 'allow';
    if (state === 'allow') return 'deny';
    return 'inherit';
  }

  function roleName(roleId: string): string {
    return roles.find(r => r.id === roleId)?.name ?? 'Unknown role';
  }
  function roleColor(roleId: string): string {
    return roles.find(r => r.id === roleId)?.color || '#99aab5';
  }
  function memberName(userId: string): string {
    return members.find(m => m.id === userId)?.username ?? 'Unknown member';
  }

  $: unoverwrittenRoles = roles.filter(r => !r.is_default && !overwrites.roles.some(o => o.role_id === r.id));
  $: unoverwrittenMembers = members.filter(m => !overwrites.members.some(o => o.user_id === m.id));

  async function loadMembers() {
    const res = await apiFetch(`${apiBase()}/api/v1/servers/${serverId}/members`, { headers: getAuthHeaders() });
    if (res.ok) members = await res.json();
  }

  async function loadAll() {
    loading = true;
    error = '';
    try {
      const [ow, rl] = await Promise.all([listChannelOverwrites(channelId), listRoles(serverId)]);
      overwrites = ow;
      roles = rl;
      await loadMembers();
    } catch (e: any) {
      error = e.message || 'Failed to load channel permissions';
    } finally {
      loading = false;
    }
  }

  onMount(loadAll);

  function addRoleRow() {
    if (!addRoleId) return;
    overwrites = { ...overwrites, roles: [...overwrites.roles, { role_id: addRoleId, allow: [], deny: [] }] };
    addRoleId = '';
  }
  function addMemberRow() {
    if (!addMemberId) return;
    overwrites = { ...overwrites, members: [...overwrites.members, { user_id: addMemberId, allow: [], deny: [] }] };
    addMemberId = '';
  }

  async function cycleRolePermission(roleId: string, permName: string) {
    const entry = overwrites.roles.find(o => o.role_id === roleId);
    if (!entry) return;
    const state = nextState(bitsToState(entry.allow, entry.deny, permName));
    const allow = entry.allow.filter(n => n !== permName);
    const deny = entry.deny.filter(n => n !== permName);
    if (state === 'allow') allow.push(permName);
    if (state === 'deny') deny.push(permName);

    busyKey = `role:${roleId}:${permName}`;
    error = '';
    try {
      await setRoleOverwrite(channelId, roleId, { allow, deny });
      overwrites = {
        ...overwrites,
        roles: overwrites.roles.map(o => (o.role_id === roleId ? { ...o, allow, deny } : o)),
      };
    } catch (e: any) {
      error = e.message || 'Failed to update overwrite';
    } finally {
      busyKey = '';
    }
  }

  async function cycleMemberPermission(userId: string, permName: string) {
    const entry = overwrites.members.find(o => o.user_id === userId);
    if (!entry) return;
    const state = nextState(bitsToState(entry.allow, entry.deny, permName));
    const allow = entry.allow.filter(n => n !== permName);
    const deny = entry.deny.filter(n => n !== permName);
    if (state === 'allow') allow.push(permName);
    if (state === 'deny') deny.push(permName);

    busyKey = `member:${userId}:${permName}`;
    error = '';
    try {
      await setMemberOverwrite(channelId, userId, { allow, deny });
      overwrites = {
        ...overwrites,
        members: overwrites.members.map(o => (o.user_id === userId ? { ...o, allow, deny } : o)),
      };
    } catch (e: any) {
      error = e.message || 'Failed to update overwrite';
    } finally {
      busyKey = '';
    }
  }

  async function removeRoleOverwrite(roleId: string) {
    error = '';
    try {
      await deleteRoleOverwrite(channelId, roleId);
      overwrites = { ...overwrites, roles: overwrites.roles.filter(o => o.role_id !== roleId) };
    } catch (e: any) {
      error = e.message || 'Failed to remove overwrite';
    }
  }

  async function removeMemberOverwrite(userId: string) {
    error = '';
    try {
      await deleteMemberOverwrite(channelId, userId);
      overwrites = { ...overwrites, members: overwrites.members.filter(o => o.user_id !== userId) };
    } catch (e: any) {
      error = e.message || 'Failed to remove overwrite';
    }
  }

  function stateLabel(state: OverwriteState): string {
    if (state === 'allow') return '✓';
    if (state === 'deny') return '✕';
    return '·';
  }
  function stateClass(state: OverwriteState): string {
    if (state === 'allow') return 'border-[#00ff00] text-[#00ff00] bg-[#00ff00]/10';
    if (state === 'deny') return 'border-red-500 text-red-500 bg-red-500/10';
    return 'border-[#00aa00]/40 text-[#00aa00]/60';
  }
</script>

<div
  class="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm"
  on:click={() => dispatch('close')}
  on:keydown={(e) => e.key === 'Escape' && dispatch('close')}
  role="dialog"
  aria-modal="true"
  tabindex="-1"
>
  <div
    class="relative w-[560px] max-w-[92vw] max-h-[85vh] bg-black border-2 border-[#00ff00] shadow-[0_0_30px_rgba(0,255,0,0.4)] flex flex-col"
    on:click|stopPropagation
    on:keydown|stopPropagation
    role="document"
  >
    <div class="p-4 border-b border-[#00ff00] flex items-center justify-between">
      <h3 class="font-bold uppercase tracking-widest text-sm terminal-glow text-[#00ff00]">
        {'>'} #{channelName} Permissions
      </h3>
      <button class="text-[#00ff00] hover:text-red-500 terminal-glow transition-colors" on:click={() => dispatch('close')} aria-label="Close">
        ✕
      </button>
    </div>

    <div class="flex-1 overflow-y-auto p-4 custom-scrollbar space-y-6">
      <p class="text-[11px] text-[#00aa00]">
        {'>'} Click a permission to cycle it: inherit (·) → allow (✓) → deny (✕). A deny here beats every role; an
        allow here beats everything except another deny set the same way. Denying <span class="text-[#00ff00]">view_channel</span>
        on the default role, then allowing it back for specific roles or members, is how you make this channel private.
      </p>

      {#if error}
        <div class="text-xs text-red-500">{'>'} {error}</div>
      {/if}

      {#if loading}
        <div class="text-[#00aa00] text-xs animate-pulse">{'>'} Loading...</div>
      {:else}
        <!-- Role overwrites -->
        <div>
          <div class="flex items-center justify-between mb-2">
            <h4 class="text-xs text-[#00aa00] uppercase tracking-wider">Role overwrites</h4>
            {#if unoverwrittenRoles.length > 0}
              <div class="flex gap-1">
                <select bind:value={addRoleId} class="bg-[#0a0e0a] border border-[#00ff00] px-1 py-1 text-[#00ff00] text-xs">
                  <option value="">+ Add role...</option>
                  {#each unoverwrittenRoles as r}<option value={r.id}>{r.name}</option>{/each}
                </select>
                <button type="button" disabled={!addRoleId} class="px-2 py-1 text-xs border border-[#00ff00] text-[#00ff00] hover:bg-[#00ff00] hover:text-black disabled:opacity-40" on:click={addRoleRow}>Add</button>
              </div>
            {/if}
          </div>
          {#if overwrites.roles.length === 0}
            <div class="text-[#00aa00]/70 text-xs">{'>'} No role overwrites on this channel.</div>
          {:else}
            <div class="space-y-3">
              {#each overwrites.roles as entry (entry.role_id)}
                <div class="border border-[#00aa00]/30 bg-[#0a0e0a] p-3">
                  <div class="flex items-center justify-between mb-2">
                    <div class="flex items-center gap-2">
                      <span class="w-2 h-2 rounded-full flex-shrink-0" style="background-color: {roleColor(entry.role_id)}"></span>
                      <span class="text-sm text-[#00ff00]">{roleName(entry.role_id)}</span>
                    </div>
                    <button type="button" class="text-xs text-red-500 hover:text-red-400" on:click={() => removeRoleOverwrite(entry.role_id)}>Remove</button>
                  </div>
                  <div class="grid grid-cols-2 gap-1">
                    {#each PERMISSION_INFO as perm}
                      {@const state = bitsToState(entry.allow, entry.deny, perm.name)}
                      <button
                        type="button"
                        disabled={busyKey === `role:${entry.role_id}:${perm.name}`}
                        class="flex items-center justify-between gap-1 px-2 py-1 border text-[11px] disabled:opacity-50 {stateClass(state)}"
                        on:click={() => cycleRolePermission(entry.role_id, perm.name)}
                        title={perm.description}
                      >
                        <span class="truncate">{perm.label}</span>
                        <span class="font-bold">{stateLabel(state)}</span>
                      </button>
                    {/each}
                  </div>
                </div>
              {/each}
            </div>
          {/if}
        </div>

        <!-- Member overwrites -->
        <div>
          <div class="flex items-center justify-between mb-2">
            <h4 class="text-xs text-[#00aa00] uppercase tracking-wider">Member overwrites</h4>
            {#if unoverwrittenMembers.length > 0}
              <div class="flex gap-1">
                <select bind:value={addMemberId} class="bg-[#0a0e0a] border border-[#00ff00] px-1 py-1 text-[#00ff00] text-xs">
                  <option value="">+ Add member...</option>
                  {#each unoverwrittenMembers as m}<option value={m.id}>{m.username}</option>{/each}
                </select>
                <button type="button" disabled={!addMemberId} class="px-2 py-1 text-xs border border-[#00ff00] text-[#00ff00] hover:bg-[#00ff00] hover:text-black disabled:opacity-40" on:click={addMemberRow}>Add</button>
              </div>
            {/if}
          </div>
          {#if overwrites.members.length === 0}
            <div class="text-[#00aa00]/70 text-xs">{'>'} No member overwrites on this channel.</div>
          {:else}
            <div class="space-y-3">
              {#each overwrites.members as entry (entry.user_id)}
                <div class="border border-[#00aa00]/30 bg-[#0a0e0a] p-3">
                  <div class="flex items-center justify-between mb-2">
                    <span class="text-sm text-[#00ff00]">{memberName(entry.user_id)}</span>
                    <button type="button" class="text-xs text-red-500 hover:text-red-400" on:click={() => removeMemberOverwrite(entry.user_id)}>Remove</button>
                  </div>
                  <div class="grid grid-cols-2 gap-1">
                    {#each PERMISSION_INFO as perm}
                      {@const state = bitsToState(entry.allow, entry.deny, perm.name)}
                      <button
                        type="button"
                        disabled={busyKey === `member:${entry.user_id}:${perm.name}`}
                        class="flex items-center justify-between gap-1 px-2 py-1 border text-[11px] disabled:opacity-50 {stateClass(state)}"
                        on:click={() => cycleMemberPermission(entry.user_id, perm.name)}
                        title={perm.description}
                      >
                        <span class="truncate">{perm.label}</span>
                        <span class="font-bold">{stateLabel(state)}</span>
                      </button>
                    {/each}
                  </div>
                </div>
              {/each}
            </div>
          {/if}
        </div>
      {/if}
    </div>
  </div>
</div>
