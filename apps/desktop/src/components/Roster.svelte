<script lang="ts">
  import { onMount } from 'svelte';
  import { getAuthHeaders } from '../lib/api';
  import PatronBadge from './PatronBadge.svelte';

  export let serverId: string | null = null;
  export let currentUser: any = null;

  interface Member {
    id: string;
    username: string;
    is_online: boolean;
    status: string;
    role: string;
    patron_tier: string;
  }

  let members: Member[] = [];
  let loading = true;

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
  }

  $: groupedMembers = statusOrder.map(status => ({
    status,
    config: statusConfig[status as keyof typeof statusConfig],
    members: members.filter(m => m.status === status)
  })).filter(group => group.members.length > 0);

  async function loadMembers(id: string) {
    loading = true;
    try {
      const response = await fetch(`http://localhost:3001/api/v1/servers/${id}/members`, {
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
              <div class="text-xs text-[#00aa00] capitalize terminal-glow">
                {member.role}
              </div>
              
            </div>
          </div>
        {/each}
      {/each}
    {/if}
  </div>
</aside>