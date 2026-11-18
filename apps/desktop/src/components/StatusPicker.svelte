<script lang="ts">
  import { createEventDispatcher, onMount, onDestroy } from 'svelte';
  import { getAuthHeaders, apiFetch, apiBase } from '../lib/api';
  import { getCurrentUser, updateUserInStorage } from '../lib/auth';

  export let currentStatus: string = 'offline';

  const dispatch = createEventDispatcher();

  let isOpen = false;
  let updating = false;

  const statuses = [
    { value: 'online', label: 'Online', color: '#00ff00', icon: '●' },
    { value: 'idle', label: 'Idle', color: '#ffaa00', icon: '◐' },
    { value: 'busy', label: 'Busy', color: '#ff0000', icon: '◉' },
    { value: 'away', label: 'Away', color: '#ff6600', icon: '◑' },
    { value: 'invisible', label: 'Invisible', color: '#666666', icon: '○' },
    { value: 'offline', label: 'Offline', color: '#444444', icon: '◌' }
  ];

  function togglePicker() {
    isOpen = !isOpen;
  }

  async function selectStatus(status: string) {
    if (status === currentStatus) {
      isOpen = false;
      return;
    }

    updating = true;
    try {
      const response = await apiFetch(`${apiBase()}/api/v1/users/me/status`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          ...getAuthHeaders(),
        },
        body: JSON.stringify({ status }),
      });

      if (response.ok) {
        const user = await response.json();
        updateUserInStorage(user);
        dispatch('statusChanged', status);
        isOpen = false;
      }
    } catch (e) {
      console.error('Failed to update status:', e);
    } finally {
      updating = false;
    }
  }

  function handleClickOutside(e: MouseEvent) {
    const target = e.target as HTMLElement;
    if (!target.closest('.status-picker')) {
      isOpen = false;
    }
  }

  onMount(() => {
    document.addEventListener('click', handleClickOutside);
  });

  onDestroy(() => {
    document.removeEventListener('click', handleClickOutside);
  });

  $: currentStatusConfig = statuses.find(s => s.value === currentStatus) || statuses[statuses.length - 1];
</script>

<div class="status-picker relative">
  <button
    type="button"
    class="flex items-center gap-2 px-2 py-1 border border-[#00ff00] hover:bg-[rgba(0,255,0,0.1)] transition-all terminal-glow"
    on:click={togglePicker}
    disabled={updating}
  >
    <span class="text-lg" style="color: {currentStatusConfig.color}; text-shadow: 0 0 8px {currentStatusConfig.color};">
      {currentStatusConfig.icon}
    </span>
    <span class="text-xs text-[#00ff00]">{currentStatusConfig.label}</span>
  </button>

  {#if isOpen}
    <div class="absolute bottom-full left-0 mb-2 w-48 bg-black border-2 border-[#00ff00] shadow-[0_0_20px_rgba(0,255,0,0.4)] z-50">
      <div class="p-2 space-y-1">
        {#each statuses as status}
          <button
            type="button"
            class="w-full flex items-center gap-3 px-3 py-2 hover:bg-[rgba(0,255,0,0.1)] transition-all terminal-glow {currentStatus === status.value ? 'bg-[rgba(0,255,0,0.15)]' : ''}"
            on:click={() => selectStatus(status.value)}
            disabled={updating}
          >
            <span class="text-lg" style="color: {status.color}; text-shadow: 0 0 8px {status.color};">
              {status.icon}
            </span>
            <span class="text-sm text-[#00ff00]">{status.label}</span>
            {#if currentStatus === status.value}
              <span class="ml-auto text-[#00ff00]">✓</span>
            {/if}
          </button>
        {/each}
      </div>
    </div>
  {/if}
</div>