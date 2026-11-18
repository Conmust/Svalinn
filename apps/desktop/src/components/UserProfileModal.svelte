<script lang="ts">
  import { createEventDispatcher } from 'svelte';
  import type { UserProfile } from '../lib/users';
  import PatronBadge from './PatronBadge.svelte';

  export let user: UserProfile | null = null;

  const dispatch = createEventDispatcher();

  const statusConfig = {
    online: { color: '#00ff00', glow: '0 0 8px #00ff00', label: 'Online' },
    idle: { color: '#ffaa00', glow: '0 0 8px #ffaa00', label: 'Idle' },
    busy: { color: '#ff0000', glow: '0 0 8px #ff0000', label: 'Do Not Disturb' },
    away: { color: '#ff6600', glow: '0 0 8px #ff6600', label: 'Away' },
    invisible: { color: '#666666', glow: '0 0 8px #666666', label: 'Invisible' },
    offline: { color: '#444444', glow: 'none', label: 'Offline' }
  };

  function getStatusInfo(status: string) {
    return statusConfig[status as keyof typeof statusConfig] || statusConfig.offline;
  }

  function formatDate(dateString: string): string {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric'
    });
  }

  function handleClose() {
    dispatch('close');
  }
</script>

{#if user}
  <div 
    class="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm" 
    on:click={handleClose} 
    on:keydown={(e) => e.key === 'Escape' && handleClose()}
    role="dialog" 
    aria-modal="true"
    tabindex="-1"
  >
    <div 
      class="relative w-[400px] max-w-[90vw] bg-black border-2 border-[#00ff00] shadow-[0_0_30px_rgba(0,255,0,0.4)] flex flex-col" 
      on:click|stopPropagation 
      on:keydown|stopPropagation
      role="document"
    >
      <!-- Header -->
      <div class="p-4 border-b border-[#00ff00] flex items-center justify-between">
        <h3 class="font-bold uppercase tracking-widest text-sm terminal-glow text-[#00ff00]">
          {'>'} User Profile
        </h3>
        <button 
          class="text-[#00ff00] hover:text-red-500 terminal-glow transition-colors" 
          on:click={handleClose}
        >
          ✕
        </button>
      </div>

      <!-- Content -->
      <div class="p-6 flex flex-col items-center text-center">
        <!-- Avatar -->
        <div class="relative mb-4">
          <div class="w-20 h-20 border-2 border-[#00ff00] flex items-center justify-center font-bold text-3xl terminal-glow bg-[#0a0e0a]">
            {user.username[0].toUpperCase()}
          </div>
          <!-- Status Indicator -->
          <div
            class="absolute bottom-0 right-0 w-5 h-5 border-2 border-black rounded-full"
            style="background-color: {getStatusInfo(user.status).color}; box-shadow: {getStatusInfo(user.status).glow};"
            title={getStatusInfo(user.status).label}
          ></div>
        </div>

        <!-- Username & Patron Badge -->
        <div class="flex items-center gap-2 mb-2">
          <h2 class="text-xl font-bold text-[#00ff00] terminal-glow">{user.username}</h2>
          {#if user.patron_tier && user.patron_tier !== 'free'}
            <PatronBadge tier={user.patron_tier} size="medium" />
          {/if}
        </div>

        <!-- Status Text -->
        <div class="text-sm text-[#00aa00] mb-6 terminal-glow">
          {getStatusInfo(user.status).label}
        </div>

        <!-- Details Grid -->
        <div class="w-full border-t border-[#00aa00]/30 pt-4 space-y-3 text-left">
          <div class="flex justify-between items-center">
            <span class="text-xs text-[#00aa00] uppercase tracking-wider">User ID</span>
            <span class="text-xs text-[#00ff00] font-mono">{user.id.slice(0, 8)}...</span>
          </div>
          <div class="flex justify-between items-center">
            <span class="text-xs text-[#00aa00] uppercase tracking-wider">Joined</span>
            <span class="text-xs text-[#00ff00]">{formatDate(user.created_at)}</span>
          </div>
        </div>
      </div>
    </div>
  </div>
{/if}