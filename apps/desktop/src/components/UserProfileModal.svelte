<script lang="ts">
  import { createEventDispatcher } from 'svelte';
  import type { UserProfile, PatronTier } from '../lib/users';
  import { setUserBetaBadge, adminSetPatronTier, PATRON_TIERS } from '../lib/users';
  import { getCurrentUser } from '../lib/auth';
  import PatronBadge from './PatronBadge.svelte';
  import BetaBadge from './BetaBadge.svelte';
  import Avatar from './Avatar.svelte';

  export let user: UserProfile | null = null;

  const dispatch = createEventDispatcher();

  const viewerIsSiteOwner = !!getCurrentUser()?.is_site_owner;
  let betaBadgeBusy = false;
  let betaBadgeError = '';

  async function toggleBetaBadge() {
    if (!user || betaBadgeBusy) return;
    betaBadgeError = '';
    betaBadgeBusy = true;
    const next = !user.has_beta_badge;
    try {
      const updated = await setUserBetaBadge(user.id, next);
      user = { ...user, has_beta_badge: updated.has_beta_badge };
    } catch (err: any) {
      betaBadgeError = err.message || 'Failed to update the Beta badge';
    } finally {
      betaBadgeBusy = false;
    }
  }

  // Patron tier -- there's no billing integration yet, so until there is,
  // this admin control (not the user themselves) is how an account actually
  // reaches patron/guild/enterprise. See lib/users.ts's adminSetPatronTier.
  let patronTierBusy = false;
  let patronTierError = '';

  async function setPatronTier(tier: PatronTier) {
    if (!user || patronTierBusy || tier === (user.patron_tier ?? 'free')) return;
    patronTierError = '';
    patronTierBusy = true;
    try {
      const updated = await adminSetPatronTier(user.id, tier);
      user = { ...user, patron_tier: updated.patron_tier, badge_emblem: updated.badge_emblem };
    } catch (err: any) {
      patronTierError = err.message || 'Failed to update patron tier';
    } finally {
      patronTierBusy = false;
    }
  }

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
  <!-- svelte-ignore a11y-no-noninteractive-element-interactions -->
  <div
    class="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm"
    on:click={handleClose}
    on:keydown={(e) => e.key === 'Escape' && handleClose()}
    role="dialog"
    aria-modal="true"
    tabindex="-1"
  >
    <!-- svelte-ignore a11y-no-noninteractive-element-interactions -->
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
          <Avatar
            url={user.avatar_url}
            label={user.username}
            className="w-20 h-20 border-2 border-[#00ff00] font-bold text-3xl terminal-glow bg-[#0a0e0a]"
          />
          <!-- Status Indicator -->
          <div
            class="absolute bottom-0 right-0 w-5 h-5 border-2 border-black rounded-full"
            style="background-color: {getStatusInfo(user.status).color}; box-shadow: {getStatusInfo(user.status).glow};"
            title={getStatusInfo(user.status).label}
          ></div>
        </div>

        <!-- Nickname (server-context) & Patron Badge -->
        <div class="flex items-center gap-2 mb-2">
          <h2 class="text-xl font-bold text-[#00ff00] terminal-glow">{user.nickname || user.username}</h2>
          {#if (user.patron_tier && user.patron_tier !== 'free') || user.is_site_owner}
            <PatronBadge tier={user.patron_tier} emblem={user.badge_emblem} isSiteOwner={!!user.is_site_owner} size="medium" />
          {/if}
          {#if user.has_beta_badge}
            <BetaBadge size="medium" />
          {/if}
        </div>
        {#if user.nickname}
          <div class="text-xs text-[#00aa00] -mt-2 mb-2 terminal-glow">@{user.username}</div>
        {/if}

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

        {#if viewerIsSiteOwner}
          <div class="w-full border-t border-[#00aa00]/30 pt-4 mt-3 space-y-1.5 text-left">
            <span class="text-xs text-[#00aa00] uppercase tracking-wider">Patron tier</span>
            <div class="grid grid-cols-2 gap-2">
              {#each PATRON_TIERS as tier}
                <button
                  type="button"
                  disabled={patronTierBusy}
                  class="py-1.5 border text-xs uppercase tracking-wider transition-colors disabled:opacity-50 {tier === (user.patron_tier ?? 'free') ? 'border-[#00ff00] bg-[#00ff00]/10 text-[#00ff00]' : 'border-[#00aa00]/50 text-[#00aa00] hover:border-[#00ff00]'}"
                  on:click={() => setPatronTier(tier)}
                >
                  {tier}
                </button>
              {/each}
            </div>
            {#if patronTierError}<div class="text-xs text-red-500 mt-1">{'>'} {patronTierError}</div>{/if}
          </div>

          <div class="w-full border-t border-[#00aa00]/30 pt-4 mt-3">
            <button
              type="button"
              disabled={betaBadgeBusy}
              class="w-full py-2 border text-xs uppercase tracking-wider transition-colors disabled:opacity-50 {user.has_beta_badge ? 'border-[#ff2db8] text-[#ff2db8] hover:bg-[#ff2db8]/10' : 'border-[#00aa00]/50 text-[#00aa00] hover:border-[#00ff00] hover:text-[#00ff00]'}"
              on:click={toggleBetaBadge}
            >
              {betaBadgeBusy ? 'Updating...' : user.has_beta_badge ? 'Revoke Beta badge' : 'Grant Beta badge'}
            </button>
            {#if betaBadgeError}<div class="text-xs text-red-500 mt-1">{'>'} {betaBadgeError}</div>{/if}
          </div>
        {/if}
      </div>
    </div>
  </div>
{/if}