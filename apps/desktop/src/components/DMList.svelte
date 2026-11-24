<script lang="ts">
  import { onMount, createEventDispatcher } from 'svelte';
  import { getCurrentUser, logout } from '../lib/auth';
  import { fetchUserConversations, createConversation, type Conversation } from '../lib/conversations';
  import { fetchAllUsers, fetchMyProfile, type PublicUser } from '../lib/users';
  import { selfAvatarUrl } from '../lib/selfProfile';
  import { autofocus } from '../lib/actions';
  import PatronBadge from './PatronBadge.svelte';
  import BetaBadge from './BetaBadge.svelte';
  import Avatar from './Avatar.svelte';

  export let activeConversation: string | null = null;

  const dispatch = createEventDispatcher();

  let conversations: Conversation[] = [];
  let loading = true;
  let currentUser = getCurrentUser();

  const statusConfig = {
    online: { color: '#00ff00', glow: '0 0 8px #00ff00' },
    idle: { color: '#ffaa00', glow: '0 0 8px #ffaa00' },
    busy: { color: '#ff0000', glow: '0 0 8px #ff0000' },
    away: { color: '#ff6600', glow: '0 0 8px #ff6600' },
    invisible: { color: '#666666', glow: '0 0 8px #666666' },
    offline: { color: '#444444', glow: 'none' }
  };

  function getStatusStyle(status: string | undefined) {
    const config = status && status in statusConfig ? statusConfig[status as keyof typeof statusConfig] : statusConfig.offline;
    return `background-color: ${config.color}; box-shadow: ${config.glow};`;
  }

  onMount(() => {
    loadConversations();
    // Seeds the self-avatar store with a freshly-signed URL -- a cached
    // one from an earlier login would have an expired signature.
    fetchMyProfile().then(p => selfAvatarUrl.set(p.avatar_url ?? null)).catch(() => {});
  });

  export async function loadConversations() {
    loading = true;
    try {
      conversations = await fetchUserConversations();
    } catch (e) {
      console.error('Failed to load conversations:', e);
    } finally {
      loading = false;
    }
  }

  function handleConversationClick(conversation: Conversation) {
    dispatch('conversationSelected', conversation);
  }

  // "+ New Message" picker: pick a user from everyone registered, create
  // (or re-use) a conversation with them, then open it.
  let showPicker = false;
  let pickerUsers: PublicUser[] = [];
  let pickerLoading = false;
  let pickerError = '';
  let pickerQuery = '';

  $: filteredPickerUsers = pickerUsers.filter(
    u => u.id !== currentUser?.id && u.username.toLowerCase().includes(pickerQuery.trim().toLowerCase())
  );

  async function openPicker() {
    showPicker = true;
    pickerError = '';
    pickerQuery = '';
    pickerLoading = true;
    try {
      pickerUsers = await fetchAllUsers();
    } catch (e: any) {
      pickerError = e.message || 'Failed to load users';
    } finally {
      pickerLoading = false;
    }
  }

  function handleLogout() {
    logout();
    dispatch('logout');
  }

  async function pickUser(user: PublicUser) {
    pickerError = '';
    try {
      const conversation = await createConversation(user.id);
      showPicker = false;
      await loadConversations();
      dispatch('conversationSelected', conversation);
    } catch (e: any) {
      pickerError = e.message || 'Failed to start conversation';
    }
  }
</script>

<aside class="flex-1 min-w-0 md:w-60 md:flex-none bg-[#0a0e0a] border-r-2 border-[#00ff00] flex flex-col h-full">
  <!-- Header -->
  <div class="p-4 border-b-2 border-[#00ff00] flex items-center justify-between gap-2">
    <h3 class="text-xs font-semibold text-[#00aa00] uppercase tracking-widest terminal-glow">
      {'>'} Direct Messages
    </h3>
    <button
      type="button"
      class="px-2 py-1 border border-[#00ff00] text-[#00ff00] text-xs hover:bg-[#00ff00] hover:text-black transition-all terminal-glow"
      title="New Message"
      on:click={openPicker}
    >
      + New
    </button>
  </div>

  <!-- Conversation List -->
  <div class="flex-1 overflow-y-auto p-2 custom-scrollbar">
    {#if loading}
      <div class="flex items-center justify-center py-8">
        <div class="animate-pulse border-2 border-[#00ff00] w-6 h-6"></div>
      </div>
    {:else if conversations.length === 0}
      <div class="text-center text-[#00aa00] text-sm py-8 px-4 terminal-glow">
        {'>'} No conversations yet
      </div>
    {:else}
      {#each conversations as conversation}
        <button
          type="button"
          class="w-full text-left px-3 py-2 mb-1 rounded hover:bg-[rgba(0,255,0,0.1)] transition-all flex items-center gap-2 group {conversation.id === activeConversation ? 'bg-[rgba(0,255,0,0.15)] border-l-2 border-[#00ff00]' : (conversation.has_unread ? 'bg-[rgba(0,255,0,0.05)]' : '')}"
          on:click={() => handleConversationClick(conversation)}
        >
          <!-- Avatar with Status -->
          <div class="relative flex-shrink-0">
            <Avatar
              url={conversation.participant_avatar_url}
              label={conversation.participant_username || '?'}
              className="w-8 h-8 border-2 border-[#00ff00] font-bold text-sm terminal-glow"
            />
            <div
              class="absolute bottom-0 right-0 w-3 h-3 border-2 border-[#0a0e0a] rounded-full"
              style={getStatusStyle(conversation.participant_status)}
            ></div>
          </div>

          <!-- Unread Indicator -->
          {#if conversation.has_unread}
            <div class="w-2 h-2 bg-[#00ff00] rounded-full shadow-[0_0_8px_#00ff00] flex-shrink-0 animate-pulse"></div>
          {:else}
            <div class="w-2 h-2 flex-shrink-0"></div>
          {/if}

          <!-- Username -->
          <div class="flex-1 min-w-0 flex items-center gap-1">
            <div class="text-sm terminal-glow truncate {conversation.has_unread ? 'text-[#00ff00] font-bold' : 'text-[#00aa00]'}">
              {conversation.participant_username || 'Unknown User'}
            </div>
            {#if (conversation.participant_patron_tier && conversation.participant_patron_tier !== 'free') || conversation.participant_is_site_owner}
              <PatronBadge
                tier={conversation.participant_patron_tier}
                emblem={conversation.participant_badge_emblem}
                isSiteOwner={conversation.participant_is_site_owner}
                size="small"
              />
            {/if}
            {#if conversation.participant_has_beta_badge}
              <BetaBadge size="small" />
            {/if}
          </div>
        </button>
      {/each}
    {/if}
  </div>

  <!-- User Footer (matches ChannelList's, so logout is reachable even with no servers joined) -->
  <div class="p-3 border-t-2 border-[#00ff00] bg-black">
    <div class="flex items-center gap-2">
      <Avatar
        url={$selfAvatarUrl}
        label={currentUser?.username ?? '?'}
        className="w-8 h-8 border-2 border-[#00ff00] font-bold text-sm terminal-glow"
      />
      <div class="flex-1 min-w-0">
        <div class="text-xs text-[#00ff00] truncate terminal-glow">{currentUser?.username ?? 'Unknown'}</div>
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
</aside>

{#if showPicker}
  <div class="fixed inset-0 z-[100] flex items-center justify-center bg-black/80" role="dialog" aria-modal="true" aria-labelledby="new-dm-title">
    <div class="w-[360px] max-w-[92vw] bg-black border-2 border-[#00ff00] p-6 space-y-4">
      <div class="flex items-center justify-between">
        <h3 id="new-dm-title" class="font-bold uppercase tracking-widest text-sm text-[#00ff00] terminal-glow">{'>'} New Message</h3>
        <button type="button" class="text-[#00aa00] hover:text-[#00ff00]" aria-label="Close" on:click={() => (showPicker = false)}>✕</button>
      </div>

      <input
        bind:value={pickerQuery}
        type="text"
        class="w-full bg-[#0a0e0a] border border-[#00ff00] px-3 py-2 text-[#00ff00] text-sm focus:outline-none"
        placeholder="Search users..."
        use:autofocus
      />

      {#if pickerError}
        <div class="text-xs text-red-500">{'>'} {pickerError}</div>
      {/if}

      <div class="max-h-60 overflow-y-auto custom-scrollbar space-y-1">
        {#if pickerLoading}
          <div class="flex items-center justify-center py-6">
            <div class="animate-pulse border-2 border-[#00ff00] w-6 h-6"></div>
          </div>
        {:else if filteredPickerUsers.length === 0}
          <div class="text-center text-[#00aa00] text-sm py-6 terminal-glow">{'>'} No users found</div>
        {:else}
          {#each filteredPickerUsers as user}
            <button
              type="button"
              class="w-full text-left px-3 py-2 rounded hover:bg-[rgba(0,255,0,0.1)] transition-all flex items-center gap-2"
              on:click={() => pickUser(user)}
            >
              <div class="relative flex-shrink-0">
                <Avatar
                  url={user.avatar_url}
                  label={user.username}
                  className="w-7 h-7 border-2 border-[#00ff00] font-bold text-xs terminal-glow"
                />
                <div
                  class="absolute bottom-0 right-0 w-2.5 h-2.5 border-2 border-black rounded-full"
                  style={getStatusStyle(user.status)}
                ></div>
              </div>
              <div class="flex-1 min-w-0 flex items-center gap-1">
                <div class="text-sm text-[#00ff00] truncate terminal-glow">{user.username}</div>
                {#if (user.patron_tier && user.patron_tier !== 'free') || user.is_site_owner}
                  <PatronBadge tier={user.patron_tier} emblem={user.badge_emblem} isSiteOwner={!!user.is_site_owner} size="small" />
                {/if}
                {#if user.has_beta_badge}
                  <BetaBadge size="small" />
                {/if}
              </div>
            </button>
          {/each}
        {/if}
      </div>
    </div>
  </div>
{/if}
