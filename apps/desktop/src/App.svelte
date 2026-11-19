<script lang="ts">
  import { apiFetch, takeLogoutReason, apiBase, setServerUrl } from './lib/api';
  import { wsClient } from './lib/websocket';
  import { onMount } from 'svelte';
  import { getCurrentUser, login, register, logout } from './lib/auth';
  import { deviceEncryptionReady, recoveryChoiceNeeded, recoveryCheckFailed, resetDeviceEncryptionSetup } from './lib/recovery';
  import ServerRail from './components/ServerRail.svelte';
  import SvalinnGauge from './components/SvalinnGauge.svelte';
  import ChannelList from './components/ChannelList.svelte';
  import ChatArea from './components/ChatArea.svelte';
  import Roster from './components/Roster.svelte';
  import AccountSettings from './components/AccountSettings.svelte';
  import RecoveryChoice from './components/RecoveryChoice.svelte';
  import DMList from './components/DMList.svelte';
  import DMChatArea from './components/DMChatArea.svelte';
  import type { Conversation } from './lib/conversations';
  import type { Channel } from './lib/servers';

  let currentUser = getCurrentUser();
  let activeServer: string | null = null;
  let activeChannel: Channel | null = null;
  let activeConversation: Conversation | null = null;
  let showRoster = false;
  let showAccountSettings = false;

  // Stay connected whenever logged in, whatever is on screen, so live
  // updates and a ban or revoked session reach the app straight away.
  $: if (currentUser) wsClient.connect();

  // Make sure this device has an E2EE keypair (generating and uploading one
  // on first use) as soon as we're logged in, so it's ready before the user
  // opens a DM. Reactive rather than onMount so it also runs right after
  // login/register, not just on page load while already logged in.
  //
  // All of the actual decision logic -- including the recovery-backup
  // check and the single shared promise that keeps `DMChatArea.svelte` and
  // `AccountSettings.svelte` from racing ahead and creating a throwaway key
  // of their own -- lives in `deviceEncryptionReady()` (see
  // `lib/recovery.ts`). This effect just kicks it off once per login;
  // `recoveryChoiceNeeded` (a store, also from `lib/recovery.ts`) drives
  // whether the unskippable `RecoveryChoice` modal below is shown.
  //
  // Deliberately fire-and-forget (`.catch` just logs): nothing in the
  // template below -- the server rail, channel list, channel chat, or any
  // of the login/account-settings UI -- reads `deviceEncryptionReady()` or
  // awaits it before rendering. Whether this resolves in a millisecond,
  // hangs for the full bounded timeout inside `lib/crypto.ts`/`recovery.ts`
  // before failing, or never gets called at all, every non-DM part of the
  // app renders and works exactly the same. Only `DMChatArea.svelte` (which
  // awaits this itself before showing a conversation) and the optional
  // `RecoveryChoice` modal depend on it -- see `DMChatArea.svelte` for how
  // a failure there degrades to an in-place error instead of reaching here.
  let checkedEncryptionSetup = false;
  $: if (currentUser && !checkedEncryptionSetup) {
    checkedEncryptionSetup = true;
    deviceEncryptionReady().catch((e) => console.error('Failed to set up encryption keys:', e));
  }

  // Short message at the top of the screen, e.g. "You were kicked from X".
  let notice = '';
  let noticeTimer: ReturnType<typeof setTimeout>;
  function showNotice(text: string) {
    notice = text;
    clearTimeout(noticeTimer);
    noticeTimer = setTimeout(() => (notice = ''), 6000);
  }

  // Kicked, banned or left: close the server if it's open.
  wsClient.on('removed_from_server', (data: { server_id: string; server_name: string; reason: string }) => {
    if (activeServer === data.server_id) {
      activeServer = null;
      activeChannel = null;
      showRoster = false;
    }
    if (data.reason === 'kicked') showNotice(`You were removed from ${data.server_name}.`);
    if (data.reason === 'banned') showNotice(`You were banned from ${data.server_name}.`);
    if (data.reason === 'deleted') showNotice(`${data.server_name} was deleted.`);
  });

  // Auth form state
  let isLoginMode = true;
  let authUsername = '';
  let authEmail = '';
  let authPassword = '';
  // Shown when the server ended the session, e.g. because of a ban.
  let authError = takeLogoutReason() ?? '';
  let authLoading = false;
  // Which Svalinn server to use; changeable on the login screen.
  let serverUrl = apiBase();
  let editingServer = false;

  function handleServerSelected(event: CustomEvent<string | null>) {
    activeServer = event.detail;
    activeChannel = null;
    activeConversation = null;
  }

  function handleChannelSelected(event: CustomEvent<Channel>) {
    activeChannel = event.detail;
  }

  function handleConversationSelected(event: CustomEvent<Conversation>) {
    activeConversation = event.detail;
  }

  function handleCreateChannel() {
    const name = prompt('Enter channel name:');
    if (!name || !activeServer) return;

    apiFetch(`${apiBase()}/api/v1/servers/${activeServer}/channels`, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json', 
        'Authorization': `Bearer ${localStorage.getItem('token')}` 
      },
      body: JSON.stringify({ name }),
    }).then(res => {
      if (!res.ok) {
        alert('Failed to create channel');
      }
    });
  }

  function handleLogout() {
    logout();
    currentUser = null;
    activeServer = null;
    activeChannel = null;
    activeConversation = null;
    checkedEncryptionSetup = false;
    resetDeviceEncryptionSetup();
  }

  async function handleAuthSubmit(e: Event) {
    e.preventDefault();
    authError = '';
    authLoading = true;

    try {
      serverUrl = setServerUrl(serverUrl);
      editingServer = false;
      if (isLoginMode) {
        const user = await login(authEmail, authPassword);
        currentUser = user;
      } else {
        const user = await register(authUsername, authEmail, authPassword);
        currentUser = user;
      }
      // Clear form
      authUsername = '';
      authEmail = '';
      authPassword = '';
    } catch (err: any) {
      authError = err.message || 'Authentication failed';
    } finally {
      authLoading = false;
    }
  }
</script>

{#if notice}
  <div class="fixed top-3 left-1/2 -translate-x-1/2 z-[200] px-4 py-2 bg-black border-2 border-[#ffaa00] text-[#ffaa00] text-sm shadow-[0_0_20px_rgba(255,170,0,0.4)]" role="status">
    {'>'} {notice}
  </div>
{/if}

{#if currentUser}
  <SvalinnGauge />
  <div class="flex h-screen bg-black text-[#00ff00] overflow-hidden font-mono">
    <!-- 1. Server Rail -->
    <ServerRail
      on:serverSelected={handleServerSelected}
      on:openAccountSettings={() => (showAccountSettings = true)}
    />
    {#if showAccountSettings}
      <AccountSettings on:close={() => (showAccountSettings = false)} />
    {/if}
    {#if $recoveryChoiceNeeded || $recoveryCheckFailed}
      <RecoveryChoice />
    {/if}
    
    <!-- 2. Channel List (Only show if a server is selected) -->
    {#if activeServer}
      <ChannelList
        {currentUser}
        activeServer={activeServer}
        activeChannel={activeChannel?.id ?? null}
        on:channelSelected={handleChannelSelected}
        on:channelDeleted={() => (activeChannel = null)}
        on:createChannel={handleCreateChannel}
        on:logout={handleLogout}
      />
    {/if}

    <!-- 3. Chat Area (Only show if a channel is selected) -->
    {#if activeChannel && activeServer && activeChannel.channel_type === 'voice'}
      <!-- Voice channels aren't wired up yet; be honest instead of showing a chat view. -->
      <div class="flex-1 flex flex-col items-center justify-center text-[#00aa00] terminal-glow">
        <div class="text-4xl mb-4">🔊</div>
        <div class="text-xl font-bold">{'>'} Voice channels aren't supported yet</div>
      </div>
    {:else if activeChannel && activeServer}
      <ChatArea
        channelId={activeChannel.id}
        serverId={activeServer}
        {currentUser}
        {showRoster}
        on:toggleRoster={() => (showRoster = !showRoster)}
      />
      {#if showRoster}
        <Roster serverId={activeServer} {currentUser} />
      {/if}
    {:else if activeServer}
      <!-- Empty state when server is selected but no channel -->
      <div class="flex-1 flex flex-col items-center justify-center text-[#00aa00] terminal-glow">
        <div class="text-4xl mb-4">⌘</div>
        <div class="text-xl font-bold">{'>'} Select a channel to start chatting</div>
      </div>
    {:else}
      <!-- No server selected: Direct Messages view -->
      <DMList
        activeConversation={activeConversation?.id ?? null}
        on:conversationSelected={handleConversationSelected}
      />
      {#if activeConversation}
        <DMChatArea
          conversationId={activeConversation.id}
          participantUsername={activeConversation.participant_username}
          participantPublicKey={activeConversation.participant_public_key}
          {currentUser}
        />
      {:else}
        <div class="flex-1 flex flex-col items-center justify-center text-[#00aa00] terminal-glow">
          <div class="text-4xl mb-4">✉</div>
          <div class="text-xl font-bold">{'>'} Select a conversation to start chatting</div>
        </div>
      {/if}
    {/if}
  </div>
{:else}
  <!-- Login/Register Screen -->
  <div class="flex h-screen items-center justify-center bg-black font-mono">
    <div class="w-[400px] bg-[#0a0e0a] border-2 border-[#00ff00] shadow-[0_0_30px_rgba(0,255,0,0.4)] p-8">
      <h1 class="text-3xl font-bold text-[#00ff00] uppercase tracking-widest mb-2 terminal-glow text-center">
        Svalinn
      </h1>
      <p class="text-xs text-[#00aa00] text-center mb-6 terminal-glow">
        {'>'} {isLoginMode ? 'Access the network' : 'Join the network'}
      </p>

      <form on:submit={handleAuthSubmit} class="space-y-4">
        <div class="text-xs text-[#00aa00]">
          {#if editingServer}
            <label for="auth-server" class="block uppercase tracking-wider mb-1">Server</label>
            <input
              id="auth-server"
              bind:value={serverUrl}
              type="url"
              class="w-full bg-black border border-[#00ff00] px-3 py-2 text-[#00ff00] focus:outline-none focus:shadow-[0_0_10px_rgba(0,255,0,0.3)]"
              placeholder="https://chat.example.com"
              required
            />
          {:else}
            Server: <span class="text-[#00ff00]">{serverUrl}</span>
            <button type="button" class="ml-1 underline hover:text-[#00ff00]" on:click={() => (editingServer = true)}>change</button>
          {/if}
        </div>

        {#if !isLoginMode}
          <div>
            <label for="auth-username" class="block text-xs text-[#00aa00] uppercase tracking-wider mb-1">Username</label>
            <input 
              id="auth-username"
              bind:value={authUsername} 
              type="text" 
              class="w-full bg-black border border-[#00ff00] px-3 py-2 text-[#00ff00] focus:outline-none focus:shadow-[0_0_10px_rgba(0,255,0,0.3)]" 
              placeholder="your_username"
              required 
            />
          </div>
        {/if}

        <div>
          <label for="auth-email" class="block text-xs text-[#00aa00] uppercase tracking-wider mb-1">Email</label>
          <input 
            id="auth-email"
            bind:value={authEmail} 
            type="email" 
            class="w-full bg-black border border-[#00ff00] px-3 py-2 text-[#00ff00] focus:outline-none focus:shadow-[0_0_10px_rgba(0,255,0,0.3)]" 
            placeholder="you@example.com"
            required 
          />
        </div>

        <div>
          <label for="auth-password" class="block text-xs text-[#00aa00] uppercase tracking-wider mb-1">Password</label>
          <input 
            id="auth-password"
            bind:value={authPassword} 
            type="password" 
            class="w-full bg-black border border-[#00ff00] px-3 py-2 text-[#00ff00] focus:outline-none focus:shadow-[0_0_10px_rgba(0,255,0,0.3)]" 
            placeholder="••••••••"
            required 
          />
        </div>

        {#if authError}
          <div class="text-xs text-red-500 terminal-glow">{'>'} {authError}</div>
        {/if}

        <button 
          type="submit" 
          disabled={authLoading}
          class="w-full py-2 bg-[#00ff00] text-black font-bold uppercase tracking-wider hover:bg-[#00aa00] transition-all terminal-glow disabled:opacity-50"
        >
          {authLoading ? 'Processing...' : (isLoginMode ? 'Login' : 'Register')}
        </button>
      </form>

      <div class="mt-6 text-center">
        <button 
          class="text-xs text-[#00aa00] hover:text-[#00ff00] terminal-glow"
          on:click={() => { isLoginMode = !isLoginMode; authError = ''; }}
        >
          {isLoginMode ? "Don't have an account? Register" : 'Already have an account? Login'}
        </button>
      </div>
    </div>
  </div>
{/if}

<style>
  :global(body) {
    margin: 0;
    padding: 0;
    background-color: black;
  }
  .terminal-glow {
    text-shadow: 0 0 5px rgba(0, 255, 0, 0.5);
  }
</style>