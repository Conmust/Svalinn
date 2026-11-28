<script lang="ts">
  import { apiFetch, takeLogoutReason, apiBase, setServerUrl } from './lib/api';
  import { wsClient } from './lib/websocket';
  import { onMount } from 'svelte';
  import { getCurrentUser, login, register, logout, forgotPassword, completeTotpLogin, isTwoFactorRequired } from './lib/auth';
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
  import CallOverlay from './components/CallOverlay.svelte';
  import VoiceChannelView from './components/VoiceChannelView.svelte';
  import { initCallSignaling } from './lib/calls';
  import { initVoiceSignaling } from './lib/voiceChannel';
  import type { Conversation } from './lib/conversations';
  import type { Channel } from './lib/servers';

  // Registers the WS listeners that drive incoming/outgoing calls and voice
  // channels. Only needs to happen once -- `wsClient.on` just adds
  // listeners, independent of connect/reconnect cycles below.
  initCallSignaling();
  initVoiceSignaling();

  let currentUser = getCurrentUser();
  let activeServer: string | null = null;
  let activeChannel: Channel | null = null;
  let activeConversation: Conversation | null = null;
  let showRoster = false;
  let showAccountSettings = false;

  // Below the `md` breakpoint there isn't room to show the server rail,
  // channel list, chat and roster side by side (see the responsive wrapper
  // classes in the template below), so only one "pane" is visible at a
  // time and this tracks which. It's read and written here but ignored by
  // the layout at `md` and above, where every pane is always shown as
  // before.
  let mobileView: 'nav' | 'chat' | 'roster' = 'nav';

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
      mobileView = 'nav';
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

  // "Forgot password?" takes over the same card as the login form (see
  // `showForgotPassword` in the template below) rather than being a
  // separate route -- there's no router here, just the one login screen.
  let showForgotPassword = false;
  let forgotEmail = '';
  let forgotLoading = false;
  let forgotError = '';
  let forgotMessage = '';
  // Only ever set under APP_ENV=development -- see `forgotPassword`'s doc
  // comment. In any other environment this stays undefined and the UI just
  // shows the generic "check your email" message.
  let forgotDevLink: string | undefined;

  // 2FA login step: `login()` returns a pending token instead of a session
  // when the account has TOTP enabled. Set, the login card swaps to a
  // code-entry screen (see template below) in place of the normal form.
  let pendingTotpToken: string | null = null;
  let totpLoginCode = '';
  let totpLoginError = '';
  let totpLoginBusy = false;

  function handleServerSelected(event: CustomEvent<string | null>) {
    activeServer = event.detail;
    activeChannel = null;
    activeConversation = null;
    mobileView = 'nav';
  }

  function handleChannelSelected(event: CustomEvent<Channel>) {
    activeChannel = event.detail;
    mobileView = 'chat';
  }

  function handleConversationSelected(event: CustomEvent<Conversation>) {
    activeConversation = event.detail;
    mobileView = 'chat';
  }

  // On mobile, "Members" swaps the chat pane out for a full-width roster
  // instead of showing a side-by-side column; the reverse happens when the
  // roster's own back button fires `rosterClosed`.
  function handleToggleRoster() {
    showRoster = !showRoster;
    mobileView = showRoster ? 'roster' : 'chat';
  }

  function handleRosterClosed() {
    showRoster = false;
    mobileView = 'chat';
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
    mobileView = 'nav';
  }

  async function handleAuthSubmit(e: Event) {
    e.preventDefault();
    authError = '';
    authLoading = true;

    try {
      serverUrl = setServerUrl(serverUrl);
      editingServer = false;
      if (isLoginMode) {
        const result = await login(authEmail, authPassword);
        if (isTwoFactorRequired(result)) {
          pendingTotpToken = result.pendingToken;
          totpLoginCode = '';
          totpLoginError = '';
        } else {
          currentUser = result;
        }
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

  async function handleTotpLoginSubmit(e: Event) {
    e.preventDefault();
    if (!pendingTotpToken) return;
    totpLoginError = '';
    totpLoginBusy = true;
    try {
      currentUser = await completeTotpLogin(pendingTotpToken, totpLoginCode);
      pendingTotpToken = null;
      totpLoginCode = '';
    } catch (err: any) {
      totpLoginError = err.message || 'That code is incorrect';
    } finally {
      totpLoginBusy = false;
    }
  }

  function cancelTotpLogin() {
    pendingTotpToken = null;
    totpLoginCode = '';
    totpLoginError = '';
  }

  function openForgotPassword() {
    showForgotPassword = true;
    forgotError = '';
    forgotMessage = '';
    forgotDevLink = undefined;
    // Carry over whatever the person already typed into the email field,
    // since they're very likely requesting a reset for the account they
    // were just trying to log into.
    forgotEmail = authEmail;
  }

  function closeForgotPassword() {
    showForgotPassword = false;
    forgotEmail = '';
    forgotError = '';
    forgotMessage = '';
    forgotDevLink = undefined;
  }

  async function handleForgotPasswordSubmit(e: Event) {
    e.preventDefault();
    forgotError = '';
    forgotMessage = '';
    forgotDevLink = undefined;
    forgotLoading = true;

    try {
      serverUrl = setServerUrl(serverUrl);
      editingServer = false;
      const { devResetLink } = await forgotPassword(forgotEmail);
      // Deliberately generic -- the server itself never reveals whether an
      // account exists for this email (see `forgotPassword`'s doc comment),
      // so neither does this message.
      forgotMessage = 'If an account exists for that email, a password reset link has been sent. The link opens a page where you can set a new password.';
      forgotDevLink = devResetLink;
    } catch (err: any) {
      forgotError = err.message || 'Could not request a password reset right now.';
    } finally {
      forgotLoading = false;
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
    <!-- 1. Nav pane: Server Rail + Channel/DM list. Below `md` this is its
         own full-screen pane (only shown when mobileView === 'nav'); at
         `md` and above it's always shown side by side with the rest, same
         as before this pane wrapper existed. -->
    <div class="w-full md:w-auto {mobileView === 'nav' ? 'flex' : 'hidden'} md:flex">
      <ServerRail
        on:serverSelected={handleServerSelected}
        on:openAccountSettings={() => (showAccountSettings = true)}
      />

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
      {:else}
        <!-- No server selected: Direct Messages list -->
        <DMList
          activeConversation={activeConversation?.id ?? null}
          on:conversationSelected={handleConversationSelected}
          on:logout={handleLogout}
        />
      {/if}
    </div>

    {#if showAccountSettings}
      <AccountSettings on:close={() => (showAccountSettings = false)} />
    {/if}
    {#if $recoveryChoiceNeeded || $recoveryCheckFailed}
      <RecoveryChoice />
    {/if}

    <CallOverlay />

    <!-- 3. Chat pane: whatever's active for the current server/DM context.
         Below `md` this only shows once something is actually selected
         (mobileView only becomes 'chat' from a selection handler), so
         there's no empty placeholder stranded with no way back to 'nav'. -->
    <div class="flex-1 min-w-0 {mobileView === 'chat' ? 'flex' : 'hidden'} md:flex">
      {#if activeChannel && activeServer && activeChannel.channel_type === 'voice'}
        <VoiceChannelView
          channelId={activeChannel.id}
          channelName={activeChannel.name}
          serverId={activeServer}
        />
      {:else if activeChannel && activeServer}
        <ChatArea
          channelId={activeChannel.id}
          serverId={activeServer}
          {currentUser}
          {showRoster}
          on:toggleRoster={handleToggleRoster}
          on:back={() => (mobileView = 'nav')}
        />
      {:else if activeConversation}
        <DMChatArea
          conversationId={activeConversation.id}
          participantId={activeConversation.participant_id}
          participantUsername={activeConversation.participant_username}
          participantPublicKey={activeConversation.participant_public_key}
          {currentUser}
          on:back={() => (mobileView = 'nav')}
        />
      {:else if activeServer}
        <!-- Empty state when server is selected but no channel (desktop only; see note above) -->
        <div class="flex-1 flex flex-col items-center justify-center text-[#00aa00] terminal-glow">
          <div class="text-4xl mb-4">⌘</div>
          <div class="text-xl font-bold">{'>'} Select a channel to start chatting</div>
        </div>
      {:else}
        <!-- Empty state when no conversation is open (desktop only; see note above) -->
        <div class="flex-1 flex flex-col items-center justify-center text-[#00aa00] terminal-glow">
          <div class="text-4xl mb-4">✉</div>
          <div class="text-xl font-bold">{'>'} Select a conversation to start chatting</div>
        </div>
      {/if}
    </div>

    <!-- 4. Roster pane: full-width on mobile (its own pane), a fixed-width
         sidebar alongside chat at `md` and above, same as before. -->
    {#if showRoster && activeServer}
      <div class="w-full md:w-auto {mobileView === 'roster' ? 'flex' : 'hidden'} md:flex">
        <Roster serverId={activeServer} {currentUser} on:close={handleRosterClosed} />
      </div>
    {/if}
  </div>
{:else}
  <!-- Login/Register Screen -->
  <div class="flex h-screen items-center justify-center bg-black font-mono px-4">
    <div class="w-full max-w-[400px] bg-[#0a0e0a] border-2 border-[#00ff00] shadow-[0_0_30px_rgba(0,255,0,0.4)] p-8">
      <h1 class="text-3xl font-bold text-[#00ff00] uppercase tracking-widest mb-2 terminal-glow text-center">
        Svalinn
      </h1>
      <p class="text-xs text-[#00aa00] text-center mb-6 terminal-glow">
        {'>'} {showForgotPassword ? 'Reset your password' : pendingTotpToken ? 'Two-factor check' : (isLoginMode ? 'Access the network' : 'Join the network')}
      </p>

      {#if pendingTotpToken}
        <form on:submit={handleTotpLoginSubmit} class="space-y-4">
          <p class="text-xs text-[#00aa00]">
            Enter the 6-digit code from your authenticator app, or one of your backup codes.
          </p>

          <div>
            <label for="totp-login-code" class="block text-xs text-[#00aa00] uppercase tracking-wider mb-1">Code</label>
            <input
              id="totp-login-code"
              bind:value={totpLoginCode}
              type="text"
              inputmode="numeric"
              autocomplete="one-time-code"
              class="w-full bg-black border border-[#00ff00] px-3 py-2 text-[#00ff00] focus:outline-none focus:shadow-[0_0_10px_rgba(0,255,0,0.3)]"
              placeholder="123456"
              required
            />
          </div>

          {#if totpLoginError}
            <div class="text-xs text-red-500 terminal-glow">{'>'} {totpLoginError}</div>
          {/if}

          <button
            type="submit"
            disabled={totpLoginBusy}
            class="w-full py-2 bg-[#00ff00] text-black font-bold uppercase tracking-wider hover:bg-[#00aa00] transition-all terminal-glow disabled:opacity-50"
          >
            {totpLoginBusy ? 'Verifying...' : 'Verify'}
          </button>
        </form>

        <div class="mt-6 text-center">
          <button class="text-xs text-[#00aa00] hover:text-[#00ff00] terminal-glow" on:click={cancelTotpLogin}>
            Back to login
          </button>
        </div>
      {:else if showForgotPassword}
        <form on:submit={handleForgotPasswordSubmit} class="space-y-4">
          <p class="text-xs text-[#00aa00]">
            Enter your account's email and we'll send a link to reset your password.
          </p>

          <div>
            <label for="forgot-email" class="block text-xs text-[#00aa00] uppercase tracking-wider mb-1">Email</label>
            <input
              id="forgot-email"
              bind:value={forgotEmail}
              type="email"
              class="w-full bg-black border border-[#00ff00] px-3 py-2 text-[#00ff00] focus:outline-none focus:shadow-[0_0_10px_rgba(0,255,0,0.3)]"
              placeholder="you@example.com"
              required
            />
          </div>

          {#if forgotError}
            <div class="text-xs text-red-500 terminal-glow">{'>'} {forgotError}</div>
          {/if}

          {#if forgotMessage}
            <div class="text-xs text-[#00ff00] terminal-glow">{'>'} {forgotMessage}</div>
            {#if forgotDevLink}
              <!-- Dev-only convenience: no real email provider is wired up yet
                   (see svalinn-server's send_password_reset_email), so this
                   link is handed back directly under APP_ENV=development. -->
              <a
                href={forgotDevLink}
                target="_blank"
                rel="noopener noreferrer"
                class="block text-xs text-[#00aa00] underline hover:text-[#00ff00] break-all"
              >
                [dev] Open reset link
              </a>
            {/if}
          {/if}

          <button
            type="submit"
            disabled={forgotLoading}
            class="w-full py-2 bg-[#00ff00] text-black font-bold uppercase tracking-wider hover:bg-[#00aa00] transition-all terminal-glow disabled:opacity-50"
          >
            {forgotLoading ? 'Sending...' : 'Send reset link'}
          </button>
        </form>

        <div class="mt-6 text-center">
          <button
            class="text-xs text-[#00aa00] hover:text-[#00ff00] terminal-glow"
            on:click={closeForgotPassword}
          >
            Back to login
          </button>
        </div>
      {:else}
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
            <div class="flex items-baseline justify-between">
              <label for="auth-password" class="block text-xs text-[#00aa00] uppercase tracking-wider mb-1">Password</label>
              {#if isLoginMode}
                <button type="button" class="text-xs text-[#00aa00] underline hover:text-[#00ff00]" on:click={openForgotPassword}>
                  Forgot password?
                </button>
              {/if}
            </div>
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
      {/if}
    </div>
  </div>
{/if}
