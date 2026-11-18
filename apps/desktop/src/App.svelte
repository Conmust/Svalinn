<script lang="ts">
  import { onMount } from 'svelte';
  import { getCurrentUser, login, register, logout } from './lib/auth';
  import ServerRail from './components/ServerRail.svelte';
  import ChannelList from './components/ChannelList.svelte';
  import ChatArea from './components/ChatArea.svelte';

  let currentUser = getCurrentUser();
  let activeServer: string | null = null;
  let activeChannel: string | null = null;

  // Auth form state
  let isLoginMode = true;
  let authUsername = '';
  let authEmail = '';
  let authPassword = '';
  let authError = '';
  let authLoading = false;

  function handleServerSelected(event: CustomEvent<string | null>) {
    activeServer = event.detail;
    activeChannel = null;
  }

  function handleChannelSelected(event: CustomEvent<string>) {
    activeChannel = event.detail;
  }

  function handleCreateChannel() {
    const name = prompt('Enter channel name:');
    if (!name || !activeServer) return;

    fetch(`http://localhost:3001/api/v1/servers/${activeServer}/channels`, {
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
  }

  async function handleAuthSubmit(e: Event) {
    e.preventDefault();
    authError = '';
    authLoading = true;

    try {
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

{#if currentUser}
  <div class="flex h-screen bg-black text-[#00ff00] overflow-hidden font-mono">
    <!-- 1. Server Rail -->
    <ServerRail 
      on:serverSelected={handleServerSelected} 
    />
    
    <!-- 2. Channel List (Only show if a server is selected) -->
    {#if activeServer}
      <ChannelList 
        {currentUser}
        activeServer={activeServer}
        activeChannel={activeChannel}
        on:channelSelected={handleChannelSelected}
        on:createChannel={handleCreateChannel}
        on:logout={handleLogout}
      />
    {/if}

    <!-- 3. Chat Area (Only show if a channel is selected) -->
    {#if activeChannel && activeServer}
      <ChatArea 
        channelId={activeChannel}
        
      />
    {:else if activeServer}
      <!-- Empty state when server is selected but no channel -->
      <div class="flex-1 flex flex-col items-center justify-center text-[#00aa00] terminal-glow">
        <div class="text-4xl mb-4">⌘</div>
        <div class="text-xl font-bold">{'>'} Select a channel to start chatting</div>
      </div>
    {:else}
      <!-- Empty state when no server is selected (DM view placeholder) -->
      <div class="flex-1 flex flex-col items-center justify-center text-[#00aa00] terminal-glow">
        <div class="text-4xl mb-4">✉</div>
        <div class="text-xl font-bold">{'>'} Direct Messages (Coming Soon)</div>
      </div>
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