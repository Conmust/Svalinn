<script lang="ts">
  import { createEventDispatcher } from 'svelte';
  import { setAuth } from '../lib/auth';

  const dispatch = createEventDispatcher();

  let mode: 'login' | 'register' = 'login';
  let email = '';
  let password = '';
  let username = '';
  let loading = false;
  let error = '';

  async function handleSubmit() {
    loading = true;
    error = '';

    try {
      const endpoint = mode === 'login' 
        ? 'http://localhost:3001/api/v1/auth/login'
        : 'http://localhost:3001/api/v1/auth/register';

      const body = mode === 'login'
        ? { email, password }
        : { username, email, password };

      const response = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });

      if (!response.ok) {
        const errData = await response.json().catch(() => ({}));
        throw new Error(errData.message || `Authentication failed (${response.status})`);
      }

      const data = await response.json();
      
      setAuth(data.token, data.user);
      dispatch('success', { user: data.user });
    } catch (e: any) {
      error = e.message || 'An unexpected error occurred';
      console.error('Auth error:', e);
    } finally {
      loading = false;
    }
  }

  function toggleMode() {
    mode = mode === 'login' ? 'register' : 'login';
    error = '';
  }
</script>

<div class="flex-1 flex items-center justify-center bg-[#0a0e0a]">
  <div class="w-96 border-2 border-[#00ff00] bg-black p-8 shadow-[0_0_30px_rgba(0,255,0,0.3)]">
    <!-- Header -->
    <div class="mb-6 text-center">
      <div class="text-4xl mb-2 terminal-glow">{'>'} SVALINN</div>
      <div class="text-xs text-[#00aa00] terminal-glow">
        {mode === 'login' ? '[ AUTHENTICATE ]' : '[ INITIALIZE NEW USER ]'}
      </div>
    </div>

    <form on:submit|preventDefault={handleSubmit} class="space-y-4">
      {#if mode === 'register'}
        <div>
          <label class="block text-xs text-[#00aa00] mb-1 terminal-glow">{'>'} Username:</label>
          <input
            type="text"
            bind:value={username}
            required
            minlength={3}
            placeholder="enter_username"
            class="w-full bg-[#0a0e0a] border border-[#00ff00] px-3 py-2 text-[#00ff00] placeholder-[#00aa00] focus:outline-none focus:shadow-[0_0_10px_rgba(0,255,0,0.3)] transition-all"
            disabled={loading}
          />
        </div>
      {/if}

      <div>
        <label class="block text-xs text-[#00aa00] mb-1 terminal-glow">{'>'} Email:</label>
        <input
          type="email"
          bind:value={email}
          required
          placeholder="user@domain.com"
          class="w-full bg-[#0a0e0a] border border-[#00ff00] px-3 py-2 text-[#00ff00] placeholder-[#00aa00] focus:outline-none focus:shadow-[0_0_10px_rgba(0,255,0,0.3)] transition-all"
          disabled={loading}
        />
      </div>

      <div>
        <label class="block text-xs text-[#00aa00] mb-1 terminal-glow">{'>'} Password:</label>
        <input
          type="password"
          bind:value={password}
          required
          minlength={6}
          placeholder="••••••••"
          class="w-full bg-[#0a0e0a] border border-[#00ff00] px-3 py-2 text-[#00ff00] placeholder-[#00aa00] focus:outline-none focus:shadow-[0_0_10px_rgba(0,255,0,0.3)] transition-all"
          disabled={loading}
        />
      </div>

      {#if error}
        <div class="text-red-500 text-xs terminal-glow border border-red-500 p-2">
          {'>'} ERROR: {error}
        </div>
      {/if}

      <button
        type="submit"
        disabled={loading}
        class="w-full py-2 bg-black border-2 border-[#00ff00] text-[#00ff00] font-semibold uppercase tracking-wider hover:bg-[#00ff00] hover:text-black transition-all disabled:opacity-50 disabled:cursor-not-allowed terminal-glow"
      >
        {loading 
          ? '[ PROCESSING... ]' 
          : mode === 'login' 
            ? '[ EXECUTE LOGIN ]' 
            : '[ EXECUTE REGISTER ]'}
      </button>

      <div class="text-center pt-2">
        <button
          type="button"
          on:click={toggleMode}
          class="text-xs text-[#00aa00] hover:text-[#00ff00] terminal-glow"
          disabled={loading}
        >
          {mode === 'login' 
            ? '> no account? initialize new user' 
            : '> existing user? authenticate'}
        </button>
      </div>
    </form>

    <!-- Footer -->
    <div class="mt-6 text-center text-[10px] text-[#00aa00] terminal-glow">
      SVALINN v0.1.0 | SECURE CHANNEL
    </div>
  </div>
</div>