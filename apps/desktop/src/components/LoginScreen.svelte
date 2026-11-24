<script lang="ts">
  import { login, register } from '../lib/auth';

  let isRegistering = false;
  let email = '';
  let username = '';
  let password = '';
  let error = '';
  let loading = false;

  async function handleSubmit() {
    error = '';
    loading = true;

    try {
      if (isRegistering) {
        await register(username, email, password);
      } else {
        await login(email, password);
      }
      // Dispatch event to parent
      window.location.reload();
    } catch (e: any) {
      error = e.message;
    } finally {
      loading = false;
    }
  }
</script>

<div class="flex items-center justify-center min-h-screen bg-obsidian">
  <div class="w-full max-w-md p-8 bg-[#111216] rounded-lg shadow-2xl border border-gray-800">
    <div class="text-center mb-8">
      <h1 class="text-4xl font-bold text-frost-blue mb-2">🛡️ Svalinn</h1>
      <p class="text-tungsten">{isRegistering ? 'Create your account' : 'Welcome back'}</p>
    </div>

    <form on:submit|preventDefault={handleSubmit} class="space-y-4">
      {#if isRegistering}
        <div>
          <label for="loginscreen-username" class="block text-sm font-medium text-tungsten mb-2">Username</label>
          <input
            id="loginscreen-username"
            type="text"
            bind:value={username}
            required
            class="w-full px-4 py-2.5 bg-[#0B0C10] border border-gray-700 rounded text-tungsten placeholder-gray-500 focus:outline-none focus:border-frost-blue transition-colors"
            placeholder="your_username"
          />
        </div>
      {/if}

      <div>
        <label for="loginscreen-email" class="block text-sm font-medium text-tungsten mb-2">Email</label>
        <input
          id="loginscreen-email"
          type="email"
          bind:value={email}
          required
          class="w-full px-4 py-2.5 bg-[#0B0C10] border border-gray-700 rounded text-tungsten placeholder-gray-500 focus:outline-none focus:border-frost-blue transition-colors"
          placeholder="you@example.com"
        />
      </div>

      <div>
        <label for="loginscreen-password" class="block text-sm font-medium text-tungsten mb-2">Password</label>
        <input
          id="loginscreen-password"
          type="password"
          bind:value={password}
          required
          minlength="6"
          class="w-full px-4 py-2.5 bg-[#0B0C10] border border-gray-700 rounded text-tungsten placeholder-gray-500 focus:outline-none focus:border-frost-blue transition-colors"
          placeholder="••••••••"
        />
      </div>

      {#if error}
        <div class="p-3 bg-red-900/20 border border-red-800 rounded text-red-400 text-sm">
          {error}
        </div>
      {/if}

      <button
        type="submit"
        disabled={loading}
        class="w-full py-2.5 bg-frost-blue text-obsidian font-semibold rounded hover:bg-frost-blue/90 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
      >
        {loading ? 'Please wait...' : (isRegistering ? 'Create Account' : 'Login')}
      </button>
    </form>

    <div class="mt-6 text-center">
      <button
        on:click={() => { isRegistering = !isRegistering; error = ''; }}
        class="text-sm text-gray-400 hover:text-frost-blue transition-colors"
      >
        {isRegistering ? 'Already have an account? Login' : "Don't have an account? Register"}
      </button>
    </div>
  </div>
</div>