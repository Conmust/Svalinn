<script lang="ts">
  import { createEventDispatcher } from 'svelte';
  import { createServer } from '../lib/servers';

  export let isOpen = false;

  const dispatch = createEventDispatcher();

  let serverName = '';
  let loading = false;
  let error = '';

  function handleKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape' && isOpen) {
      closeModal();
    }
  }

  async function handleSubmit() {
    if (!serverName.trim()) {
      error = 'Server name is required';
      return;
    }

    loading = true;
    error = '';

    try {
      const newServer = await createServer(serverName.trim());
      dispatch('serverCreated', newServer);
      closeModal();
    } catch (e: any) {
      error = e.message;
    } finally {
      loading = false;
    }
  }

  function closeModal() {
    serverName = '';
    error = '';
    dispatch('close');
  }
</script>

<svelte:window on:keydown={handleKeydown} />

{#if isOpen}
  <div class="fixed inset-0 z-50 flex items-center justify-center">
    <!-- Backdrop button. It is separate from the modal content. -->
    <button
      type="button"
      class="absolute inset-0 bg-black/70 border-0 cursor-default"
      on:click={closeModal}
      aria-label="Close create server modal"
    ></button>

    <!-- Modal content is NOT inside the button. -->
    <div
      class="relative z-10 bg-[#16171D] rounded-lg p-6 w-full max-w-md border border-gray-800 shadow-2xl"
      role="dialog"
      aria-modal="true"
      aria-labelledby="create-server-title"
    >
      <h2 id="create-server-title" class="text-2xl font-bold text-tungsten mb-4">
        Create a Server
      </h2>

      <p class="text-gray-400 text-sm mb-6">
        Give your new server a personality with a name.
      </p>

      <form on:submit|preventDefault={handleSubmit} class="space-y-4">
        <label class="block">
          <span class="block text-sm font-semibold text-tungsten mb-2">
            SERVER NAME
          </span>

          <input
            type="text"
            bind:value={serverName}
            placeholder="My Awesome Server"
            class="w-full bg-[#0B0C10] border border-gray-800 rounded px-3 py-2 text-tungsten placeholder-gray-500 focus:outline-none focus:border-frost-blue transition-colors"
            disabled={loading}
            maxlength={100}
          />
        </label>

        {#if error}
          <div class="p-3 bg-red-900/20 border border-red-800 rounded text-red-400 text-sm">
            {error}
          </div>
        {/if}

        <div class="flex gap-3 pt-4">
          <button
            type="button"
            on:click={closeModal}
            class="flex-1 px-4 py-2 bg-gray-800 hover:bg-gray-700 text-tungsten rounded transition-colors"
            disabled={loading}
          >
            Cancel
          </button>

          <button
            type="submit"
            class="flex-1 px-4 py-2 bg-frost-blue hover:bg-frost-blue/80 text-obsidian font-semibold rounded transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            disabled={loading || !serverName.trim()}
          >
            {loading ? 'Creating...' : 'Create'}
          </button>
        </div>
      </form>
    </div>
  </div>
{/if}