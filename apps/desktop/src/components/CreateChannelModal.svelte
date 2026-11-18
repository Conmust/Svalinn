<script lang="ts">
  import { createEventDispatcher } from 'svelte';
  import { createChannel } from '../lib/servers';

  export let isOpen = false;
  export let serverId: string | null = null;

  const dispatch = createEventDispatcher();

  let channelName = '';
  let channelType = 'text';
  let loading = false;
  let error = '';

  function handleKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape' && isOpen) {
      closeModal();
    }
  }

  async function handleSubmit() {
    if (!channelName.trim()) {
      error = 'Channel name is required';
      return;
    }

    if (!serverId) {
      error = 'No server selected';
      return;
    }

    loading = true;
    error = '';

    try {
      const newChannel = await createChannel(
        serverId,
        channelName.trim(),
        channelType
      );

      dispatch('channelCreated', newChannel);
      closeModal();
    } catch (e: any) {
      error = e.message;
    } finally {
      loading = false;
    }
  }

  function closeModal() {
    channelName = '';
    channelType = 'text';
    error = '';
    dispatch('close');
  }
</script>

<svelte:window on:keydown={handleKeydown} />

{#if isOpen}
  <div class="fixed inset-0 z-50 flex items-center justify-center">
    <!-- Separate backdrop button -->
    <button
      type="button"
      class="absolute inset-0 bg-black/70 border-0 cursor-default"
      on:click={closeModal}
      aria-label="Close create channel modal"
    ></button>

    <!-- Modal content is separate, so Spacebar works normally in inputs -->
    <div
      class="relative z-10 bg-[#16171D] rounded-lg p-6 w-full max-w-md border border-gray-800 shadow-2xl"
      role="dialog"
      aria-modal="true"
      aria-labelledby="create-channel-title"
    >
      <h2 id="create-channel-title" class="text-2xl font-bold text-tungsten mb-4">
        Create a Channel
      </h2>

      <p class="text-gray-400 text-sm mb-6">
        Create a new channel in your server.
      </p>

      <form on:submit|preventDefault={handleSubmit} class="space-y-4">
        <label class="block">
          <span class="block text-sm font-semibold text-tungsten mb-2">
            CHANNEL NAME
          </span>

          <input
            type="text"
            bind:value={channelName}
            placeholder="new-channel"
            class="w-full bg-[#0B0C10] border border-gray-800 rounded px-3 py-2 text-tungsten placeholder-gray-500 focus:outline-none focus:border-frost-blue transition-colors"
            disabled={loading}
            maxlength={100}
          />
        </label>

        <fieldset>
          <legend class="block text-sm font-semibold text-tungsten mb-2">
            CHANNEL TYPE
          </legend>

          <div class="space-y-2">
            <label class="flex items-center gap-3 p-3 bg-[#0B0C10] border border-gray-800 rounded cursor-pointer hover:border-gray-600 transition-colors">
              <input
                type="radio"
                name="channelType"
                value="text"
                bind:group={channelType}
                class="text-frost-blue"
              />

              <div>
                <div class="text-tungsten font-medium"># Text Channel</div>
                <div class="text-xs text-gray-500">
                  Send messages, images, and files
                </div>
              </div>
            </label>

            <label class="flex items-center gap-3 p-3 bg-[#0B0C10] border border-gray-800 rounded cursor-pointer hover:border-gray-600 transition-colors">
              <input
                type="radio"
                name="channelType"
                value="voice"
                bind:group={channelType}
                class="text-frost-blue"
              />

              <div>
                <div class="text-tungsten font-medium">🔊 Voice Channel</div>
                <div class="text-xs text-gray-500">
                  Hang out together with voice and video
                </div>
              </div>
            </label>
          </div>
        </fieldset>

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
            disabled={loading || !channelName.trim()}
          >
            {loading ? 'Creating...' : 'Create'}
          </button>
        </div>
      </form>
    </div>
  </div>
{/if}