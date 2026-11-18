<script lang="ts">
  import { createEventDispatcher, onMount } from 'svelte';
  import { getAuthHeaders, apiFetch, fileUrl } from '../lib/api';
  import { fetchServerEmojis, uploadEmoji, deleteEmoji, type CustomEmoji } from '../lib/emojis';

  export let serverId: string;
  export let serverName: string = '';
  export let serverDescription: string = '';
  export let serverIconUrl: string = '';

  const dispatch = createEventDispatcher();

  let activeTab: 'overview' | 'emojis' = 'overview';
  let emojis: CustomEmoji[] = [];
  let loading = false;
  let uploadName = '';
  let uploadFile: File | null = null;
  let uploadError = '';

  let loaded = false;

  onMount(async () => {
    // Load the current values first. Saving the form sends every field, so
    // saving with unloaded defaults would wipe the server's real name/icon.
    try {
      const res = await apiFetch(`http://localhost:3001/api/v1/servers/${serverId}`, {
        headers: getAuthHeaders(),
      });
      if (res.ok) {
        const server = await res.json();
        serverName = server.name ?? '';
        serverDescription = server.description ?? '';
        serverIconUrl = server.icon_url ?? '';
      }
    } catch (e) {
      console.error('Failed to load server settings:', e);
    } finally {
      loaded = true;
    }
    if (activeTab === 'emojis') loadEmojis();
  });

  async function loadEmojis() {
    loading = true;
    try {
      emojis = await fetchServerEmojis(serverId);
    } catch (e) {
      console.error(e);
    } finally {
      loading = false;
    }
  }

  async function handleSaveOverview(e: Event) {
    e.preventDefault();
    if (!loaded) return;
    const res = await apiFetch(`http://localhost:3001/api/v1/servers/${serverId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
      body: JSON.stringify({
        name: serverName,
        description: serverDescription,
        icon_url: serverIconUrl
      })
    });
    if (res.ok) {
      dispatch('saved');
    } else {
      const err = await res.json().catch(() => ({}));
      alert(err.error || 'Failed to save server settings');
    }
  }

  // --- FIX: Dedicated handler for file input to avoid inline 'as' casting ---
  function handleFileChange(event: Event) {
    const target = event.target as HTMLInputElement;
    uploadFile = target.files?.[0] || null;
  }

  async function handleEmojiUpload(e: Event) {
    e.preventDefault();
    if (!uploadFile || !uploadName.trim()) return;
    
    uploadError = '';
    loading = true;
    try {
      await uploadEmoji(serverId, uploadName.trim(), uploadFile);
      uploadName = '';
      uploadFile = null;
      
      // Reset the file input visually
      const fileInput = document.getElementById('emoji-file-input') as HTMLInputElement;
      if (fileInput) fileInput.value = '';
      
      await loadEmojis();
    } catch (e: any) {
      uploadError = e.message;
    } finally {
      loading = false;
    }
  }

  async function handleDeleteEmoji(emojiId: string) {
    if (!confirm('Delete this emoji?')) return;
    try {
      await deleteEmoji(serverId, emojiId);
      await loadEmojis();
    } catch (e: any) {
      alert(e.message);
    }
  }
</script>

<!-- Outer Backdrop: Added on:keydown for A11y -->
<div 
  class="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm" 
  on:click={() => dispatch('close')} 
  on:keydown={(e) => e.key === 'Escape' && dispatch('close')}
  role="dialog" 
  aria-modal="true"
  tabindex="-1"
>
  <!-- Inner Modal Content -->
  <div 
    class="relative w-[600px] max-w-[90vw] max-h-[80vh] bg-black border-2 border-[#00ff00] shadow-[0_0_30px_rgba(0,255,0,0.4)] flex flex-col" 
    on:click|stopPropagation 
    on:keydown|stopPropagation
    role="document"
  >
    
    <!-- Header -->
    <div class="p-4 border-b border-[#00ff00] flex items-center justify-between">
      <h3 class="font-bold uppercase tracking-widest text-sm terminal-glow text-[#00ff00]">{'>'} Server Settings</h3>
      <button 
        class="text-[#00ff00] hover:text-red-500 terminal-glow transition-colors" 
        on:click={() => dispatch('close')}
        aria-label="Close settings"
      >
        ✕
      </button>
    </div>

    <!-- Tabs -->
    <div class="flex border-b border-[#00aa00]/30">
      <button 
        class="flex-1 py-3 text-sm font-semibold {activeTab === 'overview' ? 'text-[#00ff00] border-b-2 border-[#00ff00] bg-[rgba(0,255,0,0.05)]' : 'text-[#00aa00] hover:text-[#00ff00]'}" 
        on:click={() => activeTab = 'overview'}
      >
        Overview
      </button>
      <button 
        class="flex-1 py-3 text-sm font-semibold {activeTab === 'emojis' ? 'text-[#00ff00] border-b-2 border-[#00ff00] bg-[rgba(0,255,0,0.05)]' : 'text-[#00aa00] hover:text-[#00ff00]'}" 
        on:click={() => { activeTab = 'emojis'; loadEmojis(); }}
      >
        Emojis
      </button>
    </div>

    <!-- Content -->
    <div class="flex-1 overflow-y-auto p-6 custom-scrollbar">
      {#if activeTab === 'overview'}
        <form on:submit={handleSaveOverview} class="space-y-4">
          <div>
            <label for="server-name" class="block text-xs text-[#00aa00] uppercase tracking-wider mb-1">Server Name</label>
            <input id="server-name" bind:value={serverName} type="text" class="w-full bg-[#0a0e0a] border border-[#00ff00] px-3 py-2 text-[#00ff00] focus:outline-none focus:shadow-[0_0_10px_rgba(0,255,0,0.3)]" required />
          </div>
          <div>
            <label for="server-desc" class="block text-xs text-[#00aa00] uppercase tracking-wider mb-1">Description</label>
            <textarea id="server-desc" bind:value={serverDescription} rows="3" class="w-full bg-[#0a0e0a] border border-[#00ff00] px-3 py-2 text-[#00ff00] focus:outline-none focus:shadow-[0_0_10px_rgba(0,255,0,0.3)] resize-none"></textarea>
          </div>
          <div>
            <label for="server-icon" class="block text-xs text-[#00aa00] uppercase tracking-wider mb-1">Icon URL</label>
            <input id="server-icon" bind:value={serverIconUrl} type="text" class="w-full bg-[#0a0e0a] border border-[#00ff00] px-3 py-2 text-[#00ff00] focus:outline-none focus:shadow-[0_0_10px_rgba(0,255,0,0.3)]" placeholder="https://example.com/icon.png" />
          </div>
          <button type="submit" class="w-full py-2 bg-black border-2 border-[#00ff00] text-[#00ff00] font-semibold uppercase tracking-wider hover:bg-[#00ff00] hover:text-black transition-all terminal-glow">Save Changes</button>
        </form>
      {:else}
        <!-- Emoji Upload -->
        <form on:submit={handleEmojiUpload} class="mb-6 p-4 border border-[#00aa00]/30 bg-[#0a0e0a]">
          <h4 class="text-xs text-[#00aa00] uppercase tracking-wider mb-3">Upload New Emoji</h4>
          <div class="flex gap-2 mb-2">
            <input 
              bind:value={uploadName} 
              type="text" 
              placeholder="emoji_name" 
              class="flex-1 bg-black border border-[#00ff00] px-3 py-2 text-[#00ff00] text-sm focus:outline-none" 
              required 
              pattern="[a-z0-9_]+" 
              title="Lowercase letters, numbers, and underscores only" 
            />
            <!-- FIX: Uses the dedicated handleFileChange function instead of inline 'as' -->
            <input 
              id="emoji-file-input"
              type="file" 
              accept="image/*" 
              on:change={handleFileChange} 
              class="flex-1 text-xs text-[#00aa00] file:mr-2 file:py-1 file:px-2 file:rounded file:border file:border-[#00ff00] file:bg-black file:text-[#00ff00] file:cursor-pointer" 
              required 
            />
          </div>
          {#if uploadError}
            <div class="text-xs text-red-500 mb-2">{uploadError}</div>
          {/if}
          <button type="submit" disabled={loading || !uploadFile} class="px-4 py-1.5 bg-black border border-[#00ff00] text-[#00ff00] text-xs hover:bg-[#00ff00] hover:text-black transition-all disabled:opacity-50">Upload</button>
        </form>

        <!-- Emoji Grid -->
        {#if loading}
          <div class="text-[#00aa00] text-xs animate-pulse">{'>'} Loading emojis...</div>
        {:else if emojis.length === 0}
          <div class="text-[#00aa00] text-xs">{'>'} No custom emojis yet.</div>
        {:else}
          <div class="grid grid-cols-4 gap-4">
            {#each emojis as emoji}
              <div class="relative group bg-[#0a0e0a] border border-[#00aa00]/30 p-2 flex flex-col items-center">
                <img src={fileUrl(emoji.url)} alt={emoji.name} class="w-12 h-12 object-contain mb-2" />
                <span class="text-[10px] text-[#00aa00] text-center truncate w-full">:{emoji.name}:</span>
                <button 
                  class="absolute top-1 right-1 text-red-500 hover:text-red-400 opacity-0 group-hover:opacity-100 transition-opacity" 
                  on:click={() => handleDeleteEmoji(emoji.id)} 
                  title="Delete"
                  aria-label="Delete emoji"
                >
                  ✕
                </button>
              </div>
            {/each}
          </div>
        {/if}
      {/if}
    </div>
  </div>
</div>