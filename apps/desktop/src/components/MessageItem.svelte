<script lang="ts">
  import { createEventDispatcher } from 'svelte';

  export let message: any;
  export let isOwnMessage: boolean = false;
  export let showHeader: boolean = true;
  export let selectionMode: boolean = false;
  export let isSelected: boolean = false;
  export let isHighlighted: boolean = false;
  export let isPinned: boolean = false;

  const dispatch = createEventDispatcher();

  function handleSelect() {
    dispatch('select', message.id);
  }

  function handleUserClick() {
    dispatch('userClicked', message.user_id);
  }

  function formatTime(dateString: string): string {
    const date = new Date(dateString);
    return date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
  }
</script>

<div 
  class="group flex gap-3 px-4 py-2 hover:bg-[rgba(0,255,0,0.05)] transition-colors {isHighlighted ? 'bg-[rgba(0,255,0,0.1)] border-l-2 border-[#00ff00]' : ''}"
>
  <!-- Selection Checkbox -->
  {#if selectionMode}
    <div class="flex items-center pt-1">
      <input 
        type="checkbox" 
        class="w-4 h-4 accent-[#00ff00] cursor-pointer" 
        checked={isSelected} 
        on:change={handleSelect}
      />
    </div>
  {/if}

  <!-- Avatar (Only show if it's the first message from this user in a row) -->
  {#if showHeader}
    <button 
      class="w-10 h-10 rounded-full border-2 border-[#00ff00] flex items-center justify-center font-bold text-sm bg-black text-[#00ff00] hover:bg-[#00ff00] hover:text-black transition-all flex-shrink-0"
      on:click={handleUserClick}
    >
      {message.username[0].toUpperCase()}
    </button>
  {:else}
    <!-- Spacer to align text when avatar is hidden -->
    <div class="w-10 flex-shrink-0"></div>
  {/if}

  <!-- Message Content -->
  <div class="flex-1 min-w-0">
    <!-- Header: Username and Timestamp -->
    {#if showHeader}
      <div class="flex items-baseline gap-2 mb-1">
        <button 
          class="font-bold text-[#00ff00] hover:underline terminal-glow"
          on:click={handleUserClick}
        >
          {message.username}
        </button>
        {#if isPinned}
          <span class="text-xs text-[#00aa00]">📌 Pinned</span>
        {/if}
        <span class="text-xs text-[#00aa00]">{formatTime(message.created_at)}</span>
        {#if message.is_edited}
          <span class="text-[10px] text-[#00aa00] italic">(edited)</span>
        {/if}
      </div>
    {/if}

    <!-- Text Content -->
    {#if message.content}
      <div class="text-sm text-[#00ff00] whitespace-pre-wrap break-words">
        {message.content}
      </div>
    {/if}

    <!-- Attachment Display -->
    {#if message.attachment_url}
      <div class="mt-2">
        {#if message.attachment_mime_type && message.attachment_mime_type.startsWith('image/')}
          <!-- Display Images -->
          <img 
            src="http://localhost:3001{message.attachment_url}" 
            alt={message.attachment_filename || 'Image attachment'}
            class="max-w-sm max-h-80 rounded border border-[#00ff00] cursor-pointer hover:opacity-80 transition-opacity"
            on:click={() => window.open(`http://localhost:3001${message.attachment_url}`, '_blank')}
          />
        {:else if message.attachment_mime_type && message.attachment_mime_type.startsWith('video/')}
          <!-- Display Videos -->
          <video controls class="max-w-sm max-h-80 rounded border border-[#00ff00]">
            <source src="http://localhost:3001{message.attachment_url}" type={message.attachment_mime_type} />
            Your browser does not support the video tag.
          </video>
        {:else}
          <!-- Display Other Files as Download Links -->
          <a 
            href="http://localhost:3001{message.attachment_url}" 
            target="_blank"
            class="inline-flex items-center gap-2 px-3 py-2 bg-[#0a0e0a] border border-[#00ff00] text-[#00ff00] hover:bg-[#00ff00] hover:text-black transition-all terminal-glow rounded"
          >
            📎 {message.attachment_filename || 'Download File'}
            {#if message.attachment_size}
              <span class="text-xs text-[#00aa00]">({(message.attachment_size / 1024).toFixed(1)} KB)</span>
            {/if}
          </a>
        {/if}
      </div>
    {/if}
  </div>
</div>

<style>
  .terminal-glow {
    text-shadow: 0 0 5px rgba(0, 255, 0, 0.5);
  }
</style>