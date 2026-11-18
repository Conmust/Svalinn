<script lang="ts">
  import { fileUrl } from '../lib/api';
  import { createEventDispatcher } from 'svelte';
  import ReactionPicker from './ReactionPicker.svelte';
  import type { Message } from '../lib/messages';

  export let message: Message;
  export let currentUserId: string = '';
  /** Owner, admin or moderator of this server. */
  export let canModerate: boolean = false;
  export let showHeader: boolean = true;
  export let selectionMode: boolean = false;
  export let isSelected: boolean = false;
  export let isHighlighted: boolean = false;

  const dispatch = createEventDispatcher<{
    select: string;
    userClicked: string;
    toggleReaction: { messageId: string; emoji: string };
    pin: Message;
    lock: Message;
    hide: Message;
    unhide: Message;
    delete: Message;
  }>();

  let pickerOpen = false;

  $: isOwn = message.user_id === currentUserId;
  $: canDelete = (isOwn || canModerate) && !message.is_locked;
  $: reactions = message.reactions ?? [];

  function formatTime(dateString: string): string {
    const date = new Date(dateString);
    return date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
  }

  const toolButton =
    'px-2 py-1 text-xs text-[#00aa00] hover:text-black hover:bg-[#00ff00] transition-colors terminal-glow';
</script>

{#if message.is_hidden}
  <!-- Hidden for this user only -->
  <div class="flex gap-3 px-4 py-1">
    <div class="w-10 flex-shrink-0"></div>
    <div class="text-xs text-[#00aa00]/70 italic">
      Message from {message.username} hidden.
      <button
        type="button"
        class="ml-1 not-italic underline hover:text-[#00ff00]"
        on:click={() => dispatch('unhide', message)}
      >Show</button>
    </div>
  </div>
{:else}
<div
  class="group relative flex gap-3 px-4 py-2 hover:bg-[rgba(0,255,0,0.05)] transition-colors {isHighlighted ? 'bg-[rgba(0,255,0,0.1)] border-l-2 border-[#00ff00]' : ''} {message.is_pinned ? 'border-l-2 border-[#00aa00]' : ''}"
>
  <!-- Selection Checkbox -->
  {#if selectionMode}
    <div class="flex items-center pt-1">
      <input
        type="checkbox"
        class="w-4 h-4 accent-[#00ff00] cursor-pointer"
        checked={isSelected}
        on:change={() => dispatch('select', message.id)}
      />
    </div>
  {/if}

  <!-- Avatar (only on the first message of a run from the same user) -->
  {#if showHeader}
    <button
      type="button"
      class="w-10 h-10 rounded-full border-2 border-[#00ff00] flex items-center justify-center font-bold text-sm bg-black text-[#00ff00] hover:bg-[#00ff00] hover:text-black transition-all flex-shrink-0"
      on:click={() => dispatch('userClicked', message.user_id)}
    >
      {message.username[0].toUpperCase()}
    </button>
  {:else}
    <div class="w-10 flex-shrink-0"></div>
  {/if}

  <div class="flex-1 min-w-0">
    {#if showHeader}
      <div class="flex items-baseline gap-2 mb-1">
        <button
          type="button"
          class="font-bold text-[#00ff00] hover:underline terminal-glow"
          on:click={() => dispatch('userClicked', message.user_id)}
        >
          {message.username}
        </button>
        <span class="text-xs text-[#00aa00]">{formatTime(message.created_at)}</span>
        {#if message.is_edited}
          <span class="text-[10px] text-[#00aa00] italic">(edited)</span>
        {/if}
      </div>
    {/if}

    {#if message.is_pinned || message.is_locked}
      <div class="flex gap-2 mb-1 text-[10px] uppercase tracking-wider text-[#00aa00]">
        {#if message.is_pinned}<span title="Pinned">📌 Pinned</span>{/if}
        {#if message.is_locked}<span title="Locked: can't be deleted until a moderator unlocks it">🔒 Locked</span>{/if}
      </div>
    {/if}

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
              src={fileUrl(message.attachment_url)} 
              alt={message.attachment_filename || 'Image attachment'}
              class="max-w-sm max-h-80 rounded border border-[#00ff00] cursor-pointer hover:opacity-80 transition-opacity"
              on:click={() => window.open(fileUrl(message.attachment_url), '_blank')}
            />
          {:else if message.attachment_mime_type && message.attachment_mime_type.startsWith('video/')}
            <!-- Display Videos -->
            <video controls class="max-w-sm max-h-80 rounded border border-[#00ff00]">
              <source src={fileUrl(message.attachment_url)} type={message.attachment_mime_type} />
              Your browser does not support the video tag.
            </video>
          {:else}
            <!-- Display Other Files as Download Links -->
            <a 
              href={fileUrl(message.attachment_url)} 
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

    <!-- Reactions: click a chip to add or remove your reaction -->
    {#if reactions.length > 0}
      <div class="flex flex-wrap gap-1 mt-2">
        {#each reactions as reaction (reaction.emoji)}
          {@const mine = reaction.user_ids.includes(currentUserId)}
          <button
            type="button"
            class="px-2 py-0.5 text-xs border rounded flex items-center gap-1 transition-colors {mine ? 'border-[#00ff00] bg-[rgba(0,255,0,0.15)] text-[#00ff00]' : 'border-[#00aa00]/50 text-[#00aa00] hover:border-[#00ff00]'}"
            title={mine ? 'Remove your reaction' : 'React with ' + reaction.emoji}
            on:click={() => dispatch('toggleReaction', { messageId: message.id, emoji: reaction.emoji })}
          >
            <span class="text-sm">{reaction.emoji}</span>
            <span>{reaction.count}</span>
          </button>
        {/each}
      </div>
    {/if}
  </div>

  <!-- Hover toolbar -->
  {#if !selectionMode}
    <div
      class="absolute -top-3 right-4 flex items-center bg-black border border-[#00ff00] shadow-[0_0_10px_rgba(0,255,0,0.3)] transition-opacity {pickerOpen ? 'opacity-100' : 'opacity-0 group-hover:opacity-100 focus-within:opacity-100'}"
    >
      <ReactionPicker
        on:openchange={(e) => (pickerOpen = e.detail)}
        on:select={(e) => dispatch('toggleReaction', { messageId: message.id, emoji: e.detail })}
      />
      {#if canModerate}
        <button type="button" class={toolButton} title={message.is_pinned ? 'Unpin' : 'Pin'} on:click={() => dispatch('pin', message)}>
          {message.is_pinned ? 'Unpin' : 'Pin'}
        </button>
        <button type="button" class={toolButton} title={message.is_locked ? 'Unlock: allow deleting again' : 'Lock: prevent deleting'} on:click={() => dispatch('lock', message)}>
          {message.is_locked ? 'Unlock' : 'Lock'}
        </button>
      {/if}
      <button type="button" class={toolButton} title="Hide this message for you only" on:click={() => dispatch('hide', message)}>
        Hide
      </button>
      {#if isOwn || canModerate}
        <button
          type="button"
          class="px-2 py-1 text-xs transition-colors {canDelete ? 'text-red-500 hover:text-black hover:bg-red-500' : 'text-red-500/40 cursor-not-allowed'}"
          title={canDelete ? 'Delete' : 'Locked messages can\'t be deleted'}
          disabled={!canDelete}
          on:click={() => dispatch('delete', message)}
        >
          Delete
        </button>
      {/if}
    </div>
  {/if}
</div>
{/if}

<style>
  .terminal-glow {
    text-shadow: 0 0 5px rgba(0, 255, 0, 0.5);
  }
</style>
