<script lang="ts">
  import { createEventDispatcher, onMount, onDestroy } from 'svelte';

  const dispatch = createEventDispatcher();
  let isOpen = false;

  // Expanded emoji list for better variety
  const emojis = [
    '👍', '👎', '❤️', '🔥', '😂', '😮', '😢', '😡',
    '🎉', '💯', '🙏', '👀', '🤔', '👏', '🚀', '💀',
    '✨', '💩', '🤡', '👽', '🤖', '👻', '🎃', '👑',
    '🌟', '⚡', '💥', '💦', '🌈', '🍕', '🍔', '☕',
    '🍺', '🎵', '🎮', '⚽', '🏀', '🏆', '🥇', '✅',
    '❌', '⚠️', '🚫', '💬', '💭', '💤', '🌙', '☀️',
    '🌧️', '❄️', '🌪️', '🌊', '🌍', '🌕', '⭐', '💎',
    '🛡️', '⚔️', '🏹', '🧪', '🔮', '🧩', '🎯', '🎲'
  ];

  function togglePicker() {
    isOpen = !isOpen;
  }

  function selectEmoji(emoji: string) {
    dispatch('select', emoji);
    isOpen = false;
  }

  function handleClickOutside(e: MouseEvent) {
    const target = e.target as HTMLElement;
    if (!target.closest('.reaction-picker')) {
      isOpen = false;
    }
  }

  onMount(() => {
    document.addEventListener('click', handleClickOutside);
  });

  onDestroy(() => {
    document.removeEventListener('click', handleClickOutside);
  });
</script>

<div class="reaction-picker relative inline-block">
  <button
    type="button"
    class="p-1.5 text-[#00aa00] hover:text-[#00ff00] hover:bg-[rgba(0,255,0,0.1)] rounded terminal-glow"
    title="Add reaction"
    on:click={togglePicker}
  >
    <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.828 14.828a4 4 0 01-5.656 0M9 10h.01M15 10h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
    </svg>
  </button>

  {#if isOpen}
    <div class="absolute bottom-full right-0 mb-2 w-80 bg-black border-2 border-[#00ff00] shadow-[0_0_20px_rgba(0,255,0,0.4)] z-50 flex flex-col animate-pulse-once">
      <!-- Header -->
      <div class="px-3 py-2 border-b border-[#00ff00] bg-[#0a0e0a] flex items-center gap-2">
        <div class="w-2 h-2 bg-[#00ff00] rounded-full animate-pulse"></div>
        <span class="text-xs font-bold uppercase tracking-widest text-[#00ff00] terminal-glow">
          {'>'} Select Reaction
        </span>
      </div>
      
      <!-- Scrollable Grid -->
      <div class="p-3 overflow-y-auto max-h-80 custom-scrollbar">
        <div class="grid grid-cols-8 gap-2">
          {#each emojis as emoji}
            <button
              type="button"
              class="w-8 h-8 flex items-center justify-center text-xl hover:bg-[rgba(0,255,0,0.2)] hover:scale-110 rounded transition-all"
              on:click={() => selectEmoji(emoji)}
              title={emoji}
            >
              {emoji}
            </button>
          {/each}
        </div>
      </div>
    </div>
  {/if}
</div>

<style>
  @keyframes pulse-once {
    0% { transform: scale(0.95) translateY(10px); opacity: 0; }
    100% { transform: scale(1) translateY(0); opacity: 1; }
  }
  .animate-pulse-once {
    animation: pulse-once 0.15s ease-out;
  }

  /* Terminal-themed scrollbar for the picker */
  .custom-scrollbar::-webkit-scrollbar {
    width: 6px;
  }
  .custom-scrollbar::-webkit-scrollbar-track {
    background: #0a0e0a;
    border-radius: 3px;
  }
  .custom-scrollbar::-webkit-scrollbar-thumb {
    background: #00ff00;
    border-radius: 3px;
  }
  .custom-scrollbar::-webkit-scrollbar-thumb:hover {
    background: #00aa00;
  }
</style>