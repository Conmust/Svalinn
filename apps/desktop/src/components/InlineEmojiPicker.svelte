<script lang="ts">
  import { createEventDispatcher, onMount, onDestroy } from 'svelte';

  const dispatch = createEventDispatcher();
  let isOpen = false;

  const emojis = [
    '😀', '😃', '😄', '😁', '😆', '😅', '🤣', '😂',
    '🙂', '🙃', '😉', '😊', '😇', '🥰', '😍', '🤩',
    '😘', '😗', '😚', '😙', '😋', '😛', '😜', '🤪',
    '😝', '🤑', '🤗', '🤭', '🤫', '🤔', '🤐', '🤨',
    '😐', '😑', '😶', '😏', '😒', '🙄', '😬', '🤥',
    '😌', '😔', '😪', '🤤', '😴', '😷', '🤒', '🤕',
    '🤢', '🤮', '🥵', '🥶', '🥴', '😵', '🤯', '🤠',
    '🥳', '😎', '🤓', '🧐', '😕', '😟', '🙁', '☹️',
    '😮', '😯', '😲', '😳', '🥺', '😦', '😧', '😨',
    '😰', '😥', '😢', '😭', '😱', '😖', '😣', '😞',
    '😓', '😩', '😫', '🥱', '😤', '😡', '😠', '🤬',
    '👍', '👎', '👌', '✌️', '🤞', '🤟', '🤘', '🤙',
    '❤️', '🧡', '💛', '💚', '💙', '💜', '🖤', '🤍',
    '💯', '💢', '💥', '💫', '💦', '💨', '🕳️', '💣',
    '🔥', '✨', '🌟', '⭐', '🎉', '🎊', '🎈', '🎁',
    '🚀', '⚡', '💎', '🏆', '🥇', '✅', '❌', '⚠️'
  ];

  function toggle() {
    isOpen = !isOpen;
  }

  function select(emoji: string) {
    dispatch('select', emoji);
    isOpen = false;
  }

  function handleClickOutside(e: MouseEvent) {
    const target = e.target as HTMLElement;
    if (!target.closest('.inline-emoji-picker')) {
      isOpen = false;
    }
  }

  onMount(() => document.addEventListener('click', handleClickOutside));
  onDestroy(() => document.removeEventListener('click', handleClickOutside));
</script>

<div class="inline-emoji-picker relative">
  <button
    type="button"
    class="h-10 w-10 bg-black border border-[#00ff00] flex items-center justify-center text-[#00ff00] hover:bg-[#00ff00] hover:text-black transition-all terminal-glow flex-shrink-0"
    on:click|preventDefault={toggle}
    title="Insert emoji"
  >
    <svg xmlns="http://www.w3.org/2000/svg" style="width: 18px !important; height: 18px !important; display: block !important;" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.828 14.828a4 4 0 01-5.656 0M9 10h.01M15 10h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
    </svg>
  </button>

  {#if isOpen}
    <div class="absolute bottom-full right-0 mb-2 w-80 bg-black border-2 border-[#00ff00] shadow-[0_0_20px_rgba(0,255,0,0.4)] z-50 flex flex-col">
      <div class="px-3 py-2 border-b border-[#00ff00] bg-[#0a0e0a] flex items-center gap-2">
        <div class="w-2 h-2 bg-[#00ff00] rounded-full animate-pulse"></div>
        <span class="text-xs font-bold uppercase tracking-widest text-[#00ff00] terminal-glow">
          {'>'} Insert Emoji
        </span>
      </div>
      <div class="p-3 overflow-y-auto max-h-64 custom-scrollbar">
        <div class="grid grid-cols-8 gap-1">
          {#each emojis as emoji}
            <button
              type="button"
              class="w-8 h-8 flex items-center justify-center text-xl hover:bg-[rgba(0,255,0,0.2)] hover:scale-110 rounded transition-all"
              on:click|preventDefault={() => select(emoji)}
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
  .custom-scrollbar::-webkit-scrollbar { width: 6px; }
  .custom-scrollbar::-webkit-scrollbar-track { background: #0a0e0a; border-radius: 3px; }
  .custom-scrollbar::-webkit-scrollbar-thumb { background: #00ff00; border-radius: 3px; }
  .custom-scrollbar::-webkit-scrollbar-thumb:hover { background: #00aa00; }
  .custom-scrollbar { scrollbar-width: thin; scrollbar-color: #00ff00 #0a0e0a; }
</style>