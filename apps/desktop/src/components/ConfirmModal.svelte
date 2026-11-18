<script lang="ts">
  import { createEventDispatcher, onMount, onDestroy } from 'svelte';

  export let title: string = 'CONFIRM ACTION';
  export let message: string = 'Are you sure?';
  export let confirmText: string = 'CONFIRM';
  export let cancelText: string = 'CANCEL';
  export let variant: 'danger' | 'warning' | 'info' = 'danger';

  const dispatch = createEventDispatcher();

  const variantColors = {
    danger: { border: '#ff0000', glow: 'rgba(255,0,0,0.4)', text: '#ff0000' },
    warning: { border: '#ffaa00', glow: 'rgba(255,170,0,0.4)', text: '#ffaa00' },
    info: { border: '#00ff00', glow: 'rgba(0,255,0,0.4)', text: '#00ff00' }
  };

  const colors = variantColors[variant];

  function handleConfirm() {
    dispatch('confirm');
  }

  function handleCancel() {
    dispatch('cancel');
  }

  function handleKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape') {
      handleCancel();
    } else if (e.key === 'Enter') {
      handleConfirm();
    }
  }

  onMount(() => {
    window.addEventListener('keydown', handleKeydown);
  });

  onDestroy(() => {
    window.removeEventListener('keydown', handleKeydown);
  });
</script>

<div class="fixed inset-0 z-[100] flex items-center justify-center">
  <!-- Backdrop -->
  <div 
    class="absolute inset-0 bg-black/80 backdrop-blur-sm"
    on:click={handleCancel}
    on:keydown={() => {}}
    role="button"
    tabindex="-1"
  ></div>

  <!-- Modal -->
  <div 
    class="relative w-96 max-w-[90vw] border-2 bg-black p-6 shadow-lg animate-pulse-once"
    style="border-color: {colors.border}; box-shadow: 0 0 30px {colors.glow}, inset 0 0 20px rgba(0,0,0,0.8);"
  >
    <!-- Scan-line effect overlay -->
    <div class="absolute inset-0 pointer-events-none opacity-20"
      style="background: repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,255,0,0.03) 2px, rgba(0,255,0,0.03) 4px);">
    </div>

    <!-- Header -->
    <div class="mb-4 flex items-center gap-2">
      <div class="w-3 h-3 border-2 animate-pulse" style="border-color: {colors.border}; box-shadow: 0 0 8px {colors.glow};"></div>
      <h3 class="font-bold uppercase tracking-widest text-sm terminal-glow" style="color: {colors.text};">
        {'>'} {title}
      </h3>
    </div>

    <!-- Message -->
    <div class="mb-6 px-2 py-3 border border-[#00ff00]/30 bg-[#0a0e0a]">
      <p class="text-sm text-[#00ff00] terminal-glow leading-relaxed whitespace-pre-wrap">
        {'>'} {message}
      </p>
    </div>

    <!-- Buttons -->
    <div class="flex gap-3">
      <button
        type="button"
        class="flex-1 px-4 py-2 bg-black border-2 text-xs font-semibold uppercase tracking-wider transition-all terminal-glow"
        style="border-color: {colors.border}; color: {colors.text};"
        on:click={handleConfirm}
        on:mouseenter={(e) => {
          e.currentTarget.style.backgroundColor = colors.border;
          e.currentTarget.style.color = '#000';
        }}
        on:mouseleave={(e) => {
          e.currentTarget.style.backgroundColor = '#000';
          e.currentTarget.style.color = colors.text;
        }}
      >
        [{confirmText}]
      </button>
      <button
        type="button"
        class="flex-1 px-4 py-2 bg-black border-2 border-[#00ff00] text-[#00ff00] text-xs font-semibold uppercase tracking-wider hover:bg-[#00ff00] hover:text-black transition-all terminal-glow"
        on:click={handleCancel}
      >
        [{cancelText}]
      </button>
    </div>

    <!-- Footer -->
    <div class="mt-4 text-center text-[10px] text-[#00aa00] terminal-glow">
      [ ENTER ] to confirm &nbsp;•&nbsp; [ ESC ] to cancel
    </div>
  </div>
</div>

<style>
  @keyframes pulse-once {
    0% { transform: scale(0.95); opacity: 0; }
    50% { transform: scale(1.02); }
    100% { transform: scale(1); opacity: 1; }
  }
  .animate-pulse-once {
    animation: pulse-once 0.2s ease-out;
  }
</style>