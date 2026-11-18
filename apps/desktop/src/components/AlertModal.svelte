<script lang="ts">
  import { createEventDispatcher, onMount, onDestroy } from 'svelte';

  export let title: string = 'NOTIFICATION';
  export let message: string = '';
  export let buttonText: string = 'ACKNOWLEDGE';
  export let variant: 'success' | 'error' | 'warning' | 'info' = 'info';

  const dispatch = createEventDispatcher();

  const variantColors = {
    success: { border: '#00ff00', glow: 'rgba(0,255,0,0.4)', text: '#00ff00', icon: '✓' },
    error: { border: '#ff0000', glow: 'rgba(255,0,0,0.4)', text: '#ff0000', icon: '✗' },
    warning: { border: '#ffaa00', glow: 'rgba(255,170,0,0.4)', text: '#ffaa00', icon: '!' },
    info: { border: '#00aaff', glow: 'rgba(0,170,255,0.4)', text: '#00aaff', icon: 'i' }
  };

  const colors = variantColors[variant];

  function handleClose() {
    dispatch('close');
  }

  function handleKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape' || e.key === 'Enter') {
      handleClose();
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
    on:click={handleClose}
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

    <!-- Header with Icon -->
    <div class="mb-4 flex items-center gap-3">
      <div 
        class="w-8 h-8 border-2 flex items-center justify-center font-bold text-lg"
        style="border-color: {colors.border}; color: {colors.text}; box-shadow: 0 0 12px {colors.glow};"
      >
        {colors.icon}
      </div>
      <h3 class="font-bold uppercase tracking-widest text-sm terminal-glow" style="color: {colors.text};">
        {'>'} {title}
      </h3>
    </div>

    <!-- Message -->
    <div class="mb-6 px-3 py-3 border border-[#00ff00]/30 bg-[#0a0e0a]">
      <p class="text-sm text-[#00ff00] terminal-glow leading-relaxed whitespace-pre-wrap">
        {'>'} {message}
      </p>
    </div>

    <!-- Button -->
    <button
      type="button"
      class="w-full px-4 py-2 bg-black border-2 text-xs font-semibold uppercase tracking-wider transition-all terminal-glow"
      style="border-color: {colors.border}; color: {colors.text};"
      on:click={handleClose}
      on:mouseenter={(e) => {
        e.currentTarget.style.backgroundColor = colors.border;
        e.currentTarget.style.color = '#000';
      }}
      on:mouseleave={(e) => {
        e.currentTarget.style.backgroundColor = '#000';
        e.currentTarget.style.color = colors.text;
      }}
    >
      [{buttonText}]
    </button>

    <!-- Footer -->
    <div class="mt-4 text-center text-[10px] text-[#00aa00] terminal-glow">
      [ ENTER ] or [ ESC ] to dismiss
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