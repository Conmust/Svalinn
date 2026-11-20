<script lang="ts">
  /// Owner-granted badge, independent of the patron tier badge
  /// (`PatronBadge.svelte`) -- shown alongside it, never instead of it.
  export let size: 'small' | 'medium' | 'large' = 'small';

  const sizeClasses = {
    small: 'w-4 h-4',
    medium: 'w-5 h-5',
    large: 'w-6 h-6'
  };

  const color = '#ff2db8';
  const glow = `0 0 8px ${color}`;
</script>

<span class="{sizeClasses[size]} inline-flex items-center justify-center" title="Beta">
  <span
    class="w-full h-full flex items-center justify-center font-bold leading-none"
    style="color: {color}; filter: drop-shadow({glow}); font-size: 0.9em;"
  >&#946;</span>
</span>
