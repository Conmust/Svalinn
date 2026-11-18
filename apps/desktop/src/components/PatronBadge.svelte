<script lang="ts">
  export let tier: string = 'free';
  export let size: 'small' | 'medium' | 'large' = 'small';
  
  const sizeClasses = {
    small: 'w-4 h-4',
    medium: 'w-5 h-5',
    large: 'w-6 h-6'
  };

  const tierConfig = {
    patron: {
      icon: 'crown',
      color: '#ffd700',
      glow: '0 0 8px #ffd700',
      title: 'Svalinn Patron'
    },
    guild: {
      icon: 'shield',
      color: '#ff6b35',
      glow: '0 0 8px #ff6b35',
      title: 'Guild Owner'
    },
    enterprise: {
      icon: 'diamond',
      color: '#00ffff',
      glow: '0 0 8px #00ffff',
      title: 'Enterprise'
    },
    free: {
      icon: null,
      color: null,
      glow: null,
      title: null
    }
  };

  $: config = tierConfig[tier as keyof typeof tierConfig] || tierConfig.free;
</script>

{#if config.icon}
  <span 
    class="{sizeClasses[size]} inline-flex items-center justify-center"
    title={config.title}
  >
    {#if config.icon === 'crown'}
      <svg 
        xmlns="http://www.w3.org/2000/svg" 
        viewBox="0 0 24 24" 
        fill={config.color}
        style="filter: drop-shadow({config.glow});"
      >
        <path d="M5 16L3 5l5.5 5L12 4l3.5 6L21 5l-2 11H5zm14 3c0 .6-.4 1-1 1H6c-.6 0-1-.4-1-1v-1h14v1z"/>
      </svg>
    {:else if config.icon === 'shield'}
      <svg 
        xmlns="http://www.w3.org/2000/svg" 
        viewBox="0 0 24 24" 
        fill={config.color}
        style="filter: drop-shadow({config.glow});"
      >
        <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-2 16l-4-4 1.41-1.41L10 14.17l6.59-6.59L18 9l-8 8z"/>
      </svg>
    {:else if config.icon === 'diamond'}
      <svg 
        xmlns="http://www.w3.org/2000/svg" 
        viewBox="0 0 24 24" 
        fill={config.color}
        style="filter: drop-shadow({config.glow});"
      >
        <path d="M19 3H5L2 9l10 12L22 9l-3-6zM12 17.17L5.83 9h12.34L12 17.17z"/>
      </svg>
    {/if}
  </span>
{/if}