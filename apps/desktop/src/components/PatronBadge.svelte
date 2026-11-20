<script lang="ts">
  export let tier: string = 'free';
  export let size: 'small' | 'medium' | 'large' = 'small';
  /// This user's chosen emblem id (`badge_emblem` from the API), or null/
  /// undefined if they haven't picked one yet -- falls back to the tier's
  /// default emblem (or, for the site owner, the Fehu rune).
  export let emblem: string | null | undefined = null;
  export let isSiteOwner: boolean = false;

  const sizeClasses = {
    small: 'w-4 h-4',
    medium: 'w-5 h-5',
    large: 'w-6 h-6'
  };

  // id -> display info. Selectable sets mirror the backend's
  // `crate::badges::{PATRON_EMBLEMS,GUILD_EMBLEMS,OWNER_EMBLEM}` --
  // keep these in sync if that list changes.
  const EMBLEMS: Record<string, { color: string; title: string }> = {
    crown: { color: '#ffd700', title: 'Crown' },
    starlight: { color: '#ffdf6b', title: 'Starlight' },
    ember: { color: '#ff7a3d', title: 'Ember' },
    wayfinder: { color: '#c08a4e', title: 'Wayfinder' },
    laurel: { color: '#b08d57', title: 'Laurel' },
    aegis: { color: '#ff6b35', title: 'Aegis' },
    blade: { color: '#c7d0d8', title: 'Blade' },
    warbrand: { color: '#8a8f98', title: 'Warbrand' },
    bastion: { color: '#9b8c7a', title: 'Bastion' },
    anchor: { color: '#3a6ea5', title: 'Anchor' },
    storm: { color: '#4fd1ff', title: 'Storm' },
    reaper: { color: '#cbbfa0', title: 'Reaper' },
    wolf: { color: '#6b7a8f', title: 'Wolf' },
    ruby: { color: '#c0193f', title: 'Ruby' },
    conqueror: { color: '#c0392b', title: 'Conqueror' },
    fehu_rune: { color: '#9b5de5', title: "Owner's sigil" },
    diamond: { color: '#00ffff', title: 'Enterprise' }
  };

  export const PATRON_EMBLEMS = ['crown', 'starlight', 'ember', 'wayfinder', 'laurel'];
  export const GUILD_EMBLEMS = [
    'aegis', 'blade', 'warbrand', 'bastion', 'anchor', 'storm', 'reaper', 'wolf', 'ruby', 'conqueror'
  ];
  export const OWNER_EMBLEM = 'fehu_rune';

  function defaultEmblemFor(t: string, owner: boolean): string | null {
    if (owner) return OWNER_EMBLEM;
    if (t === 'patron') return 'crown';
    if (t === 'guild') return 'aegis';
    if (t === 'enterprise') return 'diamond';
    return null;
  }

  $: id = emblem || defaultEmblemFor(tier, isSiteOwner);
  $: config = id ? EMBLEMS[id] : null;
  $: glow = config ? `0 0 8px ${config.color}` : '';
</script>

{#if config}
  <span class="{sizeClasses[size]} inline-flex items-center justify-center" title={config.title}>
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" style="filter: drop-shadow({glow});">
      {#if id === 'crown'}
        <path fill={config.color} d="M5 16L3 5l5.5 5L12 4l3.5 6L21 5l-2 11H5zm14 3c0 .6-.4 1-1 1H6c-.6 0-1-.4-1-1v-1h14v1z"/>
      {:else if id === 'starlight'}
        <polygon fill={config.color} points="12,2 14.5,9 22,9 16,13.5 18.5,21 12,16.5 5.5,21 8,13.5 2,9 9.5,9"/>
      {:else if id === 'ember'}
        <path fill={config.color} d="M12 2c-1.5 3.5-5 5.5-5 10a5 5 0 0010 0c0-2-1-3.5-2-4.5.5 2-.5 3.5-2 3.5-1.3 0-2.2-1.3-1.6-2.7.6-1.4 1.6-2.3.6-6.3z"/>
      {:else if id === 'wayfinder'}
        <circle cx="12" cy="12" r="8.5" fill="none" stroke={config.color} stroke-width="1.6"/>
        <polygon fill={config.color} points="12,6.5 14.2,12 12,17.5 9.8,12"/>
      {:else if id === 'laurel'}
        <circle cx="12" cy="9" r="5" fill={config.color}/>
        <path fill="none" stroke={config.color} stroke-width="1.4" stroke-linejoin="round" d="M9 13.5L6 21l5-2.3L12 21l2-2.3 5 2.3-3-7.5"/>
      {:else if id === 'aegis'}
        <path fill={config.color} d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-2 16l-4-4 1.41-1.41L10 14.17l6.59-6.59L18 9l-8 8z"/>
      {:else if id === 'blade'}
        <g transform="rotate(45 12 12)">
          <rect x="11" y="1.5" width="2" height="14" fill={config.color}/>
          <rect x="8.5" y="14" width="7" height="2" fill={config.color}/>
          <rect x="10.3" y="16" width="3.4" height="6" rx="1" fill={config.color}/>
        </g>
      {:else if id === 'warbrand'}
        <path fill={config.color} d="M8 3a6 6 0 016 6c0 2-1 3.6-2.6 4.6L8 16l-2.4-2.4L8.6 11A6 6 0 018 3z"/>
        <rect x="10.4" y="10.5" width="2" height="11" rx="1" fill={config.color} transform="rotate(45 11.4 16)"/>
      {:else if id === 'bastion'}
        <path fill={config.color} d="M4 10h2V7h2v3h2V6h2v4h2V7h2v3h2v11H4z"/>
      {:else if id === 'anchor'}
        <path fill={config.color} d="M12 2a2 2 0 110 4 2 2 0 010-4zM11 7h2v3h5a5 5 0 01-4.3 4.95L14 21h-2l.3-6.05A5 5 0 017 10h5V7z"/>
      {:else if id === 'storm'}
        <path fill={config.color} d="M13 2L4 14h6l-1 8 9-12h-6l1-8z"/>
      {:else if id === 'reaper'}
        <circle cx="12" cy="10" r="6" fill={config.color}/>
        <rect x="9" y="14" width="6" height="4" rx="1" fill={config.color}/>
        <circle cx="9.5" cy="9.5" r="1.3" fill="#000"/>
        <circle cx="14.5" cy="9.5" r="1.3" fill="#000"/>
      {:else if id === 'wolf'}
        <ellipse cx="12" cy="15" rx="3.2" ry="2.6" fill={config.color}/>
        <circle cx="7.5" cy="9" r="1.8" fill={config.color}/>
        <circle cx="11" cy="6.5" r="1.8" fill={config.color}/>
        <circle cx="15" cy="6.5" r="1.8" fill={config.color}/>
        <circle cx="18" cy="9.5" r="1.8" fill={config.color}/>
      {:else if id === 'ruby' || id === 'diamond'}
        <path fill={config.color} d="M19 3H5L2 9l10 12L22 9l-3-6zM12 17.17L5.83 9h12.34L12 17.17z"/>
      {:else if id === 'conqueror'}
        <path fill={config.color} d="M7 3h10v2h3v2a5 5 0 01-5 5h-.2A5 5 0 0110.2 12H10A5 5 0 015 7V5h2V3zM9 14h6l1 3H8l1-3zm-2 5h10v2H7v-2z"/>
      {:else if id === 'fehu_rune'}
        <g stroke={config.color} stroke-width="2" stroke-linecap="round" fill="none">
          <line x1="8" y1="4" x2="8" y2="21"/>
          <line x1="8" y1="9" x2="18" y2="4"/>
          <line x1="8" y1="14" x2="18" y2="9"/>
        </g>
      {/if}
    </svg>
  </span>
{/if}
