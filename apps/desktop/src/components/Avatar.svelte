<script lang="ts">
  import { fileUrl } from '../lib/api';

  // Shared avatar: shows the real profile picture when one is set, and
  // falls back to the existing initial-letter box everywhere a user
  // doesn't have one -- which is still almost everyone, since this is a
  // self-service, no-default picture.
  export let url: string | null | undefined = null;
  export let label: string = '?';
  // Tailwind classes controlling size/border/text -- pass the same
  // classes the old hardcoded box used, so swapping it in changes nothing
  // but the content.
  export let className: string = 'w-8 h-8 border-2 border-[#00ff00] font-bold text-sm terminal-glow';
  export let rounded: boolean = false;
</script>

{#if url}
  <img
    src={fileUrl(url)}
    alt={label}
    class="{className} {rounded ? 'rounded-full' : ''} object-cover flex-shrink-0"
  />
{:else}
  <div class="{className} {rounded ? 'rounded-full' : ''} flex items-center justify-center flex-shrink-0">
    {label ? label[0].toUpperCase() : '?'}
  </div>
{/if}
