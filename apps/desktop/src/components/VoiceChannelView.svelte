<script lang="ts">
  // Shown in the main pane when the selected channel is a voice channel.
  // Unlike ChatArea, there's no message history here -- just who's in the
  // channel and the join/leave/mute controls. The actual WebRTC mesh and
  // its signaling live in `lib/voiceChannel.ts`; this component only
  // renders that state and dispatches its actions.
  import { onDestroy } from 'svelte';
  import {
    voiceChannelState,
    voiceParticipants,
    voiceRosters,
    myVoiceMuted,
    myVoiceDeafened,
    joinVoiceChannel,
    leaveVoiceChannel,
    toggleVoiceMic,
    toggleVoiceDeafen,
  } from '../lib/voiceChannel';
  import Avatar from './Avatar.svelte';

  export let channelId: string;
  export let channelName: string;
  export let serverId: string;

  // True once I'm connected to *this specific* channel -- being connected
  // to a different one (shown via the "already in #other-channel" notice
  // below) doesn't count.
  $: isThisChannel = $voiceChannelState.channelId === channelId;
  $: isConnected = isThisChannel && $voiceChannelState.status === 'connected';
  $: isConnecting = isThisChannel && $voiceChannelState.status === 'connecting';
  $: connectedElsewhere = !isThisChannel && $voiceChannelState.status !== 'idle';

  // The roster shown here: live P2P participant state while connected
  // (includes speaking indicators), otherwise the last roster the server
  // reported for this channel (so you can see who's in it before joining).
  $: preview = $voiceRosters.get(channelId) ?? [];
  $: participants = isConnected ? [...$voiceParticipants.values()] : preview;

  function handleJoin() {
    joinVoiceChannel(channelId, channelName, serverId);
  }

  // Leaving when the component is torn down (e.g. the user switches to a
  // different channel or server) keeps "connected" from quietly lingering
  // after the view that showed it is gone. Switching to a *different*
  // voice channel can skip straight there -- `joinVoiceChannel` itself
  // leaves whatever channel was previously joined first.
  onDestroy(() => {
    if (isThisChannel) leaveVoiceChannel();
  });
</script>

<div class="flex-1 flex flex-col items-center justify-center text-[#00aa00] p-6">
  <div class="text-4xl mb-2 terminal-glow">🔊</div>
  <div class="text-xl font-bold terminal-glow mb-1">{channelName}</div>

  {#if $voiceChannelState.error && isThisChannel}
    <div class="text-red-400 text-sm mb-4">{'>'} {$voiceChannelState.error}</div>
  {/if}

  {#if connectedElsewhere}
    <div class="text-[#00aa00] text-sm mb-4">
      {'>'} Connected to #{$voiceChannelState.channelName}. Joining here will disconnect you from it.
    </div>
  {/if}

  <!-- Roster -->
  <div class="w-full max-w-md border-2 border-[#00aa00]/50 bg-[#0a0e0a] p-4 mb-5 min-h-[120px]">
    {#if participants.length === 0}
      <div class="text-[#006600] text-sm text-center py-4">
        {'>'} Nobody's here yet
      </div>
    {:else}
      <div class="grid grid-cols-3 gap-3">
        {#each participants as p (p.userId)}
          <div class="flex flex-col items-center gap-1">
            <div class="relative">
              <Avatar
                label={p.username}
                rounded
                className="w-12 h-12 border-2 {p.speaking ? 'border-[#00ff00] shadow-[0_0_12px_#00ff00]' : 'border-[#00aa00]/50'} font-bold text-sm terminal-glow"
              />
              {#if p.muted}
                <div class="absolute -bottom-1 -right-1 w-4 h-4 bg-black border border-red-500 rounded-full flex items-center justify-center text-[9px]">
                  🔇
                </div>
              {/if}
            </div>
            <div class="text-xs truncate max-w-full {p.speaking ? 'text-[#00ff00] font-bold' : 'text-[#00aa00]'}">
              {p.username}
            </div>
          </div>
        {/each}
      </div>
    {/if}
  </div>

  <!-- Controls -->
  {#if isConnected}
    <div class="flex items-center gap-3">
      <button
        type="button"
        class="w-12 h-12 rounded-full flex items-center justify-center border-2 text-lg transition-all {$myVoiceMuted ? 'bg-[#00ff00]/20 border-[#00ff00] text-[#00ff00]' : 'bg-black border-[#00aa00]/50 text-[#00aa00]'}"
        on:click={toggleVoiceMic}
        title={$myVoiceMuted ? 'Unmute mic' : 'Mute mic'}
      >
        {$myVoiceMuted ? '🔇' : '🎤'}
      </button>
      <button
        type="button"
        class="w-12 h-12 rounded-full flex items-center justify-center border-2 text-lg transition-all {$myVoiceDeafened ? 'bg-[#00ff00]/20 border-[#00ff00] text-[#00ff00]' : 'bg-black border-[#00aa00]/50 text-[#00aa00]'}"
        on:click={toggleVoiceDeafen}
        title={$myVoiceDeafened ? 'Undeafen' : 'Deafen'}
      >
        {$myVoiceDeafened ? '🔕' : '🔔'}
      </button>
      <button
        type="button"
        class="w-12 h-12 rounded-full flex items-center justify-center border-2 border-red-500 bg-red-900/40 text-red-400 hover:bg-red-900/70 text-lg transition-all"
        on:click={leaveVoiceChannel}
        title="Disconnect"
      >
        ✕
      </button>
    </div>
  {:else}
    <button
      type="button"
      class="px-6 py-2 border-2 border-[#00ff00] text-[#00ff00] hover:bg-[#00ff00] hover:text-black transition-all terminal-glow font-bold"
      on:click={handleJoin}
      disabled={isConnecting}
    >
      {isConnecting ? 'Connecting…' : 'Join Voice Channel'}
    </button>
  {/if}
</div>
