<script lang="ts">
  // Global call UI: ringing (incoming/outgoing) and in-call views. Mounted
  // once in App.svelte so a call survives navigating away from the DM that
  // started it -- state lives entirely in `lib/calls.ts`, this component
  // just renders it. Renders nothing while idle.
  import {
    callState,
    localStream,
    remoteStream,
    micMuted,
    cameraOff,
    acceptCall,
    rejectOrHangUp,
    toggleMic,
    toggleCamera,
  } from '../lib/calls';

  let localVideoEl: HTMLVideoElement;
  let remoteVideoEl: HTMLVideoElement;

  $: if (localVideoEl) localVideoEl.srcObject = $localStream;
  $: if (remoteVideoEl) remoteVideoEl.srcObject = $remoteStream;

  const circleButton =
    'w-12 h-12 rounded-full flex items-center justify-center border-2 transition-all text-lg';
</script>

{#if $callState.status !== 'idle'}
  <div
    class="fixed inset-0 z-[400] flex items-center justify-center bg-black/90 backdrop-blur-sm"
    role="dialog"
    aria-modal="true"
    aria-label="Call"
  >
    <div class="relative w-[480px] max-w-[92vw] bg-black border-2 border-[#00ff00] shadow-[0_0_30px_rgba(0,255,0,0.4)] p-6 space-y-5">
      <div class="text-center">
        <div class="text-[#00aa00] text-xs uppercase tracking-widest terminal-glow">
          {#if $callState.status === 'outgoing'}Calling...
          {:else if $callState.status === 'incoming'}Incoming call
          {:else if $callState.status === 'connecting'}Connecting...
          {:else if $callState.status === 'connected'}Connected
          {:else}{$callState.endReason ?? 'Call ended'}
          {/if}
        </div>
        <div class="text-[#00ff00] text-2xl font-bold mt-1 terminal-glow">
          {$callState.peerUsername ?? ''}
        </div>
      </div>

      {#if $callState.status === 'connecting' || $callState.status === 'connected'}
        <div class="relative bg-[#0a0e0a] border border-[#00aa00]/50 aspect-video overflow-hidden">
          {#if $remoteStream}
            <!-- svelte-ignore a11y-media-has-caption -->
            <video bind:this={remoteVideoEl} autoplay playsinline class="w-full h-full object-cover" />
          {:else}
            <div class="w-full h-full flex items-center justify-center text-[#006600] text-sm">
              Waiting for video...
            </div>
          {/if}
          {#if $callState.withVideo}
            <!-- svelte-ignore a11y-media-has-caption -->
            <video
              bind:this={localVideoEl}
              autoplay
              playsinline
              muted
              class="absolute bottom-2 right-2 w-28 h-20 object-cover border border-[#00ff00] bg-black {$cameraOff ? 'opacity-30' : ''}"
            />
          {/if}
        </div>
      {/if}

      <div class="flex items-center justify-center gap-4">
        {#if $callState.status === 'incoming'}
          <button
            type="button"
            class="{circleButton} bg-red-900/40 border-red-500 text-red-400 hover:bg-red-900/70"
            on:click={rejectOrHangUp}
            title="Decline"
          >
            ✕
          </button>
          <button
            type="button"
            class="{circleButton} bg-[#00ff00]/10 border-[#00ff00] text-[#00ff00] hover:bg-[#00ff00] hover:text-black"
            on:click={acceptCall}
            title="Accept"
          >
            ✓
          </button>
        {:else if $callState.status === 'outgoing' || $callState.status === 'connecting' || $callState.status === 'connected'}
          <button
            type="button"
            class="{circleButton} {$micMuted ? 'bg-[#00ff00]/20 border-[#00ff00] text-[#00ff00]' : 'bg-black border-[#00aa00]/50 text-[#00aa00]'}"
            on:click={toggleMic}
            title={$micMuted ? 'Unmute mic' : 'Mute mic'}
          >
            {$micMuted ? '🔇' : '🎤'}
          </button>
          {#if $callState.withVideo}
            <button
              type="button"
              class="{circleButton} {$cameraOff ? 'bg-[#00ff00]/20 border-[#00ff00] text-[#00ff00]' : 'bg-black border-[#00aa00]/50 text-[#00aa00]'}"
              on:click={toggleCamera}
              title={$cameraOff ? 'Turn camera on' : 'Turn camera off'}
            >
              {$cameraOff ? '📷' : '🎥'}
            </button>
          {/if}
          <button
            type="button"
            class="{circleButton} bg-red-900/40 border-red-500 text-red-400 hover:bg-red-900/70"
            on:click={rejectOrHangUp}
            title="Hang up"
          >
            ✕
          </button>
        {/if}
      </div>
    </div>
  </div>
{/if}
