<script lang="ts">
  // Shown exactly once per device, only when BOTH are true: this device
  // has no local E2EE keypair yet, AND the account has a recovery backup
  // set up on the server. Forces an explicit, unskippable-by-accident
  // choice between restoring the old key (old DM history stays readable)
  // and generating a fresh one (old history is permanently lost, same as
  // the no-backup default behavior) -- see `lib/recovery.ts`.
  //
  // Deliberately has no backdrop-click-to-dismiss and no Escape handler:
  // unlike AccountSettings, this is a real fork in what the user gets, not
  // a dismissable settings panel, so it always resolves via one of the
  // two explicit buttons below.
  import {
    restoreFromBackup,
    resolveRecoveryChoice,
    retryRecoveryCheck,
    recoveryCheckFailed,
    IncorrectPassphraseError,
  } from '../lib/recovery';
  import { ensureDeviceKeypair } from '../lib/crypto';

  let mode: 'choice' | 'recovering' = 'choice';
  let passphrase = '';
  let busy = false;
  let error = '';

  function startRecovering() {
    mode = 'recovering';
    error = '';
  }

  async function confirmRecover() {
    if (!passphrase) return;
    busy = true;
    error = '';
    try {
      const keypair = await restoreFromBackup(passphrase);
      passphrase = '';
      // Reports the user's choice back to `deviceEncryptionReady()`'s
      // shared promise, resolving it (and hiding this modal) for every
      // caller that's been waiting on it -- see `lib/recovery.ts`.
      resolveRecoveryChoice(keypair);
    } catch (err: any) {
      error = err instanceof IncorrectPassphraseError
        ? err.message
        : (err.message || 'Recovery failed');
    } finally {
      busy = false;
    }
  }

  async function startFresh() {
    busy = true;
    error = '';
    try {
      const keypair = await ensureDeviceKeypair();
      resolveRecoveryChoice(keypair);
    } catch (err: any) {
      error = err.message || 'Failed to set up encryption keys';
    } finally {
      busy = false;
    }
  }

  const input = 'w-full bg-[#0a0e0a] border border-[#00ff00] px-3 py-2 text-[#00ff00] text-sm focus:outline-none focus:shadow-[0_0_10px_rgba(0,255,0,0.3)]';
  const primaryButton = 'w-full py-2 bg-[#00ff00] text-black font-bold uppercase tracking-wider hover:bg-[#00aa00] transition-all disabled:opacity-50';
  const secondaryButton = 'w-full py-2 bg-black border-2 border-[#00ff00] text-[#00ff00] font-semibold uppercase tracking-wider text-sm hover:bg-[#00ff00] hover:text-black transition-all disabled:opacity-50';
</script>

<div class="fixed inset-0 z-[300] flex items-center justify-center bg-black/90 backdrop-blur-sm" role="dialog" aria-modal="true" aria-labelledby="recovery-title">
  <div class="relative w-[460px] max-w-[92vw] bg-black border-2 border-[#00ff00] shadow-[0_0_30px_rgba(0,255,0,0.4)] p-6 space-y-4">
    <h3 id="recovery-title" class="font-bold uppercase tracking-widest text-sm text-[#00ff00]">{'>'} Encrypted messaging on this device</h3>

    {#if $recoveryCheckFailed}
      <p class="text-xs text-[#00aa00]">
        We couldn't check whether this account has a recovery backup set up, so we can't safely decide for you
        whether to restore an old key or start fresh. (This is usually a slow or dropped connection, not necessarily
        a sign that anything is actually broken.)
      </p>
      <div class="text-xs text-red-500">{'>'} {$recoveryCheckFailed}</div>
      <button type="button" class={primaryButton} on:click={retryRecoveryCheck} disabled={busy}>
        Try again
      </button>
      <button type="button" class={secondaryButton} on:click={startFresh} disabled={busy}>
        {busy ? 'Setting up...' : 'Start fresh with a new key instead'}
      </button>
      {#if error}<div class="text-xs text-red-500">{'>'} {error}</div>{/if}
    {:else if mode === 'choice'}
      <p class="text-xs text-[#00aa00]">
        This account has a recovery backup set up. You can restore your old encryption key with your recovery
        passphrase (so your old encrypted direct messages stay readable), or start fresh with a brand new key
        (your old encrypted direct messages will never be readable again, on any device).
      </p>
      <button type="button" class={primaryButton} on:click={startRecovering} disabled={busy}>
        I have my recovery passphrase
      </button>
      <button type="button" class={secondaryButton} on:click={startFresh} disabled={busy}>
        {busy ? 'Setting up...' : "I don't have it -- start fresh"}
      </button>
      {#if error}<div class="text-xs text-red-500">{'>'} {error}</div>{/if}
    {:else}
      <p class="text-xs text-[#00aa00]">
        Enter the recovery passphrase you set up earlier. It's never sent anywhere -- it's only used on this device
        to unlock your backed-up key.
      </p>
      <div>
        <label for="recovery-passphrase" class="block text-xs text-[#00aa00] uppercase tracking-wider mb-1">Recovery passphrase</label>
        <input
          id="recovery-passphrase"
          type="password"
          bind:value={passphrase}
          class={input}
          autocomplete="off"
          on:keydown={(e) => e.key === 'Enter' && confirmRecover()}
        />
      </div>
      {#if error}<div class="text-xs text-red-500">{'>'} {error}</div>{/if}
      <button type="button" class={primaryButton} on:click={confirmRecover} disabled={busy || !passphrase}>
        {busy ? 'Recovering...' : 'Recover my key'}
      </button>
      <button type="button" class="text-xs text-[#00aa00] underline" on:click={() => (mode = 'choice')} disabled={busy}>
        Back
      </button>
    {/if}
  </div>
</div>
