<script lang="ts">
  import { createEventDispatcher, onMount } from 'svelte';
  import { apiFetch, apiBase } from '../lib/api';
  import { getCurrentUser, updateUserInStorage } from '../lib/auth';
  import { fetchMyDevices, removeDevice, renameDevice, type MyDevice } from '../lib/devices';
  import { clearMessageHistoryCache } from '../lib/message-history';
  import { updateMyAvatar, updateMyBadgeEmblem, allowedEmblems, PATRON_TIERS, type PatronTier } from '../lib/users';
  import { uploadFile } from '../lib/messages';
  import { selfAvatarUrl } from '../lib/selfProfile';
  import Avatar from './Avatar.svelte';
  import PatronBadge from './PatronBadge.svelte';
  import { getMyDeviceId } from '../lib/crypto';
  import { deviceEncryptionReady, replaceActiveKeypair, restoreFromBackup, IncorrectPassphraseError } from '../lib/recovery';
  import { fetchKeyBackup, createOrReplaceKeyBackup, deleteKeyBackup, type KeyBackupRecord } from '../lib/recovery';
  import {
    requestToken,
    redeemToken,
    listPendingTokens,
    storePendingToken,
    removePendingToken,
    BlindTokenError,
    type PendingToken,
  } from '../lib/blind-tokens';

  const dispatch = createEventDispatcher();

  let username = '';
  let email = '';
  let isSiteOwner = false;

  // Profile picture
  let avatarUrl: string | null = null;
  let avatarBusy = false;
  let avatarError = '';
  let avatarFileInput: HTMLInputElement;

  async function handleAvatarFile(e: Event) {
    const file = (e.target as HTMLInputElement).files?.[0];
    if (!file) return;
    avatarError = '';
    avatarBusy = true;
    try {
      const uploaded = await uploadFile(file);
      const updated = await updateMyAvatar(uploaded.url);
      avatarUrl = updated.avatar_url ?? null;
      selfAvatarUrl.set(avatarUrl);
    } catch (err: any) {
      avatarError = err.message || 'Failed to update avatar';
    } finally {
      avatarBusy = false;
      if (avatarFileInput) avatarFileInput.value = '';
    }
  }

  async function clearAvatar() {
    avatarError = '';
    avatarBusy = true;
    try {
      const updated = await updateMyAvatar(null);
      avatarUrl = updated.avatar_url ?? null;
      selfAvatarUrl.set(avatarUrl);
    } catch (err: any) {
      avatarError = err.message || 'Failed to remove avatar';
    } finally {
      avatarBusy = false;
    }
  }

  // Patron tier -- read-only here. There's no billing integration yet, so
  // until there is, the site owner grants tier changes from a user's
  // profile (see UserProfileModal.svelte), not the user themselves.
  let patronTier: PatronTier = 'free';

  // Anonymous patron-tier redemption (blind tokens) -- see lib/blind-tokens.ts.
  // Two unrelated flows live here:
  // - Anyone holding a receipt (handed to them however they paid) can turn
  //   it into a token and redeem it onto this account.
  // - The site owner can mint a receipt for someone who just paid them.
  const BLIND_TOKEN_TIERS = ['patron', 'guild', 'enterprise'] as const;
  let receiptTierToSpend: string = BLIND_TOKEN_TIERS[0];
  let receiptTokenInput = '';
  let blindTokenBusy = false;
  let blindTokenError = '';
  let blindTokenMessage = '';
  let pendingTokens: PendingToken[] = [];

  let mintTier: string = BLIND_TOKEN_TIERS[0];
  let mintBusy = false;
  let mintedReceipt: { tier: string; receipt_token: string } | null = null;
  let mintError = '';

  async function spendReceipt() {
    blindTokenError = '';
    blindTokenMessage = '';
    if (!receiptTokenInput.trim()) {
      blindTokenError = 'Enter a receipt token first';
      return;
    }
    blindTokenBusy = true;
    try {
      const token = await requestToken(receiptTierToSpend, receiptTokenInput.trim());
      storePendingToken(token);
      pendingTokens = listPendingTokens();
      receiptTokenInput = '';
      blindTokenMessage = `Got a ${receiptTierToSpend} token -- redeem it below whenever you like.`;
    } catch (err: any) {
      blindTokenError = err instanceof BlindTokenError ? err.message : 'Failed to request a token';
    } finally {
      blindTokenBusy = false;
    }
  }

  async function redeemPendingToken(token: PendingToken) {
    blindTokenError = '';
    blindTokenMessage = '';
    blindTokenBusy = true;
    try {
      await redeemToken(token);
      removePendingToken(token);
      pendingTokens = listPendingTokens();
      if (PATRON_TIERS.includes(token.tier as PatronTier) && token.tier !== 'free') {
        // Reflect the upgrade immediately rather than waiting on a refetch.
        const rank = (t: string) => PATRON_TIERS.indexOf(t as PatronTier);
        if (rank(token.tier) > rank(patronTier)) patronTier = token.tier as PatronTier;
      }
      blindTokenMessage = `Redeemed -- this account is now ${token.tier}.`;
    } catch (err: any) {
      blindTokenError = err instanceof BlindTokenError ? err.message : 'Failed to redeem that token';
    } finally {
      blindTokenBusy = false;
    }
  }

  async function mintReceipt() {
    mintError = '';
    mintedReceipt = null;
    mintBusy = true;
    try {
      const res = await apiFetch(`${apiBase()}/api/v1/admin/blind-token-receipts`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tier: mintTier }),
      });
      if (!res.ok) throw new Error(await errorFrom(res, 'Failed to mint a receipt'));
      mintedReceipt = await res.json();
    } catch (err: any) {
      mintError = err.message || 'Failed to mint a receipt';
    } finally {
      mintBusy = false;
    }
  }

  // Badge emblem (which icon this tier's badge shows -- see PatronBadge.svelte)
  let badgeEmblem: string | null = null;
  let emblemBusy = false;
  let emblemError = '';
  $: emblemChoices = allowedEmblems(patronTier, isSiteOwner);

  async function selectEmblem(id: string | null) {
    if (id === badgeEmblem || emblemBusy) return;
    emblemError = '';
    emblemBusy = true;
    try {
      const updated = await updateMyBadgeEmblem(id);
      badgeEmblem = updated.badge_emblem ?? null;
    } catch (err: any) {
      emblemError = err.message || 'Failed to update badge emblem';
    } finally {
      emblemBusy = false;
    }
  }

  // Devices (per-device E2EE keys)
  let devices: MyDevice[] = [];
  let devicesError = '';
  let devicesBusy = false;
  let renamingDeviceId: string | null = null;
  let renameLabel = '';
  let thisDeviceId = getMyDeviceId();

  async function loadDevices() {
    devicesError = '';
    try {
      devices = await fetchMyDevices();
    } catch (err: any) {
      devicesError = err.message || 'Failed to load devices';
    }
  }

  function startRename(device: MyDevice) {
    renamingDeviceId = device.id;
    renameLabel = device.device_label;
  }

  async function confirmRename() {
    if (!renamingDeviceId) return;
    devicesBusy = true;
    try {
      const updated = await renameDevice(renamingDeviceId, renameLabel.trim() || 'Unnamed device');
      devices = devices.map(d => (d.id === updated.id ? updated : d));
      renamingDeviceId = null;
    } catch (err: any) {
      devicesError = err.message || 'Failed to rename device';
    } finally {
      devicesBusy = false;
    }
  }

  async function handleRemoveDevice(device: MyDevice) {
    const isThisDevice = device.id === thisDeviceId;
    const warning = isThisDevice
      ? 'This is the device you are using right now. Removing it means THIS device will no longer be able to read any new encrypted messages until you set it up again. Continue?'
      : `Remove "${device.device_label}"? Any messages already sent to it will become permanently unreadable on it.`;
    if (!confirm(warning)) return;

    devicesBusy = true;
    try {
      await removeDevice(device.id);
      devices = devices.filter(d => d.id !== device.id);
    } catch (err: any) {
      devicesError = err.message || 'Failed to remove device';
    } finally {
      devicesBusy = false;
    }
  }

  // Local, per-device message history cache (see `message-history.ts`).
  let historyClearBusy = false;
  let historyClearError = '';
  let historyCleared = false;

  async function handleClearMessageHistory() {
    if (
      !confirm(
        'Clear cached message history on THIS device? Messages whose live encryption keys are already gone ' +
          "won't be readable again until they're sent again. This does not delete anything from the server or " +
          'from your other devices.'
      )
    ) {
      return;
    }
    historyClearBusy = true;
    historyClearError = '';
    historyCleared = false;
    try {
      await clearMessageHistoryCache();
      historyCleared = true;
    } catch (err: any) {
      historyClearError = err.message || 'Failed to clear the local message history cache';
    } finally {
      historyClearBusy = false;
    }
  }

  // Account recovery (passphrase-encrypted backup of this device's key)
  let keyBackup: KeyBackupRecord | null = null;
  let recoveryLoading = true;
  let recoveryError = '';
  let recoveryMessage = '';
  let recoveryBusy = false;
  // Shows the set-up/change-passphrase form; false just shows the current
  // status + action buttons.
  let showRecoveryForm = false;
  let recoveryPassphrase = '';
  let recoveryPassphraseConfirm = '';

  async function loadKeyBackup() {
    recoveryError = '';
    recoveryLoading = true;
    try {
      keyBackup = await fetchKeyBackup();
    } catch (err: any) {
      recoveryError = err.message || 'Failed to check recovery backup status';
    } finally {
      recoveryLoading = false;
    }
  }

  function openRecoveryForm() {
    recoveryError = '';
    recoveryMessage = '';
    recoveryPassphrase = '';
    recoveryPassphraseConfirm = '';
    showRecoveryForm = true;
  }

  async function confirmRecoverySetup() {
    recoveryError = '';
    recoveryMessage = '';
    if (recoveryPassphrase.length < 8) {
      recoveryError = 'Choose a passphrase of at least 8 characters.';
      return;
    }
    if (recoveryPassphrase !== recoveryPassphraseConfirm) {
      recoveryError = "The passphrases don't match.";
      return;
    }
    if (!confirm(
      "If you forget this passphrase, there is NO way to recover it or the backup it protects -- " +
      "not even Svalinn's server operators can help. Continue?"
    )) {
      return;
    }

    recoveryBusy = true;
    try {
      // Guarantees this device has a keypair before backing it up -- goes
      // through the same shared gate as `App.svelte`/`DMChatArea.svelte`
      // (see `lib/recovery.ts`) rather than `ensureDeviceKeypair()`
      // directly, so opening Account Settings can't race ahead of an
      // in-flight recovery-backup check either. A no-op if a keypair
      // already exists.
      const kp = await deviceEncryptionReady();
      await createOrReplaceKeyBackup(recoveryPassphrase, kp.publicKey, kp.privateKey, kp.deviceId);
      recoveryPassphrase = '';
      recoveryPassphraseConfirm = '';
      showRecoveryForm = false;
      recoveryMessage = 'Recovery backup saved.';
      await loadKeyBackup();
    } catch (err: any) {
      recoveryError = err.message || 'Failed to save recovery backup';
    } finally {
      recoveryBusy = false;
    }
  }

  async function handleRemoveBackup() {
    if (!confirm('Remove your recovery backup? If you lose every device after this, old encrypted messages will never be recoverable.')) return;
    recoveryBusy = true;
    recoveryError = '';
    recoveryMessage = '';
    try {
      await deleteKeyBackup();
      keyBackup = null;
      recoveryMessage = 'Recovery backup removed.';
    } catch (err: any) {
      recoveryError = err.message || 'Failed to remove recovery backup';
    } finally {
      recoveryBusy = false;
    }
  }

  // Manual "recover from backup" escape hatch. Unlike `RecoveryChoice.svelte`
  // (which only ever appears once, before THIS device has any local key at
  // all -- see `needsRecoveryChoice()` in `lib/recovery.ts`, which
  // short-circuits to false forever once a local keypair exists, even a
  // throwaway one generated by the retry-then-fallback path after a
  // transient network error), this button stays available any time the
  // account has a server-side backup, REGARDLESS of whether this device
  // already has its own local key -- it's the only way back to the real
  // backed-up key if that short-circuit already fired on this device.
  let showRecoverForm = false;
  let recoverPassphrase = '';
  let recoverBusy = false;
  let recoverError = '';
  let recoverMessage = '';

  function openRecoverForm() {
    recoverError = '';
    recoverMessage = '';
    recoverPassphrase = '';
    showRecoverForm = true;
  }

  async function confirmRecoverFromBackup() {
    recoverError = '';
    if (!recoverPassphrase) return;
    // Same stakes as `RecoveryChoice.svelte`'s choice screen, but phrased
    // for the fact that THIS device may already have its own key in active
    // use -- that current key is about to be replaced, not merely created.
    if (!confirm(
      "This will REPLACE this device's current encryption key with the one recovered from your backup. " +
      "Going forward, this device will send and receive encrypted messages under the recovered key instead -- " +
      "this device's current key (and anything that still relies on it) is left behind. Continue?"
    )) {
      return;
    }

    recoverBusy = true;
    try {
      const keypair = await restoreFromBackup(recoverPassphrase);
      // `restoreFromBackup()` only updates `localStorage` and `crypto.ts`'s
      // own keypair cache -- it has no idea that `deviceEncryptionReady()`'s
      // shared gate (in `lib/recovery.ts`) already handed the OLD keypair
      // out to things like an open `DMChatArea.svelte`. Without this call,
      // this device would keep silently encrypting/sending under the
      // stale, abandoned key for the rest of the session even though this
      // panel and `localStorage` both correctly show the recovered
      // identity. This makes every current and future
      // `deviceEncryptionReady()` consumer pick up the recovered key
      // immediately, with no reload required.
      replaceActiveKeypair(keypair);
      recoverPassphrase = '';
      showRecoverForm = false;
      recoverMessage = 'Key recovered from backup -- this device now uses the recovered key.';
      thisDeviceId = keypair.deviceId;
      await loadDevices();
    } catch (err: any) {
      recoverError = err instanceof IncorrectPassphraseError ? err.message : (err.message || 'Failed to recover from backup');
    } finally {
      recoverBusy = false;
    }
  }

  // Change email
  let newEmail = '';
  let emailPassword = '';
  let emailMessage = '';
  let emailError = '';
  let emailBusy = false;

  // Change password
  let currentPassword = '';
  let newPassword = '';
  let confirmPassword = '';
  let passwordMessage = '';
  let passwordError = '';
  let passwordBusy = false;

  onMount(async () => {
    const res = await apiFetch(`${apiBase()}/api/v1/users/me/account`);
    if (res.ok) {
      const account = await res.json();
      username = account.username;
      email = account.email;
      isSiteOwner = account.is_site_owner;
    }
    // /me/account doesn't carry patron_tier -- /me (get_current_user) does.
    const meRes = await apiFetch(`${apiBase()}/api/v1/users/me`);
    if (meRes.ok) {
      const me = await meRes.json();
      if (PATRON_TIERS.includes(me.patron_tier)) patronTier = me.patron_tier;
      avatarUrl = me.avatar_url ?? null;
      badgeEmblem = me.badge_emblem ?? null;
    }
    await loadDevices();
    await loadKeyBackup();
    pendingTokens = listPendingTokens();
  });

  async function errorFrom(res: Response, fallback: string): Promise<string> {
    const err = await res.json().catch(() => ({}));
    return err.error || fallback;
  }

  async function changeEmail(e: Event) {
    e.preventDefault();
    emailMessage = emailError = '';
    emailBusy = true;
    try {
      const res = await apiFetch(`${apiBase()}/api/v1/users/me/email`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: newEmail, current_password: emailPassword }),
      });
      if (res.ok) {
        email = (await res.json()).email;
        const user = getCurrentUser();
        if (user) updateUserInStorage({ ...user, email });
        newEmail = emailPassword = '';
        emailMessage = 'Email updated. Use it the next time you log in.';
      } else {
        emailError = await errorFrom(res, 'Could not change email');
      }
    } catch (err: any) {
      emailError = err.message || 'Network error';
    } finally {
      emailBusy = false;
    }
  }

  async function changePassword(e: Event) {
    e.preventDefault();
    passwordMessage = passwordError = '';
    if (newPassword !== confirmPassword) {
      passwordError = "The new passwords don't match";
      return;
    }
    passwordBusy = true;
    try {
      const res = await apiFetch(`${apiBase()}/api/v1/users/me/password`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
      });
      if (res.ok) {
        const { other_sessions_ended } = await res.json();
        currentPassword = newPassword = confirmPassword = '';
        passwordMessage = other_sessions_ended > 0
          ? `Password changed. You were logged out on ${other_sessions_ended} other device${other_sessions_ended === 1 ? '' : 's'}.`
          : 'Password changed.';
      } else {
        passwordError = await errorFrom(res, 'Could not change password');
      }
    } catch (err: any) {
      passwordError = err.message || 'Network error';
    } finally {
      passwordBusy = false;
    }
  }

  const input = 'w-full bg-[#0a0e0a] border border-[#00ff00] px-3 py-2 text-[#00ff00] text-sm focus:outline-none focus:shadow-[0_0_10px_rgba(0,255,0,0.3)]';
  const label = 'block text-xs text-[#00aa00] uppercase tracking-wider mb-1';
  const submit = 'w-full py-2 bg-black border-2 border-[#00ff00] text-[#00ff00] font-semibold uppercase tracking-wider text-sm hover:bg-[#00ff00] hover:text-black transition-all disabled:opacity-50';
</script>

<svelte:window on:keydown={(e) => e.key === 'Escape' && dispatch('close')} />

<div class="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm" role="dialog" aria-modal="true" aria-labelledby="account-title">
  <div class="relative w-[520px] max-w-[92vw] max-h-[88vh] overflow-y-auto bg-black border-2 border-[#00ff00] shadow-[0_0_30px_rgba(0,255,0,0.4)]">
    <div class="p-4 border-b border-[#00ff00] flex items-center justify-between">
      <h3 id="account-title" class="font-bold uppercase tracking-widest text-sm text-[#00ff00]">{'>'} Account Settings</h3>
      <button class="text-[#00ff00] hover:text-red-500" on:click={() => dispatch('close')} aria-label="Close account settings">✕</button>
    </div>

    <div class="p-6 space-y-8">
      <section class="flex items-center gap-4">
        <Avatar
          url={avatarUrl}
          label={username}
          className="w-16 h-16 border-2 border-[#00ff00] font-bold text-2xl terminal-glow bg-[#0a0e0a]"
        />
        <div class="flex-1 min-w-0">
          <div class="text-lg font-bold text-[#00ff00]">{username}</div>
          <div class="text-xs text-[#00aa00]">{email}</div>
          {#if isSiteOwner}
            <div class="inline-block mt-2 px-2 py-0.5 text-[10px] uppercase tracking-widest border border-[#ffaa00] text-[#ffaa00]">Site owner</div>
          {/if}
        </div>
      </section>

      <section class="space-y-2">
        <h4 class="text-sm font-bold text-[#00ff00] uppercase tracking-wider">Profile picture</h4>
        <input
          bind:this={avatarFileInput}
          type="file"
          accept="image/*"
          class="hidden"
          on:change={handleAvatarFile}
        />
        <div class="flex gap-2">
          <button
            type="button"
            class="text-xs text-[#00ff00] underline disabled:opacity-50"
            disabled={avatarBusy}
            on:click={() => avatarFileInput?.click()}
          >
            {avatarBusy ? 'Uploading...' : avatarUrl ? 'Change picture' : 'Upload a picture'}
          </button>
          {#if avatarUrl}
            <button type="button" class="text-xs text-red-500 underline disabled:opacity-50" disabled={avatarBusy} on:click={clearAvatar}>
              Remove
            </button>
          {/if}
        </div>
        {#if avatarError}<div class="text-xs text-red-500">{'>'} {avatarError}</div>{/if}
      </section>

      <section class="space-y-3">
        <h4 class="text-sm font-bold text-[#00ff00] uppercase tracking-wider">Patron tier</h4>
        <p class="text-[11px] text-[#00aa00]">
          Svalinn doesn't have billing set up yet, so tier changes aren't self-service -- the site owner
          grants them. Guild tier and above is required to create a server.
        </p>
        <div class="flex items-center gap-2 py-2 px-3 border border-[#00aa00]/50">
          {#if patronTier !== 'free'}<PatronBadge tier={patronTier} size="small" />{/if}
          <span class="text-xs uppercase tracking-wider text-[#00ff00]">{patronTier}</span>
        </div>
      </section>

      <section class="space-y-3">
        <h4 class="text-sm font-bold text-[#00ff00] uppercase tracking-wider">Redeem a patron token</h4>
        <p class="text-[11px] text-[#00aa00]">
          Have a one-time receipt from however you paid? Spend it here for a token, then redeem the token on
          whichever account you want upgraded -- the server has no way to connect the two.
        </p>
        <div class="flex gap-2">
          <select bind:value={receiptTierToSpend} class="{input} flex-none w-32">
            {#each BLIND_TOKEN_TIERS as t}<option value={t}>{t}</option>{/each}
          </select>
          <input
            type="text"
            placeholder="Receipt token"
            bind:value={receiptTokenInput}
            class="{input} flex-1"
            disabled={blindTokenBusy}
          />
          <button type="button" class="text-xs text-[#00ff00] underline disabled:opacity-50 whitespace-nowrap" disabled={blindTokenBusy} on:click={spendReceipt}>
            {blindTokenBusy ? 'Working...' : 'Get token'}
          </button>
        </div>

        {#if pendingTokens.length > 0}
          <div class="space-y-1">
            {#each pendingTokens as token (token.preparedMessage)}
              <div class="flex items-center justify-between gap-2 py-1.5 px-2 border border-[#00aa00]/50 text-xs">
                <span class="uppercase tracking-wider text-[#00ff00]">{token.tier} token</span>
                <button type="button" class="text-[#00ff00] underline disabled:opacity-50" disabled={blindTokenBusy} on:click={() => redeemPendingToken(token)}>
                  Redeem on this account
                </button>
              </div>
            {/each}
          </div>
        {/if}

        {#if blindTokenError}<div class="text-xs text-red-500">{'>'} {blindTokenError}</div>{/if}
        {#if blindTokenMessage}<div class="text-xs text-[#00ff00]">{'>'} {blindTokenMessage}</div>{/if}
      </section>

      {#if isSiteOwner}
        <section class="space-y-3">
          <h4 class="text-sm font-bold text-[#00ff00] uppercase tracking-wider">Mint a blind-token receipt</h4>
          <p class="text-[11px] text-[#00aa00]">
            After confirming a payment through whatever channel (cash, a voucher, anything), mint a one-time
            receipt here and hand it to whoever paid. It authorizes exactly one token for the chosen tier.
          </p>
          <div class="flex gap-2">
            <select bind:value={mintTier} class="{input} flex-none w-32">
              {#each BLIND_TOKEN_TIERS as t}<option value={t}>{t}</option>{/each}
            </select>
            <button type="button" class="text-xs text-[#00ff00] underline disabled:opacity-50" disabled={mintBusy} on:click={mintReceipt}>
              {mintBusy ? 'Minting...' : 'Mint receipt'}
            </button>
          </div>
          {#if mintedReceipt}
            <div class="py-2 px-3 border border-[#00ff00]/50 text-xs break-all">
              <span class="text-[#00aa00] uppercase tracking-wider">{mintedReceipt.tier} receipt:</span>
              {mintedReceipt.receipt_token}
            </div>
          {/if}
          {#if mintError}<div class="text-xs text-red-500">{'>'} {mintError}</div>{/if}
        </section>
      {/if}

      {#if emblemChoices.length > 0}
        <section class="space-y-3">
          <h4 class="text-sm font-bold text-[#00ff00] uppercase tracking-wider">Badge emblem</h4>
          <p class="text-[11px] text-[#00aa00]">
            {isSiteOwner
              ? 'As site owner you can use any emblem, including the owner-exclusive rune.'
              : `Pick which emblem your ${patronTier} badge shows.`}
          </p>
          <div class="grid grid-cols-4 gap-2">
            <button
              type="button"
              disabled={emblemBusy}
              class="flex flex-col items-center justify-center gap-1 py-2 border text-[10px] uppercase tracking-wider transition-colors disabled:opacity-50 {badgeEmblem === null ? 'border-[#00ff00] bg-[#00ff00]/10 text-[#00ff00]' : 'border-[#00aa00]/50 text-[#00aa00] hover:border-[#00ff00]'}"
              on:click={() => selectEmblem(null)}
            >
              <span class="text-[9px]">Default</span>
            </button>
            {#each emblemChoices as id}
              <button
                type="button"
                disabled={emblemBusy}
                class="flex flex-col items-center justify-center gap-1 py-2 border text-[10px] uppercase tracking-wider transition-colors disabled:opacity-50 {badgeEmblem === id ? 'border-[#00ff00] bg-[#00ff00]/10 text-[#00ff00]' : 'border-[#00aa00]/50 text-[#00aa00] hover:border-[#00ff00]'}"
                on:click={() => selectEmblem(id)}
              >
                <PatronBadge tier={patronTier} emblem={id} isSiteOwner={false} size="medium" />
              </button>
            {/each}
          </div>
          {#if emblemError}<div class="text-xs text-red-500">{'>'} {emblemError}</div>{/if}
        </section>
      {/if}

      <form on:submit={changeEmail} class="space-y-3">
        <h4 class="text-sm font-bold text-[#00ff00] uppercase tracking-wider">Change email</h4>
        <div>
          <label for="account-new-email" class={label}>New email</label>
          <input id="account-new-email" type="email" bind:value={newEmail} class={input} required autocomplete="email" />
        </div>
        <div>
          <label for="account-email-password" class={label}>Current password</label>
          <input id="account-email-password" type="password" bind:value={emailPassword} class={input} required autocomplete="current-password" />
        </div>
        {#if emailError}<div class="text-xs text-red-500">{'>'} {emailError}</div>{/if}
        {#if emailMessage}<div class="text-xs text-[#00ff00]">{'>'} {emailMessage}</div>{/if}
        <button type="submit" class={submit} disabled={emailBusy}>{emailBusy ? 'Saving...' : 'Change email'}</button>
      </form>

      <form on:submit={changePassword} class="space-y-3">
        <h4 class="text-sm font-bold text-[#00ff00] uppercase tracking-wider">Change password</h4>
        <div>
          <label for="account-current-password" class={label}>Current password</label>
          <input id="account-current-password" type="password" bind:value={currentPassword} class={input} required autocomplete="current-password" />
        </div>
        <div>
          <label for="account-new-password" class={label}>New password</label>
          <input id="account-new-password" type="password" bind:value={newPassword} class={input} required minlength="6" autocomplete="new-password" />
        </div>
        <div>
          <label for="account-confirm-password" class={label}>Confirm new password</label>
          <input id="account-confirm-password" type="password" bind:value={confirmPassword} class={input} required minlength="6" autocomplete="new-password" />
        </div>
        <p class="text-[11px] text-[#00aa00]">Changing your password logs you out on every other device.</p>
        {#if passwordError}<div class="text-xs text-red-500">{'>'} {passwordError}</div>{/if}
        {#if passwordMessage}<div class="text-xs text-[#00ff00]">{'>'} {passwordMessage}</div>{/if}
        <button type="submit" class={submit} disabled={passwordBusy}>{passwordBusy ? 'Saving...' : 'Change password'}</button>
      </form>

      <section class="space-y-3">
        <h4 class="text-sm font-bold text-[#00ff00] uppercase tracking-wider">Encrypted messaging devices</h4>
        <p class="text-[11px] text-[#00aa00]">
          Each device you've used for encrypted messages keeps its own key -- a private key never leaves the device
          it was created on. Removing a device means messages already sent to it can never be read on it again.
        </p>
        {#if devicesError}<div class="text-xs text-red-500">{'>'} {devicesError}</div>{/if}
        {#if devices.length === 0}
          <div class="text-xs text-[#00aa00]">{'>'} No devices registered yet.</div>
        {:else}
          <ul class="space-y-2">
            {#each devices as device (device.id)}
              <li class="flex items-center justify-between gap-2 border border-[#00aa00] px-3 py-2">
                {#if renamingDeviceId === device.id}
                  <input
                    bind:value={renameLabel}
                    class={input}
                    style="flex: 1"
                    on:keydown={(e) => e.key === 'Enter' && confirmRename()}
                  />
                  <button type="button" class="text-xs text-[#00ff00] underline" on:click={confirmRename} disabled={devicesBusy}>Save</button>
                  <button type="button" class="text-xs text-[#00aa00] underline" on:click={() => (renamingDeviceId = null)}>Cancel</button>
                {:else}
                  <div class="flex-1 min-w-0">
                    <div class="text-sm text-[#00ff00] truncate">
                      {device.device_label}
                      {#if device.id === thisDeviceId}<span class="text-[10px] text-[#ffaa00]"> (this device)</span>{/if}
                    </div>
                    <div class="text-[10px] text-[#00aa00]">Added {new Date(device.created_at).toLocaleDateString()}</div>
                  </div>
                  <button type="button" class="text-xs text-[#00ff00] underline" on:click={() => startRename(device)} disabled={devicesBusy}>Rename</button>
                  <button type="button" class="text-xs text-red-500 underline" on:click={() => handleRemoveDevice(device)} disabled={devicesBusy}>Remove</button>
                {/if}
              </li>
            {/each}
          </ul>
        {/if}
      </section>

      <section class="space-y-3">
        <h4 class="text-sm font-bold text-[#00ff00] uppercase tracking-wider">Message history on this device</h4>
        <p class="text-[11px] text-[#00aa00]">
          To keep old encrypted messages readable after a reload (even once their original encryption key is gone),
          this device keeps its own local, encrypted copy of messages you've already decrypted. It never leaves this
          device and is never sent to the server. Clearing it brings back the stricter guarantee that a message
          becomes unreadable here the moment its key is gone -- but anything whose key is already gone won't be
          readable again either way.
        </p>
        {#if historyClearError}<div class="text-xs text-red-500">{'>'} {historyClearError}</div>{/if}
        {#if historyCleared}<div class="text-xs text-[#00ff00]">{'>'} Local message history cache cleared.</div>{/if}
        <button type="button" class="text-xs text-red-500 underline disabled:opacity-50" disabled={historyClearBusy} on:click={handleClearMessageHistory}>
          {historyClearBusy ? 'Clearing...' : 'Clear message history on this device'}
        </button>
      </section>

      <section class="space-y-3">
        <h4 class="text-sm font-bold text-[#00ff00] uppercase tracking-wider">Account recovery</h4>
        <p class="text-[11px] text-[#00aa00]">
          Optional: back up this device's encryption key under a passphrase, so a brand new device can recover it
          later and still read your old encrypted direct messages. Without this, losing every device means old
          encrypted history is gone for good -- that stays true unless you set this up.
        </p>

        {#if recoveryError}<div class="text-xs text-red-500">{'>'} {recoveryError}</div>{/if}
        {#if recoveryMessage}<div class="text-xs text-[#00ff00]">{'>'} {recoveryMessage}</div>{/if}

        {#if recoveryLoading}
          <div class="text-xs text-[#00aa00]">{'>'} Checking...</div>
        {:else if showRecoveryForm}
          <div class="space-y-3 border border-[#00aa00] p-3">
            <p class="text-[11px] text-[#ffaa00]">
              There is no way to recover this passphrase if you forget it -- write it down somewhere safe.
            </p>
            <div>
              <label for="recovery-new-passphrase" class={label}>Recovery passphrase</label>
              <input id="recovery-new-passphrase" type="password" bind:value={recoveryPassphrase} class={input} autocomplete="off" minlength="8" />
            </div>
            <div>
              <label for="recovery-confirm-passphrase" class={label}>Confirm passphrase</label>
              <input id="recovery-confirm-passphrase" type="password" bind:value={recoveryPassphraseConfirm} class={input} autocomplete="off" minlength="8" />
            </div>
            <div class="flex gap-2">
              <button type="button" class={submit} on:click={confirmRecoverySetup} disabled={recoveryBusy}>
                {recoveryBusy ? 'Saving...' : 'Save recovery backup'}
              </button>
              <button type="button" class="text-xs text-[#00aa00] underline" on:click={() => (showRecoveryForm = false)} disabled={recoveryBusy}>Cancel</button>
            </div>
          </div>
        {:else if keyBackup}
          <div class="flex items-center justify-between gap-2 border border-[#00aa00] px-3 py-2">
            <div class="text-xs text-[#00ff00]">
              {'>'} Recovery backup is set up.
              <div class="text-[10px] text-[#00aa00]">Last updated {new Date(keyBackup.updated_at).toLocaleDateString()}</div>
            </div>
            <div class="flex gap-2 shrink-0">
              <button type="button" class="text-xs text-[#00ff00] underline" on:click={openRecoveryForm} disabled={recoveryBusy}>Change passphrase</button>
              <button type="button" class="text-xs text-red-500 underline" on:click={handleRemoveBackup} disabled={recoveryBusy}>Remove</button>
            </div>
          </div>
        {:else}
          <div class="text-xs text-[#00aa00]">{'>'} No recovery backup set up yet.</div>
          <button type="button" class={submit} on:click={openRecoveryForm} disabled={recoveryBusy}>Set up a recovery passphrase</button>
        {/if}

        {#if !recoveryLoading && keyBackup && !showRecoveryForm}
          {#if showRecoverForm}
            <div class="space-y-3 border border-[#ffaa00] p-3">
              <p class="text-[11px] text-[#ffaa00]">
                This replaces THIS device's current encryption key with the one recovered from the backup. Enter the
                recovery passphrase.
              </p>
              <div>
                <label for="recover-passphrase" class={label}>Recovery passphrase</label>
                <input
                  id="recover-passphrase"
                  type="password"
                  bind:value={recoverPassphrase}
                  class={input}
                  autocomplete="off"
                  on:keydown={(e) => e.key === 'Enter' && confirmRecoverFromBackup()}
                />
              </div>
              {#if recoverError}<div class="text-xs text-red-500">{'>'} {recoverError}</div>{/if}
              <div class="flex gap-2">
                <button type="button" class={submit} on:click={confirmRecoverFromBackup} disabled={recoverBusy || !recoverPassphrase}>
                  {recoverBusy ? 'Recovering...' : 'Recover my key'}
                </button>
                <button type="button" class="text-xs text-[#00aa00] underline" on:click={() => (showRecoverForm = false)} disabled={recoverBusy}>Cancel</button>
              </div>
            </div>
          {:else}
            <div>
              <button type="button" class="text-xs text-[#00ff00] underline" on:click={openRecoverForm} disabled={recoveryBusy || recoverBusy}>
                Recover from backup
              </button>
              <p class="text-[10px] text-[#00aa00] mt-1">
                Restore this account's backed-up key onto THIS device, replacing its current key. Use this if this
                device ended up with the wrong key (e.g. a fresh one was generated after a network error) even
                though a backup already exists.
              </p>
            </div>
          {/if}
          {#if recoverMessage}<div class="text-xs text-[#00ff00]">{'>'} {recoverMessage}</div>{/if}
        {/if}
      </section>
    </div>
  </div>
</div>
