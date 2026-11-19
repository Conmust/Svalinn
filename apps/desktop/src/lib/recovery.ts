// Optional, opt-in passphrase-based recovery backup for a device's E2EE
// private key (see `lib/crypto.ts` for the keypair itself, and
// `migrations/0031_key_recovery_backup.sql` for the server-side table).
//
// The whole point of this file is that nothing secret ever crosses the
// network: the passphrase and the symmetric key derived from it live only
// in memory in this module, for exactly as long as one encrypt/decrypt
// call takes, and are never sent to or logged by the server. Only the
// final ciphertext blob + salt + kdf_params go over the wire -- none of
// those are secret on their own (the blob is useless without the
// passphrase, and the salt/kdf_params are just "how to re-derive the key
// IF you already have the passphrase").
//
// KDF tier: Argon2id (`crypto_pwhash_ALG_ARGON2ID13`) at the MODERATE
// opslimit/memlimit tier. INTERACTIVE is tuned for unlocking something on
// every app launch and is too cheap to resist an attacker who steals this
// blob and brute-forces it completely offline, with no rate limiting.
// SENSITIVE is markedly more resistant but is specced for background/
// rare operations that can take several seconds and up to ~1GiB of RAM --
// too heavy for a UI the user is actively waiting on, especially on
// lower-end hardware. MODERATE (libsodium's own docs put it at roughly
// 0.7s and 256MiB on a modern desktop) is the "resistant but still
// practical interactively" middle tier, so that's what's used for both
// setting up and recovering a backup.
import sodium from 'libsodium-wrappers-sumo';
import { writable, type Writable } from 'svelte/store';
import { apiFetch, apiBase, getAuthHeaders } from './api';
import { fetchMyDevices, registerDevice } from './devices';
import { adoptRecoveredKeypair, ensureDeviceKeypair, hasLocalKeypair, type DeviceKeypair } from './crypto';

let readyPromise: Promise<void> | null = null;
function ready(): Promise<void> {
  if (!readyPromise) readyPromise = sodium.ready;
  return readyPromise;
}

/** What `kdf_params` holds, so a future client version can still reproduce
 * the exact derivation used for an older backup even if its own defaults
 * change later. */
interface KdfParams {
  algorithm: 'argon2id13';
  opslimit: number;
  memlimit: number;
  /** Bumped only if the envelope format below (payload shape / nonce
   * placement) ever changes. */
  version: 1;
}

export interface KeyBackupRecord {
  encrypted_blob: string;
  salt: string;
  kdf_params: KdfParams;
  updated_at: string;
}

/** The plaintext this module encrypts/decrypts. Carrying `deviceId` and
 * `publicKey` alongside the private key (rather than backing up the
 * private key alone) is what lets recovery restore the SAME device
 * identity -- see `restoreFromBackup` below for why that matters. */
interface BackupPayload {
  privateKey: string;
  publicKey: string;
  deviceId: string;
}

function deriveKey(passphrase: string, salt: Uint8Array, params: KdfParams): Uint8Array {
  return sodium.crypto_pwhash(
    sodium.crypto_secretbox_KEYBYTES,
    passphrase,
    salt,
    params.opslimit,
    params.memlimit,
    sodium.crypto_pwhash_ALG_ARGON2ID13
  );
}

/** Does the current account have a recovery backup set up at all? Used to
 * decide, on a device with no local keypair yet, whether to offer
 * recovery before generating a brand new key. */
export async function fetchKeyBackup(): Promise<KeyBackupRecord | null> {
  const response = await apiFetch(`${apiBase()}/api/v1/users/me/key-backup`, {
    headers: getAuthHeaders(),
  });
  if (response.status === 404) return null;
  if (!response.ok) {
    throw new Error('Failed to check for an existing recovery backup');
  }
  return response.json();
}

/**
 * Encrypts the given device's private key (plus its public key and device
 * id) under a key derived from `passphrase`, and uploads the result,
 * replacing any previous backup for this account outright (single-slot
 * design -- see migration 0031).
 *
 * The passphrase is used only in-memory here to derive the symmetric key;
 * it is never included in the request body and never logged.
 */
export async function createOrReplaceKeyBackup(
  passphrase: string,
  publicKey: string,
  privateKey: string,
  deviceId: string
): Promise<void> {
  await ready();

  const salt = sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES);
  const params: KdfParams = {
    algorithm: 'argon2id13',
    opslimit: sodium.crypto_pwhash_OPSLIMIT_MODERATE,
    memlimit: sodium.crypto_pwhash_MEMLIMIT_MODERATE,
    version: 1,
  };
  const key = deriveKey(passphrase, salt, params);

  const payload: BackupPayload = { privateKey, publicKey, deviceId };
  const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
  const ciphertext = sodium.crypto_secretbox_easy(sodium.from_string(JSON.stringify(payload)), nonce, key);
  sodium.memzero(key);

  // Nonce is prepended to the ciphertext before base64-encoding, so the
  // server only ever needs to store/relay a single opaque string.
  const combined = new Uint8Array(nonce.length + ciphertext.length);
  combined.set(nonce, 0);
  combined.set(ciphertext, nonce.length);
  const encryptedBlob = sodium.to_base64(combined, sodium.base64_variants.ORIGINAL);
  const saltBase64 = sodium.to_base64(salt, sodium.base64_variants.ORIGINAL);

  const response = await apiFetch(`${apiBase()}/api/v1/users/me/key-backup`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
    body: JSON.stringify({ encrypted_blob: encryptedBlob, salt: saltBase64, kdf_params: params }),
  });
  if (!response.ok) {
    throw new Error('Failed to upload recovery backup');
  }
}

/** Removes the account's recovery backup, e.g. because the user no longer
 * wants this recovery option enabled. */
export async function deleteKeyBackup(): Promise<void> {
  const response = await apiFetch(`${apiBase()}/api/v1/users/me/key-backup`, {
    method: 'DELETE',
    headers: getAuthHeaders(),
  });
  if (!response.ok) {
    throw new Error('Failed to remove recovery backup');
  }
}

/** Thrown by `decryptKeyBackup` when the passphrase is wrong (or the blob
 * is corrupt) -- libsodium's authenticated encryption naturally rejects a
 * wrong key, so this is the expected, clean failure mode, not a crash. */
export class IncorrectPassphraseError extends Error {
  constructor() {
    super('Incorrect passphrase, or the backup is corrupted.');
  }
}

/**
 * Decrypts a fetched backup record with a user-entered passphrase,
 * returning the recovered device identity. Never throws for "wrong
 * passphrase" in a way that looks like a crash -- that case is always
 * `IncorrectPassphraseError`.
 */
export async function decryptKeyBackup(
  record: KeyBackupRecord,
  passphrase: string
): Promise<{ publicKey: string; privateKey: string; deviceId: string }> {
  await ready();

  let combined: Uint8Array;
  let salt: Uint8Array;
  try {
    combined = sodium.from_base64(record.encrypted_blob, sodium.base64_variants.ORIGINAL);
    salt = sodium.from_base64(record.salt, sodium.base64_variants.ORIGINAL);
  } catch {
    throw new IncorrectPassphraseError();
  }

  const nonceLen = sodium.crypto_secretbox_NONCEBYTES;
  if (combined.length <= nonceLen) throw new IncorrectPassphraseError();
  const nonce = combined.slice(0, nonceLen);
  const ciphertext = combined.slice(nonceLen);

  const key = deriveKey(passphrase, salt, record.kdf_params);
  let plaintextBytes: Uint8Array;
  try {
    plaintextBytes = sodium.crypto_secretbox_open_easy(ciphertext, nonce, key);
  } catch {
    throw new IncorrectPassphraseError();
  } finally {
    sodium.memzero(key);
  }

  let payload: BackupPayload;
  try {
    payload = JSON.parse(sodium.to_string(plaintextBytes));
    if (!payload.privateKey || !payload.publicKey || !payload.deviceId) throw new Error('malformed');
  } catch {
    throw new IncorrectPassphraseError();
  }

  return { publicKey: payload.publicKey, privateKey: payload.privateKey, deviceId: payload.deviceId };
}

/**
 * Full recovery flow for a brand new device with no local keypair: fetch
 * the backup, decrypt it with `passphrase`, and adopt the recovered key as
 * this device's own -- restoring the SAME private key (not a new one), so
 * old history encrypted for it stays decryptable.
 *
 * Device-id reuse decision: a recovered key is only useful for reading old
 * history if the client identifies itself with the SAME `device_id` that
 * old messages' `message_recipients` rows were fanned out to -- the server
 * and other clients key everything off `device_id`, not off the public key
 * itself (see migration 0030 and `lib/devices.ts`). So:
 *
 * - If the original `device_keys` row (from the backup) still exists --
 *   the common case, e.g. the user just got a new phone and never
 *   explicitly removed the old one from Account Settings -- this reuses
 *   that SAME `device_id`. No new registration call is made; the server
 *   already has this id tied to this public key, and old
 *   `message_recipients` rows addressed to it become readable again.
 * - If that row was explicitly removed (see `routes::devices::delete_device`
 *   -- deleting a device is permanent, and anything already addressed to
 *   it is explicitly documented as an orphan that stays unreadable), this
 *   re-registers the SAME public/private keypair under a brand NEW
 *   `device_id`. That restores the identity for all FUTURE messages (new
 *   sends will be fanned out to this new registration), but does not and
 *   cannot un-orphan history addressed to the deleted id -- consistent
 *   with the existing, accepted "removing a device is permanent" behavior.
 *   This is strictly better than generating an unrelated fresh key, since
 *   at least the key material (and thus any out-of-band identity a
 *   contact may have noted) is preserved, even though old ciphertext
 *   addressed to the old id is still gone.
 */
export async function restoreFromBackup(passphrase: string): Promise<DeviceKeypair> {
  const record = await fetchKeyBackup();
  if (!record) throw new Error('No recovery backup is set up for this account.');

  const recovered = await decryptKeyBackup(record, passphrase);

  const existingDevices = await fetchMyDevices();
  const stillRegistered = existingDevices.some((d) => d.id === recovered.deviceId);

  const deviceId = stillRegistered
    ? recovered.deviceId
    : await registerDevice(recovered.publicKey, 'Recovered device');

  const keypair: DeviceKeypair = { publicKey: recovered.publicKey, privateKey: recovered.privateKey, deviceId };
  adoptRecoveredKeypair(keypair);
  return keypair;
}

/**
 * True if this device needs to ask the user to make an explicit
 * recover-or-start-fresh choice before `ensureDeviceKeypair()` can safely
 * be called: i.e. this device has no local keypair yet AND the account
 * has a recovery backup that could restore an old one. Opt-out users (no
 * backup ever set up) always get `false` here, so their experience is
 * byte-for-byte what it was before this feature existed -- a fresh key is
 * generated with no prompt, same as always.
 */
export async function needsRecoveryChoice(): Promise<boolean> {
  if (hasLocalKeypair()) return false;
  const record = await fetchKeyBackup();
  return record !== null;
}

// --- The single gate to this device's first-ever keypair -----------------
//
// `ensureDeviceKeypair()` (in `lib/crypto.ts`) is low-level: it just
// generates-or-returns a key, with no awareness of recovery backups at
// all. Deciding WHETHER it's safe to call that -- i.e. "has the
// recovery-backup check resolved one way or the other yet?" -- used to be
// each call site's own responsibility, and `App.svelte` was the only one
// that got it right. `DMChatArea.svelte` called `ensureDeviceKeypair()`
// directly at component init, so opening a DM while `App.svelte`'s own
// backup check was still in flight raced ahead, generated a throwaway key,
// and permanently burned the chance to ever recover the real backed-up key
// on that device (`needsRecoveryChoice()` short-circuits to `false` as soon
// as `hasLocalKeypair()` is true).
//
// `deviceEncryptionReady()` below is now the ONLY entry point every
// consumer (`App.svelte`'s setup effect, `DMChatArea.svelte`,
// `AccountSettings.svelte`) is allowed to use to get at this device's
// keypair. All callers -- no matter when they call it relative to each
// other -- share the exact same in-flight promise, so there is no window
// in which a second caller can race ahead of the first and create a
// keypair through some other path.

/** True while this device has no keypair yet and the account has a
 * recovery backup that could restore an old one -- i.e. while the user
 * needs to make an explicit choice before any keypair can be created.
 * `App.svelte` shows `RecoveryChoice.svelte` whenever this is true, and it
 * clears automatically once the user's choice is reported back via
 * `resolveRecoveryChoice`. */
export const recoveryChoiceNeeded: Writable<boolean> = writable(false);

/** The current value of this device's keypair, kept in sync with
 * `deviceReadyPromise` below -- `null` until that promise first settles.
 * Existing in addition to (not instead of) `deviceEncryptionReady()`
 * because a `Promise` can only ever resolve once: `DMChatArea.svelte`'s
 * module-init `.then()` captures whatever keypair it settled with as a
 * one-time snapshot, which is exactly what let the manual "recover from
 * backup" escape hatch below go unnoticed by an already-open DM view (see
 * `replaceActiveKeypair`). Reactive consumers subscribe to this store
 * instead (`$activeDeviceKeypair`) so a later change is picked up
 * immediately, with no reload required. */
export const activeDeviceKeypair: Writable<DeviceKeypair | null> = writable(null);

let deviceReadyPromise: Promise<DeviceKeypair> | null = null;
let resolveReady: ((kp: DeviceKeypair) => void) | null = null;
let rejectReady: ((err: unknown) => void) | null = null;

/** Maximum number of times to retry the backup-existence check after a
 * transient error (e.g. a dropped network request) before falling back to
 * just generating a fresh key, so a genuine error never leaves the device
 * permanently stuck with no keypair (see non-blocking issue #1). */
const MAX_BACKUP_CHECK_ATTEMPTS = 3;

/** Settles `deviceReadyPromise` (if a resolver is still waiting) and
 * mirrors the value into `activeDeviceKeypair`, so every path that
 * produces this device's first-ever keypair keeps both in sync. */
function settleDeviceReady(keypair: DeviceKeypair): void {
  resolveReady?.(keypair);
  activeDeviceKeypair.set(keypair);
}

async function runDeviceEncryptionSetup(attempt = 1): Promise<void> {
  try {
    if (!(await needsRecoveryChoice())) {
      settleDeviceReady(await ensureDeviceKeypair());
      return;
    }
    recoveryChoiceNeeded.set(true);
    // Deliberately leaves `deviceReadyPromise` pending here -- it's resolved
    // later by `resolveRecoveryChoice()`, once the user has made their
    // choice in `RecoveryChoice.svelte`.
  } catch (e) {
    console.error('Failed to check for an existing recovery backup:', e);
    if (attempt < MAX_BACKUP_CHECK_ATTEMPTS) {
      setTimeout(() => void runDeviceEncryptionSetup(attempt + 1), 1000 * attempt);
      return;
    }
    // Out of retries on a genuine error (as opposed to "no backup exists",
    // which `needsRecoveryChoice()` reports as a normal `false`, not an
    // error): fail toward the safe default of just generating a fresh key,
    // same as the no-backup case, rather than leaving the device stuck
    // with no key and no message-sending capability until a full reload.
    try {
      settleDeviceReady(await ensureDeviceKeypair());
    } catch (err) {
      rejectReady?.(err);
    }
  }
}

/**
 * Resolves once this device definitely has a keypair -- the ONE path
 * through which that can ever happen for the first time on this device.
 * Every caller gets the exact same promise back for as long as it's
 * pending, so a `DMChatArea` opened mid-check, an `AccountSettings` opened
 * mid-check, and `App.svelte`'s own setup effect all wait on the SAME
 * resolution instead of each deciding independently.
 */
export function deviceEncryptionReady(): Promise<DeviceKeypair> {
  if (!deviceReadyPromise) {
    deviceReadyPromise = new Promise<DeviceKeypair>((resolve, reject) => {
      resolveReady = resolve;
      rejectReady = reject;
    });
    void runDeviceEncryptionSetup();
  }
  return deviceReadyPromise;
}

/** Called by `RecoveryChoice.svelte` once the user has made their explicit
 * recover-or-start-fresh choice, with the resulting keypair -- resolves
 * every pending `deviceEncryptionReady()` caller (including any DM view or
 * settings panel opened while the choice was still unmade) and clears the
 * modal flag. */
export function resolveRecoveryChoice(keypair: DeviceKeypair): void {
  recoveryChoiceNeeded.set(false);
  settleDeviceReady(keypair);
}

/**
 * Updates this device's keypair AFTER `deviceEncryptionReady()` has
 * already settled -- the manual "Recover from backup" escape hatch in
 * `AccountSettings.svelte` is specifically for a device that already has
 * (and has already handed out, e.g. to an open `DMChatArea.svelte`) its
 * OLD keypair, which is exactly the case `resolveRecoveryChoice()` above
 * can't handle: it only ever fires once, to settle the gate from pending,
 * and a `Promise` cannot be made to resolve a second time with a new
 * value.
 *
 * This instead:
 * - Updates `activeDeviceKeypair`, so any already-mounted reactive
 *   consumer (`DMChatArea.svelte`, via `$activeDeviceKeypair`) picks up
 *   the new key immediately -- no reload required.
 * - Replaces `deviceReadyPromise` itself with a promise already resolved
 *   to the new keypair, so any FUTURE `await deviceEncryptionReady()`
 *   caller (e.g. a `DMChatArea` for a different conversation, opened
 *   after this call) gets the new keypair too, instead of the stale one
 *   baked into the old promise.
 * - As a safety net, if the gate somehow hadn't settled yet when this is
 *   called (e.g. this ran while the very first setup check was still in
 *   flight), resolves that original pending promise too, so a caller
 *   already awaiting it doesn't hang forever.
 */
export function replaceActiveKeypair(keypair: DeviceKeypair): void {
  recoveryChoiceNeeded.set(false);
  resolveReady?.(keypair);
  resolveReady = null;
  rejectReady = null;
  deviceReadyPromise = Promise.resolve(keypair);
  activeDeviceKeypair.set(keypair);
}

/** Resets setup state on logout, so the next login re-runs the check for
 * whichever account logs in next instead of resolving instantly from a
 * stale promise tied to the previous account. */
export function resetDeviceEncryptionSetup(): void {
  deviceReadyPromise = null;
  resolveReady = null;
  rejectReady = null;
  recoveryChoiceNeeded.set(false);
  activeDeviceKeypair.set(null);
}
