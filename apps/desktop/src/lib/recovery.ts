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
import {
  adoptRecoveredKeypair,
  ensureDeviceKeypair,
  hasLocalKeypair,
  CryptoLibraryError,
  type DeviceKeypair,
} from './crypto';
import {
  ensureRatchetReady,
  exportRatchetIdentityForBackup,
  importRecoveredRatchetIdentity,
  type RatchetIdentityBackup,
} from './ratchet';
import { withTimeout, TimeoutError } from './timeout';

/** Same bound as `lib/crypto.ts`'s own `ready()` -- this module loads
 * `sodium` independently (it needs `crypto_pwhash`/`crypto_secretbox`,
 * which `crypto.ts` never touches), so it needs the exact same "don't wait
 * forever" guard rather than inheriting one from there. */
const SODIUM_READY_TIMEOUT_MS = 8000;
const KEY_BACKUP_NETWORK_TIMEOUT_MS = 10_000;

/** Bound for the ONE network call that gates this device's first-ever
 * keypair (`needsRecoveryChoice()`'s call to `fetchKeyBackup()`, via
 * `runDeviceEncryptionSetup()` below) -- deliberately much more generous
 * than `KEY_BACKUP_NETWORK_TIMEOUT_MS` (used for ordinary, foreground,
 * user-initiated save/delete backup actions). A merely slow (not hung)
 * server/connection must not be indistinguishable from a genuinely broken
 * one here: unlike a save/delete click, THIS check's failure mode is "give
 * up and silently generate an unrelated fresh key", permanently forfeiting
 * the normal path back to a real backed-up key with no warning. Picking a
 * bound this generous means a check that's merely slow -- even "just over
 * the old 10s timeout" slow -- succeeds on the very first attempt, well
 * before `runDeviceEncryptionSetup()`'s retry loop would ever give up. */
const BACKUP_EXISTENCE_CHECK_TIMEOUT_MS = 20_000;

let readyPromise: Promise<void> | null = null;
function ready(): Promise<void> {
  if (!readyPromise) {
    readyPromise = withTimeout(
      sodium.ready,
      SODIUM_READY_TIMEOUT_MS,
      'The encryption library took too long to load.'
    ).catch((err) => {
      readyPromise = null;
      throw err instanceof CryptoLibraryError
        ? err
        : new CryptoLibraryError(err instanceof TimeoutError ? err.message : undefined);
    });
  }
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
 * identity -- see `restoreFromBackup` below for why that matters.
 *
 * `ratchetIdentity` is optional and additive: a backup created before
 * this field existed simply won't have it, and decrypts/restores exactly
 * as before (no ratchet material to restore, same as today's behavior).
 * See `ratchet.ts`'s `exportRatchetIdentityForBackup` for why it needs to
 * travel alongside the core identity key at all. */
interface BackupPayload {
  privateKey: string;
  publicKey: string;
  deviceId: string;
  ratchetIdentity?: RatchetIdentityBackup;
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
export async function fetchKeyBackup(timeoutMs: number = KEY_BACKUP_NETWORK_TIMEOUT_MS): Promise<KeyBackupRecord | null> {
  const response = await withTimeout(
    apiFetch(`${apiBase()}/api/v1/users/me/key-backup`, {
      headers: getAuthHeaders(),
    }),
    timeoutMs,
    'Timed out checking for an existing recovery backup.'
  );
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

  // `ensureRatchetReady()` is idempotent (see its own doc comment) --
  // calling it here defensively, rather than assuming some earlier
  // fire-and-forget call already finished, closes a real ordering gap:
  // `settleDeviceReady()` kicks it off in the background and does NOT wait
  // for it before this device is considered "ready" elsewhere, so a backup
  // created soon after a device's first launch could otherwise race ahead
  // of its own signing identity / signed prekey ever being generated, and
  // silently ship with no ratchet material to restore later.
  await ensureRatchetReady();
  const ratchetIdentity = exportRatchetIdentityForBackup();
  const payload: BackupPayload = { privateKey, publicKey, deviceId, ...(ratchetIdentity ? { ratchetIdentity } : {}) };
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

  const response = await withTimeout(
    apiFetch(`${apiBase()}/api/v1/users/me/key-backup`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
      body: JSON.stringify({ encrypted_blob: encryptedBlob, salt: saltBase64, kdf_params: params }),
    }),
    KEY_BACKUP_NETWORK_TIMEOUT_MS,
    'Timed out uploading the recovery backup.'
  );
  if (!response.ok) {
    throw new Error('Failed to upload recovery backup');
  }
}

/** Removes the account's recovery backup, e.g. because the user no longer
 * wants this recovery option enabled. */
export async function deleteKeyBackup(): Promise<void> {
  const response = await withTimeout(
    apiFetch(`${apiBase()}/api/v1/users/me/key-backup`, {
      method: 'DELETE',
      headers: getAuthHeaders(),
    }),
    KEY_BACKUP_NETWORK_TIMEOUT_MS,
    'Timed out removing the recovery backup.'
  );
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
): Promise<{ publicKey: string; privateKey: string; deviceId: string; ratchetIdentity?: RatchetIdentityBackup }> {
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

  return {
    publicKey: payload.publicKey,
    privateKey: payload.privateKey,
    deviceId: payload.deviceId,
    ratchetIdentity: payload.ratchetIdentity,
  };
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
  // Must happen BEFORE either caller resolves the device-ready gate
  // (`resolveRecoveryChoice`/`replaceActiveKeypair`), since that's what
  // can trigger `ensureRatchetReady()` -- see `importRecoveredRatchetIdentity`'s
  // own comment for why ordering matters here.
  if (recovered.ratchetIdentity) {
    importRecoveredRatchetIdentity(recovered.ratchetIdentity);
  }
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
  // Uses the generous `BACKUP_EXISTENCE_CHECK_TIMEOUT_MS` bound, not the
  // shorter one `fetchKeyBackup()` defaults to for ordinary save/delete
  // calls -- see that constant's comment for why this specific call needs
  // more room before it's treated as failed.
  const record = await fetchKeyBackup(BACKUP_EXISTENCE_CHECK_TIMEOUT_MS);
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

/** Non-null while this device has no local keypair AND the backup-existence
 * check (`needsRecoveryChoice()`) has failed `MAX_BACKUP_CHECK_ATTEMPTS`
 * times in a row WITHOUT ever determining whether the account has a
 * backup -- i.e. every attempt was a timeout or network error, never a
 * clean "no backup exists" (that's reported as an ordinary `false`, not an
 * error -- see `needsRecoveryChoice()`). This is "couldn't determine",
 * which must never be treated the same as "confirmed no backup" -- doing
 * so would silently and permanently forfeit this device's only path back
 * to a real backed-up key, with no indication anything was skipped. Holds
 * a user-facing message describing the failure; `App.svelte` shows
 * `RecoveryChoice.svelte`'s explicit "couldn't check" screen whenever this
 * is set, exactly like it does for `recoveryChoiceNeeded`, so the
 * recover-vs-fresh choice is always made knowingly by the user, never by a
 * transient failure on their behalf. */
export const recoveryCheckFailed: Writable<string | null> = writable(null);

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

/** Maximum number of times to retry the backup-existence check after an
 * AMBIGUOUS failure (a timeout, or an ordinary network error -- never
 * resolved to a clean yes/no) before giving up and surfacing
 * `recoveryCheckFailed` instead of silently guessing. Paired with
 * `BACKUP_EXISTENCE_CHECK_TIMEOUT_MS` being generous enough that a merely
 * slow (not hung) check already succeeds on the FIRST attempt, this retry
 * loop mainly exists for a check that fails fast and repeatedly (e.g. no
 * network at all), not for one that's just slow. */
const MAX_BACKUP_CHECK_ATTEMPTS = 3;

/** Settles `deviceReadyPromise` (if a resolver is still waiting) and
 * mirrors the value into `activeDeviceKeypair`, so every path that
 * produces this device's first-ever keypair keeps both in sync. */
function settleDeviceReady(keypair: DeviceKeypair): void {
  resolveReady?.(keypair);
  activeDeviceKeypair.set(keypair);

  // Best-effort, fire-and-forget: sets this device up for the Double
  // Ratchet (signing identity, signed prekey, one-time prekeys) alongside
  // its existing stateless keypair above. Never blocks `deviceEncryptionReady()`
  // on it -- a failure here (e.g. this one request to publish a prekey
  // timing out) shouldn't stop a device that otherwise works fine from
  // opening DMs; it just means every peer falls back to the legacy
  // per-device path (`RatchetNotSupportedError` -- see `ratchet.ts`) until
  // a later call succeeds. `ensureRatchetReady()` is idempotent and safe to
  // call repeatedly, so there's no harm in just trying again next launch.
  ensureRatchetReady().catch((e) => console.error('Failed to set this device up for the Double Ratchet:', e));
}

async function runDeviceEncryptionSetup(attempt = 1): Promise<void> {
  // Step 1: does this device need to ask the user to choose? This is the
  // ONLY part that's retried -- it's the part that can fail AMBIGUOUSLY
  // (a timeout or network error never tells us whether a backup exists).
  // Kept in its own try/catch, separate from the `ensureDeviceKeypair()`
  // call below, so a real failure from THAT (a broken crypto library, a
  // broken device registration -- see should-fix #1) is never misdiagnosed
  // as a backup-check problem and retried under this schedule for no
  // reason.
  let needsChoice: boolean;
  try {
    needsChoice = await needsRecoveryChoice();
  } catch (e) {
    console.error('Failed to check for an existing recovery backup:', e);
    if (attempt < MAX_BACKUP_CHECK_ATTEMPTS) {
      setTimeout(() => void runDeviceEncryptionSetup(attempt + 1), 1000 * attempt);
      return;
    }
    // Out of retries WITHOUT ever confirming whether a backup exists --
    // this is "couldn't determine", never "confirmed no backup" (that's
    // `needsRecoveryChoice()` returning a clean `false`, handled below,
    // not landing here at all). Silently falling back to generating an
    // unrelated fresh key here would permanently and invisibly forfeit
    // this device's only path back to a real backed-up key -- exactly the
    // blocking bug this guards against. Surface an explicit, actionable
    // error instead and leave `deviceReadyPromise` pending: the user
    // decides, via `RecoveryChoice.svelte`'s "couldn't check" screen,
    // whether to retry (`retryRecoveryCheck()`) or knowingly start fresh.
    recoveryCheckFailed.set(
      e instanceof TimeoutError
        ? e.message
        : e instanceof Error
          ? e.message
          : 'Could not check for an existing recovery backup.'
    );
    return;
  }

  if (needsChoice) {
    recoveryChoiceNeeded.set(true);
    // Deliberately leaves `deviceReadyPromise` pending here -- it's resolved
    // later by `resolveRecoveryChoice()`, once the user has made their
    // choice in `RecoveryChoice.svelte`.
    return;
  }

  // No backup exists (a clean, confirmed "no" -- not an ambiguous
  // failure): safe to generate a fresh key with no prompt, same as always.
  // NOT wrapped in the backup-check's retry logic above: a real failure
  // here (`CryptoLibraryError`/`DeviceSetupError`) is a non-transient bug
  // that retrying under THAT schedule would only delay surfacing, with a
  // misleading "recovery backup" console message to boot (should-fix #1).
  try {
    settleDeviceReady(await ensureDeviceKeypair());
  } catch (err) {
    rejectReady?.(err);
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
  recoveryCheckFailed.set(null);
  settleDeviceReady(keypair);
}

/** Called by `RecoveryChoice.svelte`'s "couldn't check" screen when the
 * user chooses to retry the backup-existence check rather than start
 * fresh. `deviceReadyPromise` is still pending at this point (the failure
 * path above never rejects or resolves it), so this just clears the error
 * and re-runs the check from attempt 1 -- any of `App.svelte`,
 * `DMChatArea.svelte`, or `AccountSettings.svelte` already awaiting
 * `deviceEncryptionReady()` keep waiting on the exact same promise and
 * pick up whatever this new attempt resolves to. */
export function retryRecoveryCheck(): void {
  recoveryCheckFailed.set(null);
  void runDeviceEncryptionSetup();
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
  recoveryCheckFailed.set(null);
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
  recoveryCheckFailed.set(null);
  activeDeviceKeypair.set(null);
}
