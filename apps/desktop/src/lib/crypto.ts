// End-to-end encryption for direct messages: X25519 key agreement +
// XSalsa20-Poly1305 (libsodium's `crypto_box` construction, via
// libsodium-wrappers). The server only ever sees ciphertext and public
// keys -- private keys never leave this client, on any code path, ever.
//
// Per-device model: every device a user logs in on generates and keeps its
// OWN keypair, forever. There is no way to move a private key to another
// device -- a second device is just a second, independent identity that
// has to be encrypted to separately. See `lib/devices.ts` for registering/
// listing/removing devices and discovering a conversation's participant
// devices.
import sodium from 'libsodium-wrappers-sumo';
import { registerDevice } from './devices';
import { withTimeout, TimeoutError } from './timeout';

const PUBLIC_KEY_STORAGE_KEY = 'svalinn_e2ee_public_key';
const PRIVATE_KEY_STORAGE_KEY = 'svalinn_e2ee_private_key';
const DEVICE_ID_STORAGE_KEY = 'svalinn_e2ee_device_id';

export interface DeviceKeypair {
  publicKey: string;
  privateKey: string;
  /** This device's own id, as returned by `POST /users/me/devices`. Used
   * to pick this device's own ciphertext out of a fan-out message, and to
   * manage (rename/remove) this device from the devices settings UI. */
  deviceId: string;
}

// --- Distinct, non-conflated failure modes --------------------------------
//
// Everything below used to end up as a bare `Error` (or wasn't caught at
// all), which meant a genuine bug -- libsodium's WASM module never loading,
// `localStorage` being unavailable, a device-registration request that
// keeps failing -- looked, to a caller, exactly like any other rejected
// promise. That's fine for "retry and move on" logic, but it's not enough
// for UI that's supposed to tell a user (or a test) WHY encrypted messaging
// isn't working right now. These classes exist so call sites can tell "the
// crypto library itself is broken" apart from "this device couldn't be
// registered" apart from "unexpected error", instead of guessing from a
// free-text message.

/** The libsodium WASM module never finished loading (or threw while
 * loading) -- e.g. a webview without real WASM support, a blocked/corrupt
 * asset, or a CSP that forbids it. Nothing that depends on `sodium` can
 * work at all until this is fixed; there is no key-specific recovery from
 * it. */
export class CryptoLibraryError extends Error {
  constructor(message = 'The encryption library failed to load.') {
    super(message);
    this.name = 'CryptoLibraryError';
  }
}

/** This device couldn't be prepared for encrypted messaging for a reason
 * that has nothing to do with any particular key or passphrase -- e.g.
 * `localStorage` is unavailable/full/disabled (private/incognito-like
 * webview modes), or the device-registration request to the server kept
 * failing. Distinct from `CryptoLibraryError`: the crypto library itself
 * is fine, this device specifically just isn't set up. */
export class DeviceSetupError extends Error {
  constructor(message = 'This device could not be set up for encrypted messaging.') {
    super(message);
    this.name = 'DeviceSetupError';
  }
}

/** How long we're willing to wait for libsodium's WASM module to finish
 * initializing before giving up and surfacing `CryptoLibraryError`, rather
 * than leaving every caller (device setup, recovery, every DM view) stuck
 * on a promise that may simply never resolve. */
const SODIUM_READY_TIMEOUT_MS = 8000;

let readyPromise: Promise<void> | null = null;

/** Resolves once libsodium's WASM module has finished loading, or rejects
 * with `CryptoLibraryError` if it hasn't within `SODIUM_READY_TIMEOUT_MS`.
 * A timeout here doesn't cancel the real `sodium.ready` -- if it later
 * resolves on its own, the NEXT call to `ready()` (this promise is reset on
 * failure) picks it up immediately instead of staying stuck forever. */
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

/** `localStorage.setItem`/`.getItem` can throw synchronously -- full quota,
 * disabled storage, or some private/incognito-like webview modes reject it
 * outright. Checked once, up front, so a broken store surfaces as one clear
 * `DeviceSetupError` instead of a confusing failure deep inside whichever
 * `localStorage` call happened to run first. */
let keypairPromise: Promise<DeviceKeypair> | null = null;

function checkStorageAvailable(): void {
  const probeKey = '__svalinn_storage_probe__';
  try {
    localStorage.setItem(probeKey, '1');
    localStorage.removeItem(probeKey);
  } catch {
    throw new DeviceSetupError(
      'This device cannot store an encryption key (local storage is unavailable, full, or disabled).'
    );
  }
}

function readStoredKeypair(): DeviceKeypair | null {
  try {
    const publicKey = localStorage.getItem(PUBLIC_KEY_STORAGE_KEY);
    const privateKey = localStorage.getItem(PRIVATE_KEY_STORAGE_KEY);
    const deviceId = localStorage.getItem(DEVICE_ID_STORAGE_KEY);
    if (!publicKey || !privateKey || !deviceId) return null;
    return { publicKey, privateKey, deviceId };
  } catch {
    // Treated as "nothing stored yet" here -- `ensureDeviceKeypair` always
    // runs `checkStorageAvailable()` before it would try to persist a new
    // key, so a genuinely broken store still surfaces as `DeviceSetupError`
    // rather than silently regenerating a key every call.
    return null;
  }
}

/**
 * True if this device already has a local keypair (whether generated here
 * or restored via `lib/recovery.ts`). Synchronous, so callers can decide
 * *before* calling `ensureDeviceKeypair()` whether they need to offer
 * passphrase recovery first -- see `App.svelte`'s
 * `setupDeviceEncryption()`, which checks this before ever generating a
 * fresh key.
 */
export function hasLocalKeypair(): boolean {
  return readStoredKeypair() !== null;
}

/** A reasonable default label for a newly-registered device. The user can
 * rename it later from the devices settings UI. */
function defaultDeviceLabel(): string {
  const platform = (typeof navigator !== 'undefined' && navigator.platform) || 'Device';
  return `${platform} - ${new Date().toLocaleDateString()}`;
}

/**
 * Returns this device's own X25519 keypair and device id (base64-encoded
 * keys), generating a keypair and registering a new device with the
 * server on first use. The private key is stored only in `localStorage`
 * and is never sent anywhere -- only the public half is ever part of a
 * request body.
 *
 * Per-device model: calling this again on the same device just returns
 * the existing keypair/device id without registering again. A different
 * device (different browser profile, different install, cleared
 * localStorage, ...) always gets its own independent keypair and its own
 * `device_id` -- there is no shared "the user's key", only "this device's
 * key".
 */
export function ensureDeviceKeypair(): Promise<DeviceKeypair> {
  if (!keypairPromise) {
    keypairPromise = (async () => {
      const existing = readStoredKeypair();
      if (existing) return existing;

      // Fail fast and clearly if this device simply can't persist a key at
      // all, rather than generating one, registering it with the server,
      // and only THEN discovering `localStorage.setItem` throws -- that
      // would leave an orphaned registration server-side for no benefit.
      checkStorageAvailable();

      await ready();
      const generated = sodium.crypto_box_keypair();
      const publicKey = sodium.to_base64(generated.publicKey, sodium.base64_variants.ORIGINAL);
      const privateKey = sodium.to_base64(generated.privateKey, sodium.base64_variants.ORIGINAL);

      // Register before persisting locally: if registration fails, nothing
      // is written to localStorage, so the next call starts over instead of
      // treating this device as "set up" with a key/id the server never saw.
      let deviceId: string;
      try {
        deviceId = await registerDevice(publicKey, defaultDeviceLabel());
      } catch (err) {
        throw new DeviceSetupError(
          err instanceof Error ? `Failed to register this device: ${err.message}` : 'Failed to register this device.'
        );
      }

      try {
        localStorage.setItem(PUBLIC_KEY_STORAGE_KEY, publicKey);
        localStorage.setItem(PRIVATE_KEY_STORAGE_KEY, privateKey);
        localStorage.setItem(DEVICE_ID_STORAGE_KEY, deviceId);
      } catch {
        throw new DeviceSetupError(
          'This device cannot store an encryption key (local storage is unavailable, full, or disabled).'
        );
      }

      return { publicKey, privateKey, deviceId };
    })().catch((err) => {
      // Don't leave future callers stuck on a permanently rejected promise --
      // let the next call retry from scratch.
      keypairPromise = null;
      throw err;
    });
  }
  return keypairPromise;
}

/**
 * Adopts a keypair recovered from a passphrase backup (see
 * `lib/recovery.ts`) as THIS device's keypair: persists it to
 * `localStorage` exactly like a freshly-generated one, and primes the
 * in-memory promise so any later `ensureDeviceKeypair()` call just returns
 * it instead of generating a new key.
 *
 * Callers choose `deviceId` themselves (see `lib/recovery.ts`'s
 * `restoreFromBackup`): either the ORIGINAL device id the backup was made
 * under (if that device is still registered server-side -- the common
 * case), or a freshly re-registered one (if the original registration was
 * since removed). Either way, by the time this is called the device id
 * passed in is already valid server-side -- this function only ever
 * writes local storage, it never talks to the network itself.
 */
export function adoptRecoveredKeypair(keypair: DeviceKeypair): void {
  localStorage.setItem(PUBLIC_KEY_STORAGE_KEY, keypair.publicKey);
  localStorage.setItem(PRIVATE_KEY_STORAGE_KEY, keypair.privateKey);
  localStorage.setItem(DEVICE_ID_STORAGE_KEY, keypair.deviceId);
  keypairPromise = Promise.resolve(keypair);
}

/**
 * This device's own id, if `ensureDeviceKeypair` has already resolved at
 * least once (and localStorage hasn't been cleared since). Synchronous, for
 * call sites that just need to filter/tag by device id and can't await --
 * e.g. the WebSocket message handler picking this device's entry out of a
 * fan-out broadcast. Returns `null` if the device isn't set up yet; callers
 * should treat that the same as "no matching entry", never as "use some
 * other device's".
 */
export function getMyDeviceId(): string | null {
  try {
    return localStorage.getItem(DEVICE_ID_STORAGE_KEY);
  } catch {
    return null;
  }
}

/**
 * Encrypts `plaintext` for `recipientPublicKeyBase64` using this device's
 * private key, with a fresh random nonce. Never reuse a nonce across calls
 * -- `crypto_box_easy`'s security depends on each nonce being used at most
 * once for a given key pair, which is why a new one is generated here every
 * time rather than being passed in.
 */
export function encryptForRecipient(
  plaintext: string,
  recipientPublicKeyBase64: string,
  myPrivateKeyBase64: string
): { ciphertext: string; nonce: string } {
  const recipientPublicKey = sodium.from_base64(recipientPublicKeyBase64, sodium.base64_variants.ORIGINAL);
  const myPrivateKey = sodium.from_base64(myPrivateKeyBase64, sodium.base64_variants.ORIGINAL);
  const nonceBytes = sodium.randombytes_buf(sodium.crypto_box_NONCEBYTES);

  const ciphertextBytes = sodium.crypto_box_easy(
    sodium.from_string(plaintext),
    nonceBytes,
    recipientPublicKey,
    myPrivateKey
  );

  return {
    ciphertext: sodium.to_base64(ciphertextBytes, sodium.base64_variants.ORIGINAL),
    nonce: sodium.to_base64(nonceBytes, sodium.base64_variants.ORIGINAL),
  };
}

/**
 * Decrypts a message encrypted with `encryptForRecipient`. Returns `null`
 * (rather than throwing) if decryption fails -- wrong key, tampered
 * ciphertext, or wrong nonce -- so a bad message never crashes the UI.
 *
 * X25519 key agreement is symmetric: `shared_secret(my_private, their_public)
 * == shared_secret(their_private, my_public)`. That means the sender of a
 * message can decrypt their own sent ciphertext using the very same
 * (recipient_public_key, my_private_key) pair used to encrypt it. So for
 * every message in a 1-on-1 conversation -- whether sent by you or
 * received from the other person -- decrypt it with (the OTHER
 * participant's public key, MY OWN private key). There's no need to track
 * "whose key to use" per message.
 */
export function decryptFromSender(
  ciphertextBase64: string,
  nonceBase64: string,
  otherPartyPublicKeyBase64: string,
  myPrivateKeyBase64: string
): string | null {
  // Two genuinely different failure points, kept in separate try/catches
  // purely so the console log can say which one actually happened --
  // decoding four base64 strings should essentially never fail unless a
  // `message_recipients` row (or this device's own stored key) is corrupt,
  // whereas `crypto_box_open_easy` rejecting is the ordinary, expected
  // "wrong key/tampered ciphertext" case. Both still resolve to the exact
  // same `null` return (there's no safe way to show "corrupt" vs "wrong
  // key" differently in a message bubble without leaking more than we
  // should), so this changes nothing about behavior -- only about what
  // shows up in the console when diagnosing a real bug.
  let ciphertext: Uint8Array, nonce: Uint8Array, otherPartyPublicKey: Uint8Array, myPrivateKey: Uint8Array;
  try {
    ciphertext = sodium.from_base64(ciphertextBase64, sodium.base64_variants.ORIGINAL);
    nonce = sodium.from_base64(nonceBase64, sodium.base64_variants.ORIGINAL);
    otherPartyPublicKey = sodium.from_base64(otherPartyPublicKeyBase64, sodium.base64_variants.ORIGINAL);
    myPrivateKey = sodium.from_base64(myPrivateKeyBase64, sodium.base64_variants.ORIGINAL);
  } catch (err) {
    console.warn('Could not decode a DM for decryption (malformed base64 -- likely a corrupt row):', err);
    return null;
  }

  try {
    const plaintextBytes = sodium.crypto_box_open_easy(ciphertext, nonce, otherPartyPublicKey, myPrivateKey);
    return sodium.to_string(plaintextBytes);
  } catch {
    // Expected, ordinary failure: wrong key, tampered ciphertext, or wrong
    // nonce. Not logged as an error -- this happens routinely for anyone's
    // own non-matching history and isn't a sign of a bug.
    return null;
  }
}

// --- File attachment encryption -------------------------------------------
//
// Re-encrypting a whole file once per recipient device (the way
// `encryptForRecipient` handles short message text above) would mean
// uploading/storing N copies of a potentially large file. Instead this uses
// hybrid encryption, same idea TLS/PGP/age all use: generate ONE random
// symmetric key, encrypt the file bytes with it ONCE (`crypto_secretbox_easy`
// -- XSalsa20-Poly1305 under a shared secret key, as opposed to `crypto_box`'s
// X25519-derived shared secret), then "wrap" (encrypt) that small 32-byte key
// once per recipient device with the EXISTING per-device `crypto_box_easy`
// mechanism above. Only the small wrapped key is duplicated per device, not
// the file itself -- the encrypted file blob is uploaded/stored exactly once,
// same as an unencrypted attachment is today.

/** A file's bytes, encrypted once under a fresh random symmetric key. Upload
 * `ciphertext` as the attachment blob (it replaces the plaintext file bytes
 * byte-for-byte in the upload); `nonce` goes on the message itself
 * (`attachment_nonce`, shared across every recipient since the blob is
 * shared); `fileKey` never leaves this function's caller -- it's only ever
 * used locally to call `wrapFileKey` once per recipient device, and must
 * never be sent to the server in this raw form. */
export interface EncryptedFile {
  ciphertext: Uint8Array;
  nonce: string;
  fileKey: Uint8Array;
}

/** Encrypts `fileBytes` with a freshly generated random key -- never reused
 * across files, including a resend of the exact same file, same spirit as
 * `encryptForRecipient`'s fresh nonce per call. */
export function encryptFileForFanout(fileBytes: Uint8Array): EncryptedFile {
  const fileKey = sodium.randombytes_buf(sodium.crypto_secretbox_KEYBYTES);
  const nonceBytes = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
  const ciphertext = sodium.crypto_secretbox_easy(fileBytes, nonceBytes, fileKey);
  return {
    ciphertext,
    nonce: sodium.to_base64(nonceBytes, sodium.base64_variants.ORIGINAL),
    fileKey,
  };
}

/** Wraps (encrypts) a file's symmetric key for one recipient device, using
 * the exact same per-device mechanism as `encryptForRecipient` -- this is
 * just that function applied to 32 key bytes instead of a text string. One
 * call per recipient device (see `get_participant_devices`/
 * `ParticipantDevice`), same fan-out list the message ciphertext itself goes
 * to. */
export function wrapFileKey(
  fileKey: Uint8Array,
  recipientPublicKeyBase64: string,
  myPrivateKeyBase64: string
): { ciphertext: string; nonce: string } {
  const recipientPublicKey = sodium.from_base64(recipientPublicKeyBase64, sodium.base64_variants.ORIGINAL);
  const myPrivateKey = sodium.from_base64(myPrivateKeyBase64, sodium.base64_variants.ORIGINAL);
  const nonceBytes = sodium.randombytes_buf(sodium.crypto_box_NONCEBYTES);

  const wrappedBytes = sodium.crypto_box_easy(fileKey, nonceBytes, recipientPublicKey, myPrivateKey);

  return {
    ciphertext: sodium.to_base64(wrappedBytes, sodium.base64_variants.ORIGINAL),
    nonce: sodium.to_base64(nonceBytes, sodium.base64_variants.ORIGINAL),
  };
}

/** Unwraps this device's own copy of a file's symmetric key (from
 * `message_recipients.attachment_key_ciphertext`/`attachment_key_nonce`),
 * using the sending device's public key -- same (sender_public_key, my own
 * private key) pairing `decryptFromSender` uses for message text, and for
 * the same reason (X25519 key agreement is symmetric). Returns `null`
 * rather than throwing on any failure, same contract as
 * `decryptFromSender`. */
export function unwrapFileKey(
  wrappedKeyCiphertextBase64: string,
  wrappedKeyNonceBase64: string,
  senderPublicKeyBase64: string,
  myPrivateKeyBase64: string
): Uint8Array | null {
  let wrapped: Uint8Array, nonce: Uint8Array, senderPublicKey: Uint8Array, myPrivateKey: Uint8Array;
  try {
    wrapped = sodium.from_base64(wrappedKeyCiphertextBase64, sodium.base64_variants.ORIGINAL);
    nonce = sodium.from_base64(wrappedKeyNonceBase64, sodium.base64_variants.ORIGINAL);
    senderPublicKey = sodium.from_base64(senderPublicKeyBase64, sodium.base64_variants.ORIGINAL);
    myPrivateKey = sodium.from_base64(myPrivateKeyBase64, sodium.base64_variants.ORIGINAL);
  } catch (err) {
    console.warn('Could not decode a wrapped attachment key (malformed base64 -- likely a corrupt row):', err);
    return null;
  }

  try {
    return sodium.crypto_box_open_easy(wrapped, nonce, senderPublicKey, myPrivateKey);
  } catch {
    // Expected, ordinary failure: wrong key, tampered ciphertext, or wrong
    // nonce -- not logged as an error, same as `decryptFromSender`.
    return null;
  }
}

/** Decrypts an attachment blob's bytes with its (already unwrapped)
 * symmetric file key. Returns `null` rather than throwing on any failure --
 * wrong key, truncated/tampered download, or wrong nonce -- so a bad
 * attachment degrades to a placeholder instead of crashing the message
 * list. */
export function decryptFileBytes(ciphertextBytes: Uint8Array, nonceBase64: string, fileKey: Uint8Array): Uint8Array | null {
  let nonce: Uint8Array;
  try {
    nonce = sodium.from_base64(nonceBase64, sodium.base64_variants.ORIGINAL);
  } catch (err) {
    console.warn('Could not decode an attachment nonce (malformed base64 -- likely a corrupt row):', err);
    return null;
  }

  try {
    return sodium.crypto_secretbox_open_easy(ciphertextBytes, nonce, fileKey);
  } catch {
    // Expected, ordinary failure: wrong key or a corrupted/tampered
    // download -- not logged as an error.
    return null;
  }
}
