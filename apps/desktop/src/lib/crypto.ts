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

let readyPromise: Promise<void> | null = null;
let keypairPromise: Promise<DeviceKeypair> | null = null;

/** Resolves once libsodium's WASM module has finished loading. */
function ready(): Promise<void> {
  if (!readyPromise) readyPromise = sodium.ready;
  return readyPromise;
}

function readStoredKeypair(): DeviceKeypair | null {
  const publicKey = localStorage.getItem(PUBLIC_KEY_STORAGE_KEY);
  const privateKey = localStorage.getItem(PRIVATE_KEY_STORAGE_KEY);
  const deviceId = localStorage.getItem(DEVICE_ID_STORAGE_KEY);
  if (!publicKey || !privateKey || !deviceId) return null;
  return { publicKey, privateKey, deviceId };
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

      await ready();
      const generated = sodium.crypto_box_keypair();
      const publicKey = sodium.to_base64(generated.publicKey, sodium.base64_variants.ORIGINAL);
      const privateKey = sodium.to_base64(generated.privateKey, sodium.base64_variants.ORIGINAL);

      // Register before persisting locally: if registration fails, nothing
      // is written to localStorage, so the next call starts over instead of
      // treating this device as "set up" with a key/id the server never saw.
      const deviceId = await registerDevice(publicKey, defaultDeviceLabel());

      localStorage.setItem(PUBLIC_KEY_STORAGE_KEY, publicKey);
      localStorage.setItem(PRIVATE_KEY_STORAGE_KEY, privateKey);
      localStorage.setItem(DEVICE_ID_STORAGE_KEY, deviceId);

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
  return localStorage.getItem(DEVICE_ID_STORAGE_KEY);
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
  try {
    const ciphertext = sodium.from_base64(ciphertextBase64, sodium.base64_variants.ORIGINAL);
    const nonce = sodium.from_base64(nonceBase64, sodium.base64_variants.ORIGINAL);
    const otherPartyPublicKey = sodium.from_base64(otherPartyPublicKeyBase64, sodium.base64_variants.ORIGINAL);
    const myPrivateKey = sodium.from_base64(myPrivateKeyBase64, sodium.base64_variants.ORIGINAL);

    const plaintextBytes = sodium.crypto_box_open_easy(ciphertext, nonce, otherPartyPublicKey, myPrivateKey);
    return sodium.to_string(plaintextBytes);
  } catch {
    return null;
  }
}
