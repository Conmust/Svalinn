// Minimal Node-side mirror of `apps/desktop/src/lib/crypto.ts`'s X25519
// `crypto_box` fan-out encryption, for API-level e2e tests that need to
// send or decrypt a REAL encrypted channel/DM message rather than driving
// the real app through a browser (see `tests/ui/chat.spec.ts` for the
// browser-driven path, which needs none of this -- it uses the app's own
// crypto). Channel messages are mandatory end-to-end encrypted now, so any
// API-level test that sends a channel message needs this to produce
// ciphertext the server will accept at all.
import sodium from 'libsodium-wrappers-sumo';

let readyPromise: Promise<void> | null = null;
export async function ensureSodium(): Promise<void> {
  if (!readyPromise) readyPromise = sodium.ready;
  await readyPromise;
}

const B64 = () => sodium.base64_variants.ORIGINAL;

export interface TestDeviceKeypair {
  publicKey: string;
  privateKey: string;
}

/** Generates a fresh X25519 keypair, base64-encoded the same way the real
 * client does -- this does NOT register it with the server; see
 * `registerDevice` in `api.ts`. */
export async function genKeypair(): Promise<TestDeviceKeypair> {
  await ensureSodium();
  const kp = sodium.crypto_box_keypair();
  return {
    publicKey: sodium.to_base64(kp.publicKey, B64()),
    privateKey: sodium.to_base64(kp.privateKey, B64()),
  };
}

/** Mirrors `lib/crypto.ts`'s `encryptForRecipient`. */
export async function encryptForRecipient(
  plaintext: string,
  recipientPublicKeyB64: string,
  myPrivateKeyB64: string
): Promise<{ ciphertext: string; nonce: string }> {
  await ensureSodium();
  const nonce = sodium.randombytes_buf(sodium.crypto_box_NONCEBYTES);
  const ciphertext = sodium.crypto_box_easy(
    sodium.from_string(plaintext),
    nonce,
    sodium.from_base64(recipientPublicKeyB64, B64()),
    sodium.from_base64(myPrivateKeyB64, B64())
  );
  return {
    ciphertext: sodium.to_base64(ciphertext, B64()),
    nonce: sodium.to_base64(nonce, B64()),
  };
}

/** Mirrors `lib/crypto.ts`'s `decryptFromSender`. Returns `null` on
 * failure instead of throwing, same as the real client. */
export async function decryptFromSender(
  ciphertextB64: string,
  nonceB64: string,
  senderPublicKeyB64: string,
  myPrivateKeyB64: string
): Promise<string | null> {
  await ensureSodium();
  try {
    const plaintext = sodium.crypto_box_open_easy(
      sodium.from_base64(ciphertextB64, B64()),
      sodium.from_base64(nonceB64, B64()),
      sodium.from_base64(senderPublicKeyB64, B64()),
      sodium.from_base64(myPrivateKeyB64, B64())
    );
    return sodium.to_string(plaintext);
  } catch {
    return null;
  }
}

/** Mirrors `lib/crypto.ts`'s `encryptFileForFanout`: one fresh symmetric
 * key, the file encrypted once with it. */
export async function encryptFileForFanout(
  fileBytes: Uint8Array
): Promise<{ ciphertext: Uint8Array; nonce: string; fileKey: Uint8Array }> {
  await ensureSodium();
  const fileKey = sodium.randombytes_buf(sodium.crypto_secretbox_KEYBYTES);
  const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
  const ciphertext = sodium.crypto_secretbox_easy(fileBytes, nonce, fileKey);
  return { ciphertext, nonce: sodium.to_base64(nonce, B64()), fileKey };
}

/** Mirrors `lib/crypto.ts`'s `wrapFileKey` -- `fileKey` is raw bytes, not a
 * UTF-8 string, so this wraps them directly rather than going through
 * `encryptForRecipient`'s string-based API. */
export async function wrapFileKey(
  fileKey: Uint8Array,
  recipientPublicKeyB64: string,
  myPrivateKeyB64: string
): Promise<{ ciphertext: string; nonce: string }> {
  await ensureSodium();
  const nonce = sodium.randombytes_buf(sodium.crypto_box_NONCEBYTES);
  const wrapped = sodium.crypto_box_easy(
    fileKey,
    nonce,
    sodium.from_base64(recipientPublicKeyB64, B64()),
    sodium.from_base64(myPrivateKeyB64, B64())
  );
  return { ciphertext: sodium.to_base64(wrapped, B64()), nonce: sodium.to_base64(nonce, B64()) };
}
