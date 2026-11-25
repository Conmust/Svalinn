// Double Ratchet end-to-end encryption, layered ALONGSIDE (not replacing)
// the stateless per-device `crypto.ts` path: `crypto.ts` is simple and
// correct but gives up forward secrecy and post-compromise security the
// moment a device's long-term private key is ever exposed, because every
// message to/from that device is encrypted under the SAME keypair forever.
// This module gives each (device, peer device) pair its own session whose
// keys keep changing -- a signed-prekey-based X3DH-style handshake
// bootstraps a shared secret the first time two devices talk, and a
// Double Ratchet (symmetric-key ratchet + Diffie-Hellman ratchet) evolves
// that secret on every message afterward, so compromising today's key
// never un-does yesterday's privacy (forward secrecy) and never
// compromises tomorrow's either, once both sides ratchet again
// (post-compromise security / "healing").
//
// Scope, deliberately: this implements the CORE Double Ratchet + an
// X3DH-style bootstrap, matching Signal's published algorithm, but does
// NOT implement XEdDSA (reusing one Curve25519 key for both ECDH and
// signing). Instead each device has two separate identity keypairs: the
// existing X25519 keypair from `crypto.ts` (Diffie-Hellman only, exactly
// as today) and a NEW Ed25519 keypair, generated and managed entirely by
// this module, used ONLY to sign this device's own signed prekey. That is
// a deliberate scoping decision, not an oversight -- XEdDSA needs careful,
// specialized handling to be safe, and a second keypair sidesteps that
// entirely at the cost of one extra public key per device.
//
// Per-session local state lives in `localStorage`
// (`svalinn_ratchet_session_<peerDeviceId>`), same as `crypto.ts`'s device
// keypair -- it's the fast, authoritative copy. The server additionally
// holds a best-effort ENCRYPTED backup of it (see `backupSession` and
// migration 0038's `ratchet_sessions` table), purely for recovery if this
// device's local storage is ever cleared while its long-term identity key
// (which the backup's encryption key is deterministically derived from)
// survives. The server never sees anything but opaque ciphertext.
import sodium from 'libsodium-wrappers-sumo';
import { ensureDeviceKeypair, DeviceSetupError } from './crypto';
import {
  setSigningKey,
  uploadPrekeys,
  fetchPrekeyCounts,
  fetchPrekeyBundle,
  fetchRatchetSession,
  putRatchetSession,
  RatchetNotSupportedError,
  NoRatchetSessionError,
  RatchetSessionConflictError,
  type PrekeyUpload,
  type PrekeyBundle,
} from './devices';

export { RatchetNotSupportedError };

// --- Base64 helpers (same ORIGINAL variant/convention as crypto.ts) -------

function b64(bytes: Uint8Array): string {
  return sodium.to_base64(bytes, sodium.base64_variants.ORIGINAL);
}
function fromB64(str: string): Uint8Array {
  return sodium.from_base64(str, sodium.base64_variants.ORIGINAL);
}

// --- Distinct failure modes ------------------------------------------------

/** A device's signed-prekey bundle carried a signature that didn't verify
 * against its claimed signing identity key -- either a corrupted bundle or
 * an impersonation attempt. Refusing to bootstrap a session from it is the
 * entire point of signing the prekey in the first place. */
export class RatchetVerificationError extends Error {
  constructor(message = "A device's signed prekey signature failed verification.") {
    super(message);
    this.name = 'RatchetVerificationError';
  }
}

/** A message claimed a sender position far enough ahead of what we've seen
 * that honoring it would mean deriving (and storing) an unbounded number
 * of skipped message keys -- almost certainly a corrupted/malicious
 * message or a badly desynced session, not a legitimate large gap. */
export class RatchetTooManySkippedMessagesError extends Error {
  constructor(message = 'Refusing to skip an unreasonable number of message keys.') {
    super(message);
    this.name = 'RatchetTooManySkippedMessagesError';
  }
}

/** `encryptMessage` was called on a session that has never had a send
 * chain established -- i.e. we're the responder in a brand-new session
 * and haven't decrypted anything from the peer yet. Per the Double
 * Ratchet algorithm, a responder can't send until it has received (the DH
 * ratchet step triggered by the first incoming message is what gives it a
 * send chain at all). Callers should wait for an incoming message first. */
export class RatchetSendBeforeReceiveError extends Error {
  constructor(message = "Can't send yet -- no message has been received on this session to ratchet a send chain from.") {
    super(message);
    this.name = 'RatchetSendBeforeReceiveError';
  }
}

// --- HKDF (RFC 5869), built on crypto_auth_hmacsha256 ---------------------
//
// libsodium-wrappers-sumo doesn't expose HKDF directly, but HMAC-SHA256 is
// all it's built from. `crypto_auth_hmacsha256(message, key)` requires an
// exactly-32-byte key -- which every key used below (root keys, chain
// keys, PRKs) always is, since they're either freshly generated 32-byte
// values or the output of this same HKDF.

function hmac(key: Uint8Array, data: Uint8Array): Uint8Array {
  return sodium.crypto_auth_hmacsha256(data, key);
}

/** HKDF-Expand: stretches a pseudorandom key into `length` bytes of
 * output, bound to `info` so different purposes (root KDF vs. the pickle
 * backup key, say) never collide even if fed the same `prk`. */
function hkdfExpand(prk: Uint8Array, info: string, length: number): Uint8Array {
  const infoBytes = sodium.from_string(info);
  const out = new Uint8Array(length);
  let generated = 0;
  let previousBlock: Uint8Array = new Uint8Array(0);
  let counter = 1;
  while (generated < length) {
    const input = new Uint8Array(previousBlock.length + infoBytes.length + 1);
    input.set(previousBlock, 0);
    input.set(infoBytes, previousBlock.length);
    input[previousBlock.length + infoBytes.length] = counter;
    previousBlock = hmac(prk, input);
    const take = Math.min(previousBlock.length, length - generated);
    out.set(previousBlock.subarray(0, take), generated);
    generated += take;
    counter += 1;
  }
  return out;
}

// --- Double Ratchet KDFs (Signal's reference algorithm) -------------------

/** The root KDF: mixes a fresh DH output into the root key, producing a
 * new root key plus a fresh chain key. Run once per DH ratchet step (so,
 * roughly, once per "turn" of the conversation switching direction). */
function kdfRootKey(rootKey: Uint8Array, dhOutput: Uint8Array): { rootKey: Uint8Array; chainKey: Uint8Array } {
  const prk = hmac(rootKey, dhOutput); // HKDF-Extract: HMAC(salt=rootKey, ikm=dhOutput)
  const okm = hkdfExpand(prk, 'SvalinnRatchetRootKDF', 64);
  return { rootKey: okm.slice(0, 32), chainKey: okm.slice(32, 64) };
}

/** The chain KDF: derives the next chain key and this message's key from
 * the current chain key, using fixed single-byte constants (0x01/0x02)
 * exactly as Signal's spec does. Run once per MESSAGE sent or received
 * within a chain -- this is what gives every message its own unique key
 * without a fresh DH exchange each time. */
function kdfChainKey(chainKey: Uint8Array): { chainKey: Uint8Array; messageKey: Uint8Array } {
  const messageKey = hmac(chainKey, new Uint8Array([0x01]));
  const nextChainKey = hmac(chainKey, new Uint8Array([0x02]));
  return { chainKey: nextChainKey, messageKey };
}

function dh(myPrivateKey: Uint8Array, theirPublicKey: Uint8Array): Uint8Array {
  return sodium.crypto_scalarmult(myPrivateKey, theirPublicKey);
}

function generateRatchetKeypair(): { publicKey: Uint8Array; privateKey: Uint8Array } {
  return sodium.crypto_box_keypair();
}

/** Puts two identity public keys into a fixed order regardless of which
 * one belongs to "me" -- so both participants compute the exact same
 * associated-data bytes for AEAD, without needing to agree in advance on
 * who's "first". */
function canonicalPair(a: Uint8Array, b: Uint8Array): { low: Uint8Array; high: Uint8Array } {
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return a[i] < b[i] ? { low: a, high: b } : { low: b, high: a };
  }
  return { low: a, high: b };
}

function buildAD(state: RatchetState): Uint8Array {
  const low = fromB64(state.adLow);
  const high = fromB64(state.adHigh);
  const out = new Uint8Array(low.length + high.length);
  out.set(low, 0);
  out.set(high, low.length);
  return out;
}

const MAX_SKIPPED_MESSAGE_KEYS = 1000;

// --- Session state ----------------------------------------------------

/** The full local state of one Double Ratchet session -- one device's own
 * view of its conversation with ONE specific peer device. Every field is
 * plain JSON-serializable data (binary values as base64) so it can be
 * stored in `localStorage` and, encrypted as a whole, backed up
 * server-side. See this file's header comment on why this is per
 * (device, peer device), never shared between the two devices in it. */
export interface RatchetState {
  /** This device's current ratchet keypair -- regenerated every time we
   * take a DH ratchet step (i.e. every time the conversation's "turn"
   * passes back to us after the peer has sent at least one message). */
  dhsPublic: string;
  dhsPrivate: string;
  /** The peer's last-known ratchet public key, or null if we've never
   * received anything from them yet (true only for a brand-new session
   * where we're the initiator and haven't gotten a reply). */
  dhrPublic: string | null;
  rootKey: string;
  /** Null until this device has something to send with: the initiator
   * gets one immediately (from the X3DH handshake); the responder only
   * gets one once it's processed an incoming message and taken its own DH
   * ratchet step in response. */
  chainKeySend: string | null;
  /** Null until this device has received at least one message. */
  chainKeyRecv: string | null;
  /** Messages sent in the current sending chain. */
  sendCount: number;
  /** Messages received in the current receiving chain. */
  recvCount: number;
  /** Length of the PREVIOUS sending chain, carried in every message's
   * header so the peer knows how many messages to skip-and-cache from
   * their old receiving chain before ratcheting, in case any are still in
   * flight out of order. */
  previousChainLength: number;
  /** Cached message keys for messages that arrived out of order (skipped
   * over at the time, kept around so they can still be decrypted if/when
   * they eventually show up), keyed by `${senderRatchetPublicKeyB64}:${n}`.
   * Each one is consumed (deleted) the moment it's used, so a replay of
   * the same ciphertext can't be decrypted twice. */
  skippedKeys: Record<string, string>;
  /** Set only on the very first message WE send as the session's
   * initiator, carrying the X3DH fields (our identity key, our ephemeral
   * key, which one-time prekey we consumed) the peer needs to bootstrap
   * their own side from that one message -- then cleared immediately
   * after, since no later message needs to repeat them. */
  pendingInitialHeader: InitialHandshakeFields | null;
  /** The two participants' identity public keys, canonically ordered (see
   * `canonicalPair`) so both sides derive identical AEAD associated data
   * -- binds every ciphertext to this specific pair of identities so it
   * can never be replayed into a different conversation. */
  adLow: string;
  adHigh: string;
  /** `updated_at` of this session's last successful server-side backup, or
   * null if it's never been backed up -- passed as `expected_updated_at`
   * on the next backup so a concurrent write from another tab (or a
   * backup race) is caught as a conflict rather than silently clobbered.
   * See `backupSession`. */
  backupUpdatedAt: string | null;
}

/** The X3DH-style handshake fields a session's INITIATOR must send, once,
 * attached to their first message -- everything the responder needs to
 * derive the same shared secret, since they can't fetch a "prekey bundle"
 * for someone who's never published one back. */
export interface InitialHandshakeFields {
  identityPublicKey: string;
  ephemeralPublicKey: string;
  usedOneTimePrekeyPublicKey: string | null;
}

/** What actually travels with a Double Ratchet-encrypted message. `dh`,
 * `pn`, `n` are the per-message ratchet header Signal's algorithm
 * specifies; `initial` is present only on a session's very first message
 * (see `InitialHandshakeFields`). */
export interface RatchetEnvelope {
  dh: string;
  pn: number;
  n: number;
  ciphertext: string;
  nonce: string;
  initial?: InitialHandshakeFields;
}

function initRatchetAsInitiator(
  sharedKey: Uint8Array,
  theirSignedPrekeyPublic: Uint8Array,
  myIdentityPublicKey: Uint8Array,
  peerIdentityPublicKey: Uint8Array,
  pendingInitialHeader: InitialHandshakeFields
): RatchetState {
  const dhs = generateRatchetKeypair();
  const { rootKey, chainKey } = kdfRootKey(sharedKey, dh(dhs.privateKey, theirSignedPrekeyPublic));
  const { low, high } = canonicalPair(myIdentityPublicKey, peerIdentityPublicKey);
  return {
    dhsPublic: b64(dhs.publicKey),
    dhsPrivate: b64(dhs.privateKey),
    dhrPublic: b64(theirSignedPrekeyPublic),
    rootKey: b64(rootKey),
    chainKeySend: b64(chainKey),
    chainKeyRecv: null,
    sendCount: 0,
    recvCount: 0,
    previousChainLength: 0,
    skippedKeys: {},
    pendingInitialHeader,
    adLow: b64(low),
    adHigh: b64(high),
    backupUpdatedAt: null,
  };
}

function initRatchetAsResponder(
  sharedKey: Uint8Array,
  myRatchetKeypair: { publicKey: Uint8Array; privateKey: Uint8Array },
  myIdentityPublicKey: Uint8Array,
  peerIdentityPublicKey: Uint8Array
): RatchetState {
  const { low, high } = canonicalPair(myIdentityPublicKey, peerIdentityPublicKey);
  return {
    dhsPublic: b64(myRatchetKeypair.publicKey),
    dhsPrivate: b64(myRatchetKeypair.privateKey),
    dhrPublic: null,
    rootKey: b64(sharedKey),
    chainKeySend: null,
    chainKeyRecv: null,
    sendCount: 0,
    recvCount: 0,
    previousChainLength: 0,
    skippedKeys: {},
    pendingInitialHeader: null,
    adLow: b64(low),
    adHigh: b64(high),
    backupUpdatedAt: null,
  };
}

/** Advances a session's SENDING chain by one message. Returns a new state
 * (never mutates the one passed in) alongside the envelope fields the
 * caller should actually transmit. */
function ratchetEncrypt(
  state: RatchetState,
  plaintext: string
): { state: RatchetState; dh: string; pn: number; n: number; ciphertext: string; nonce: string } {
  if (!state.chainKeySend) {
    throw new RatchetSendBeforeReceiveError();
  }
  const { chainKey: nextChainKey, messageKey } = kdfChainKey(fromB64(state.chainKeySend));
  const n = state.sendCount;
  const pn = state.previousChainLength;
  const ad = buildAD(state);
  const nonceBytes = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  const ciphertextBytes = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    sodium.from_string(plaintext),
    ad,
    null,
    nonceBytes,
    messageKey
  );
  const newState: RatchetState = { ...state, chainKeySend: b64(nextChainKey), sendCount: n + 1 };
  return { state: newState, dh: state.dhsPublic, pn, n, ciphertext: b64(ciphertextBytes), nonce: b64(nonceBytes) };
}

/** Derives and caches message keys for every message index in the current
 * receiving chain up to (but not including) `untilN`, for messages that
 * may still arrive out of order. A no-op if there's no receiving chain yet
 * (a brand-new responder session that hasn't taken its first DH ratchet
 * step) -- there's nothing to skip ahead of. */
function skipMessageKeys(state: RatchetState, untilN: number): RatchetState {
  if (state.chainKeyRecv === null) return state;
  if (untilN - state.recvCount > MAX_SKIPPED_MESSAGE_KEYS) {
    throw new RatchetTooManySkippedMessagesError();
  }
  let chainKey = fromB64(state.chainKeyRecv);
  const skippedKeys = { ...state.skippedKeys };
  let recvCount = state.recvCount;
  const dhrPublic = state.dhrPublic as string;
  while (recvCount < untilN) {
    const derived = kdfChainKey(chainKey);
    skippedKeys[`${dhrPublic}:${recvCount}`] = b64(derived.messageKey);
    chainKey = derived.chainKey;
    recvCount += 1;
  }
  return { ...state, chainKeyRecv: b64(chainKey), recvCount, skippedKeys };
}

/** Takes a DH ratchet step on receipt of a message from a new ratchet
 * public key: derives a fresh receiving chain from the DH of our current
 * (about-to-be-replaced) keypair with their new one, then generates a
 * fresh keypair of our own and derives a fresh sending chain from THAT --
 * so by the time this returns, we're ready to both finish decrypting (via
 * the new receiving chain) and reply (via the new sending chain). */
function performDhRatchet(state: RatchetState, theirNewDhPublicB64: string): RatchetState {
  const theirNewDhPublic = fromB64(theirNewDhPublicB64);
  const afterReceive = kdfRootKey(fromB64(state.rootKey), dh(fromB64(state.dhsPrivate), theirNewDhPublic));
  const newDhs = generateRatchetKeypair();
  const afterSend = kdfRootKey(afterReceive.rootKey, dh(newDhs.privateKey, theirNewDhPublic));
  return {
    ...state,
    dhrPublic: theirNewDhPublicB64,
    rootKey: b64(afterSend.rootKey),
    chainKeyRecv: b64(afterReceive.chainKey),
    chainKeySend: b64(afterSend.chainKey),
    previousChainLength: state.sendCount,
    sendCount: 0,
    recvCount: 0,
    dhsPublic: b64(newDhs.publicKey),
    dhsPrivate: b64(newDhs.privateKey),
  };
}

/** Attempts to decrypt a message using an already-cached skipped message
 * key, for a message that arrived out of order relative to ones already
 * processed. Returns null if no cached key matches (the normal case for
 * an in-order message) or if decryption with a matching key still fails
 * (tampered ciphertext). */
function tryDecryptWithSkippedKey(
  state: RatchetState,
  envelope: RatchetEnvelope,
  ad: Uint8Array
): { state: RatchetState; plaintext: string } | null {
  const key = `${envelope.dh}:${envelope.n}`;
  const messageKeyB64 = state.skippedKeys[key];
  if (!messageKeyB64) return null;
  try {
    const plaintextBytes = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      fromB64(envelope.ciphertext),
      ad,
      fromB64(envelope.nonce),
      fromB64(messageKeyB64)
    );
    const skippedKeys = { ...state.skippedKeys };
    delete skippedKeys[key];
    return { state: { ...state, skippedKeys }, plaintext: sodium.to_string(plaintextBytes) };
  } catch {
    return null;
  }
}

/** Advances a session on receipt of a message, taking a DH ratchet step
 * first if needed. Returns the new state (to persist) and the decrypted
 * plaintext, or null if decryption genuinely failed (tampered ciphertext,
 * wrong key) -- in which case the ORIGINAL state should be kept, since
 * nothing about the session actually advanced. */
function ratchetDecrypt(state: RatchetState, envelope: RatchetEnvelope): { state: RatchetState; plaintext: string } | null {
  const ad = buildAD(state);

  const fromSkipped = tryDecryptWithSkippedKey(state, envelope, ad);
  if (fromSkipped) return fromSkipped;

  let working = state;
  if (envelope.dh !== working.dhrPublic) {
    working = skipMessageKeys(working, envelope.pn);
    working = performDhRatchet(working, envelope.dh);
  }
  working = skipMessageKeys(working, envelope.n);

  if (!working.chainKeyRecv) return null; // malformed/out-of-protocol state; nothing sane to decrypt with
  const { chainKey: nextChainKey, messageKey } = kdfChainKey(fromB64(working.chainKeyRecv));
  working = { ...working, chainKeyRecv: b64(nextChainKey), recvCount: working.recvCount + 1 };

  try {
    const plaintextBytes = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      fromB64(envelope.ciphertext),
      ad,
      fromB64(envelope.nonce),
      messageKey
    );
    return { state: working, plaintext: sodium.to_string(plaintextBytes) };
  } catch {
    return null;
  }
}

// --- X3DH-style session bootstrap -----------------------------------------

const X3DH_INFO = 'SvalinnX3DH';

/** Mixes the (three or four) DH outputs from an X3DH handshake into one
 * 32-byte shared secret. A zero salt is standard practice for X3DH when,
 * as here, there's no separately-agreed salt value to use instead -- the
 * secrecy comes entirely from the DH outputs themselves, which neither
 * party could compute without one of the private keys involved. */
function deriveX3DHSharedKey(dh1: Uint8Array, dh2: Uint8Array, dh3: Uint8Array, dh4: Uint8Array | null): Uint8Array {
  const parts = dh4 ? [dh1, dh2, dh3, dh4] : [dh1, dh2, dh3];
  const ikm = new Uint8Array(parts.reduce((sum, p) => sum + p.length, 0));
  let offset = 0;
  for (const part of parts) {
    ikm.set(part, offset);
    offset += part.length;
  }
  const zeroSalt = new Uint8Array(sodium.crypto_auth_hmacsha256_KEYBYTES);
  const prk = hmac(zeroSalt, ikm);
  return hkdfExpand(prk, X3DH_INFO, 32);
}

function verifySignedPrekey(bundle: PrekeyBundle): void {
  const verified = sodium.crypto_sign_verify_detached(
    fromB64(bundle.signedPrekeySignature),
    fromB64(bundle.signedPrekeyPublicKey),
    fromB64(bundle.identitySigningPublicKey)
  );
  if (!verified) {
    throw new RatchetVerificationError();
  }
}

/** Bootstraps a brand-new session as the INITIATOR: fetches `peerDeviceId`'s
 * published prekey bundle, verifies its signature, runs the X3DH DH
 * computations, and derives the session's initial state. The caller (see
 * `encryptMessage`) is responsible for attaching the resulting
 * `pendingInitialHeader` to the first actual message sent. */
async function bootstrapSessionAsInitiator(peerDeviceId: string): Promise<RatchetState> {
  const bundle = await fetchPrekeyBundle(peerDeviceId);
  verifySignedPrekey(bundle);

  const { publicKey: myIdentityPublicKeyB64, privateKey: myIdentityPrivateKeyB64 } = await ensureDeviceKeypair();
  const myIdentityPrivateKey = fromB64(myIdentityPrivateKeyB64);
  const myIdentityPublicKey = fromB64(myIdentityPublicKeyB64);
  const ephemeral = generateRatchetKeypair();

  const theirIdentityPublic = fromB64(bundle.identityPublicKey);
  const theirSignedPrekeyPublic = fromB64(bundle.signedPrekeyPublicKey);
  const theirOneTimePrekeyPublic = bundle.oneTimePrekeyPublicKey ? fromB64(bundle.oneTimePrekeyPublicKey) : null;

  const dh1 = dh(myIdentityPrivateKey, theirSignedPrekeyPublic);
  const dh2 = dh(ephemeral.privateKey, theirIdentityPublic);
  const dh3 = dh(ephemeral.privateKey, theirSignedPrekeyPublic);
  const dh4 = theirOneTimePrekeyPublic ? dh(ephemeral.privateKey, theirOneTimePrekeyPublic) : null;
  const sharedKey = deriveX3DHSharedKey(dh1, dh2, dh3, dh4);

  const pendingInitialHeader: InitialHandshakeFields = {
    identityPublicKey: myIdentityPublicKeyB64,
    ephemeralPublicKey: b64(ephemeral.publicKey),
    usedOneTimePrekeyPublicKey: bundle.oneTimePrekeyPublicKey,
  };

  return initRatchetAsInitiator(sharedKey, theirSignedPrekeyPublic, myIdentityPublicKey, theirIdentityPublic, pendingInitialHeader);
}

/** Bootstraps a brand-new session as the RESPONDER, from the X3DH fields
 * carried on an incoming message's `initial` block. Mirrors the
 * initiator's DH computations using this device's own locally-held signed
 * prekey (and, if referenced and still available, one-time prekey)
 * private keys -- see this file's header comment on why those private
 * keys have to be kept locally rather than only published. */
async function establishSessionAsResponder(peerDeviceId: string, initial: InitialHandshakeFields): Promise<RatchetState> {
  const signedPrekeyPublic = localStorage.getItem(SIGNED_PREKEY_PUBLIC_KEY_STORAGE_KEY);
  const signedPrekeyPrivate = localStorage.getItem(SIGNED_PREKEY_PRIVATE_KEY_STORAGE_KEY);
  if (!signedPrekeyPublic || !signedPrekeyPrivate) {
    throw new DeviceSetupError('This device has no local signed prekey to bootstrap a ratchet session with.');
  }

  const oneTimePrekeyPrivate = initial.usedOneTimePrekeyPublicKey
    ? findAndConsumeLocalOneTimePrekey(initial.usedOneTimePrekeyPublicKey)
    : null;
  if (initial.usedOneTimePrekeyPublicKey && !oneTimePrekeyPrivate) {
    // Evicted locally (see `maintainOneTimePrekeys`'s bounded FIFO) or
    // already consumed by a previous handshake. Not fatal -- X3DH still
    // provides a secure handshake from the other three DH outputs alone,
    // just without that one-time key's extra forward-secrecy margin.
    console.warn('Referenced one-time prekey is no longer available locally; falling back to a 3-DH X3DH handshake.');
  }

  const { publicKey: myIdentityPublicKeyB64, privateKey: myIdentityPrivateKeyB64 } = await ensureDeviceKeypair();
  const myIdentityPrivateKey = fromB64(myIdentityPrivateKeyB64);
  const myIdentityPublicKey = fromB64(myIdentityPublicKeyB64);
  const mySignedPrekeyPrivate = fromB64(signedPrekeyPrivate);
  const mySignedPrekeyPublic = fromB64(signedPrekeyPublic);

  const theirIdentityPublic = fromB64(initial.identityPublicKey);
  const theirEphemeralPublic = fromB64(initial.ephemeralPublicKey);

  // Mirrors the initiator's DH1-DH4 exactly, with the two sides of each
  // DH swapped -- X25519 is symmetric, so these equal the initiator's
  // values one-for-one.
  const dh1 = dh(mySignedPrekeyPrivate, theirIdentityPublic);
  const dh2 = dh(myIdentityPrivateKey, theirEphemeralPublic);
  const dh3 = dh(mySignedPrekeyPrivate, theirEphemeralPublic);
  const dh4 = oneTimePrekeyPrivate ? dh(oneTimePrekeyPrivate, theirEphemeralPublic) : null;
  const sharedKey = deriveX3DHSharedKey(dh1, dh2, dh3, dh4);

  const state = initRatchetAsResponder(
    sharedKey,
    { publicKey: mySignedPrekeyPublic, privateKey: mySignedPrekeyPrivate },
    myIdentityPublicKey,
    theirIdentityPublic
  );
  void peerDeviceId; // not needed for derivation itself -- kept for symmetry/callers
  return state;
}

// --- Identity & prekey lifecycle (local storage + server publication) -----

const SIGNING_PUBLIC_KEY_STORAGE_KEY = 'svalinn_ratchet_signing_public_key';
const SIGNING_PRIVATE_KEY_STORAGE_KEY = 'svalinn_ratchet_signing_private_key';
const SIGNED_PREKEY_PUBLIC_KEY_STORAGE_KEY = 'svalinn_ratchet_signed_prekey_public_key';
const SIGNED_PREKEY_PRIVATE_KEY_STORAGE_KEY = 'svalinn_ratchet_signed_prekey_private_key';
const SIGNED_PREKEY_CREATED_AT_STORAGE_KEY = 'svalinn_ratchet_signed_prekey_created_at';
const ONE_TIME_PREKEYS_STORAGE_KEY = 'svalinn_ratchet_one_time_prekeys';

const SIGNED_PREKEY_ROTATE_INTERVAL_MS = 7 * 24 * 60 * 60 * 1000;
const ONE_TIME_PREKEY_LOW_WATER_MARK = 10;
const ONE_TIME_PREKEY_REPLENISH_BATCH = 20;
/** Mirrors the server's own `MAX_UNCONSUMED_ONE_TIME_PREKEYS` cap
 * (`routes/devices.rs`) -- keeping this device's local stash bounded to
 * roughly the same size the server will ever actually be holding
 * unconsumed prekeys for. See `establishSessionAsResponder`'s fallback
 * for what happens on the rare eviction of a still-referenced key. */
const MAX_LOCAL_ONE_TIME_PREKEYS = 200;

interface StoredOneTimePrekey {
  publicKey: string;
  privateKey: string;
}

function loadOneTimePrekeys(): StoredOneTimePrekey[] {
  try {
    const raw = localStorage.getItem(ONE_TIME_PREKEYS_STORAGE_KEY);
    return raw ? (JSON.parse(raw) as StoredOneTimePrekey[]) : [];
  } catch {
    return [];
  }
}

function storeOneTimePrekeys(keys: StoredOneTimePrekey[]): void {
  try {
    localStorage.setItem(ONE_TIME_PREKEYS_STORAGE_KEY, JSON.stringify(keys));
  } catch {
    // Best-effort -- see crypto.ts's `checkStorageAvailable` precedent;
    // a broken store here just means fewer one-time prekeys available
    // locally, not a correctness problem (X3DH degrades gracefully).
  }
}

function findAndConsumeLocalOneTimePrekey(publicKey: string): Uint8Array | null {
  const keys = loadOneTimePrekeys();
  const idx = keys.findIndex((k) => k.publicKey === publicKey);
  if (idx === -1) return null;
  const [found] = keys.splice(idx, 1);
  storeOneTimePrekeys(keys);
  return fromB64(found.privateKey);
}

async function ensureSigningIdentity(deviceId: string): Promise<{ publicKey: string; privateKey: string }> {
  const existingPublic = localStorage.getItem(SIGNING_PUBLIC_KEY_STORAGE_KEY);
  const existingPrivate = localStorage.getItem(SIGNING_PRIVATE_KEY_STORAGE_KEY);
  if (existingPublic && existingPrivate) return { publicKey: existingPublic, privateKey: existingPrivate };

  const kp = sodium.crypto_sign_keypair();
  const publicKey = b64(kp.publicKey);
  const privateKey = b64(kp.privateKey);
  await setSigningKey(deviceId, publicKey);
  try {
    localStorage.setItem(SIGNING_PUBLIC_KEY_STORAGE_KEY, publicKey);
    localStorage.setItem(SIGNING_PRIVATE_KEY_STORAGE_KEY, privateKey);
  } catch {
    throw new DeviceSetupError(
      "This device cannot store its ratchet signing key (local storage is unavailable, full, or disabled)."
    );
  }
  return { publicKey, privateKey };
}

async function ensureSignedPrekey(deviceId: string, signingPrivateKey: Uint8Array): Promise<void> {
  const existingPublic = localStorage.getItem(SIGNED_PREKEY_PUBLIC_KEY_STORAGE_KEY);
  const existingPrivate = localStorage.getItem(SIGNED_PREKEY_PRIVATE_KEY_STORAGE_KEY);
  const createdAt = Number(localStorage.getItem(SIGNED_PREKEY_CREATED_AT_STORAGE_KEY) ?? '0');
  const isFresh = Boolean(existingPublic) && Boolean(existingPrivate) && Date.now() - createdAt < SIGNED_PREKEY_ROTATE_INTERVAL_MS;
  if (isFresh) return;

  const kp = generateRatchetKeypair();
  const publicKey = b64(kp.publicKey);
  const privateKey = b64(kp.privateKey);
  const signature = b64(sodium.crypto_sign_detached(kp.publicKey, signingPrivateKey));
  await uploadPrekeys(deviceId, [{ keyType: 'signed', publicKey, signature }]);
  try {
    localStorage.setItem(SIGNED_PREKEY_PUBLIC_KEY_STORAGE_KEY, publicKey);
    localStorage.setItem(SIGNED_PREKEY_PRIVATE_KEY_STORAGE_KEY, privateKey);
    localStorage.setItem(SIGNED_PREKEY_CREATED_AT_STORAGE_KEY, String(Date.now()));
  } catch {
    throw new DeviceSetupError(
      "This device cannot store its ratchet signed prekey (local storage is unavailable, full, or disabled)."
    );
  }
}

async function maintainOneTimePrekeys(deviceId: string): Promise<void> {
  const counts = await fetchPrekeyCounts(deviceId);
  if (counts.unconsumedOneTimePrekeys >= ONE_TIME_PREKEY_LOW_WATER_MARK) return;

  const newKeys: StoredOneTimePrekey[] = [];
  const uploads: PrekeyUpload[] = [];
  for (let i = 0; i < ONE_TIME_PREKEY_REPLENISH_BATCH; i++) {
    const kp = generateRatchetKeypair();
    const publicKey = b64(kp.publicKey);
    newKeys.push({ publicKey, privateKey: b64(kp.privateKey) });
    uploads.push({ keyType: 'one_time', publicKey });
  }
  await uploadPrekeys(deviceId, uploads);

  const merged = [...loadOneTimePrekeys(), ...newKeys];
  const bounded = merged.length > MAX_LOCAL_ONE_TIME_PREKEYS ? merged.slice(merged.length - MAX_LOCAL_ONE_TIME_PREKEYS) : merged;
  storeOneTimePrekeys(bounded);
}

/** Sets this device up for the Double Ratchet, idempotently: generates (or
 * reuses) its signing identity, makes sure it has a current signed
 * prekey, and tops up its one-time prekey stash if it's running low.
 * Safe to call on every app startup, alongside `ensureDeviceKeypair()`. */
export async function ensureRatchetReady(): Promise<void> {
  await sodium.ready;
  const { deviceId } = await ensureDeviceKeypair();
  const signing = await ensureSigningIdentity(deviceId);
  await ensureSignedPrekey(deviceId, fromB64(signing.privateKey));
  await maintainOneTimePrekeys(deviceId);
}

// --- Session persistence (local cache + best-effort encrypted backup) -----

function sessionStorageKey(peerDeviceId: string): string {
  return `svalinn_ratchet_session_${peerDeviceId}`;
}

function loadLocalSession(peerDeviceId: string): RatchetState | null {
  try {
    const raw = localStorage.getItem(sessionStorageKey(peerDeviceId));
    return raw ? (JSON.parse(raw) as RatchetState) : null;
  } catch {
    return null;
  }
}

function storeLocalSession(peerDeviceId: string, state: RatchetState): void {
  try {
    localStorage.setItem(sessionStorageKey(peerDeviceId), JSON.stringify(state));
  } catch {
    // Best-effort, same as everywhere else in this module -- a message
    // already in flight shouldn't fail just because the backup/cache
    // write did. Correctness for THIS message doesn't depend on the
    // write succeeding; only future messages (and recovery) would.
  }
}

/** Deterministically derives this device's pickle-encryption key from its
 * own long-term identity private key via HKDF -- never stored separately
 * (there'd be nothing gained by storing another secret derived from a
 * secret already being stored), and never shared with any other device,
 * since each device's identity private key is unique to it. */
function derivePickleKey(identityPrivateKey: Uint8Array): Uint8Array {
  const zeroSalt = new Uint8Array(sodium.crypto_auth_hmacsha256_KEYBYTES);
  const prk = hmac(zeroSalt, identityPrivateKey);
  return hkdfExpand(prk, 'SvalinnRatchetPickleKey', sodium.crypto_secretbox_KEYBYTES);
}

/** Pushes this device's own encrypted backup of a session to the server.
 * Best-effort: a failure here never blocks sending or receiving, since
 * the authoritative copy is always the local one (see `storeLocalSession`,
 * called first by `saveSession`, unconditionally). */
async function backupSession(myDeviceId: string, peerDeviceId: string, state: RatchetState): Promise<void> {
  const { privateKey } = await ensureDeviceKeypair();
  const pickleKey = derivePickleKey(fromB64(privateKey));
  const nonceBytes = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
  const ciphertextBytes = sodium.crypto_secretbox_easy(sodium.from_string(JSON.stringify(state)), nonceBytes, pickleKey);

  try {
    const saved = await putRatchetSession(myDeviceId, peerDeviceId, b64(ciphertextBytes), b64(nonceBytes), state.backupUpdatedAt);
    const current = loadLocalSession(peerDeviceId);
    if (current) storeLocalSession(peerDeviceId, { ...current, backupUpdatedAt: saved.updatedAt });
  } catch (err) {
    if (err instanceof RatchetSessionConflictError) {
      // Our bookkeeping of the backup's `updated_at` is stale (e.g. another
      // tab on this same device backed it up in between) -- resync just
      // that timestamp so the NEXT backup attempt's optimistic-concurrency
      // check succeeds, rather than conflicting forever. The local
      // session's actual ratchet state is unaffected either way.
      try {
        const serverState = await fetchRatchetSession(myDeviceId, peerDeviceId);
        const current = loadLocalSession(peerDeviceId);
        if (current) storeLocalSession(peerDeviceId, { ...current, backupUpdatedAt: serverState.updatedAt });
      } catch {
        /* will just retry blind on the next message */
      }
      return;
    }
    throw err;
  }
}

function saveSession(myDeviceId: string, peerDeviceId: string, state: RatchetState): void {
  storeLocalSession(peerDeviceId, state);
  backupSession(myDeviceId, peerDeviceId, state).catch((err) => {
    console.warn('Failed to back up a ratchet session to the server (local session is still fine):', err);
  });
}

/** Loads a session's local state, falling back to recovering it from the
 * server-side encrypted backup if nothing's cached locally (e.g. local
 * storage was cleared) -- see this file's header comment. Returns null if
 * there's truly no session yet either way. */
async function loadOrRecoverSession(myDeviceId: string, peerDeviceId: string): Promise<RatchetState | null> {
  const local = loadLocalSession(peerDeviceId);
  if (local) return local;

  try {
    const backup = await fetchRatchetSession(myDeviceId, peerDeviceId);
    const { privateKey } = await ensureDeviceKeypair();
    const pickleKey = derivePickleKey(fromB64(privateKey));
    const plaintextBytes = sodium.crypto_secretbox_open_easy(fromB64(backup.pickleCiphertext), fromB64(backup.pickleNonce), pickleKey);
    const state = JSON.parse(sodium.to_string(plaintextBytes)) as RatchetState;
    state.backupUpdatedAt = backup.updatedAt;
    storeLocalSession(peerDeviceId, state);
    return state;
  } catch (err) {
    if (err instanceof NoRatchetSessionError) return null;
    console.warn('Failed to recover a ratchet session from its server-side backup:', err);
    return null;
  }
}

// --- Public send/receive API ----------------------------------------------

/** Encrypts `plaintext` for `peerDeviceId`, establishing a brand-new
 * session via the X3DH-style handshake first if none exists yet. Throws
 * `RatchetNotSupportedError` if the peer device hasn't opted into the
 * Double Ratchet (no published signed prekey) -- callers should catch
 * that and fall back to `crypto.ts`'s stateless per-device encryption. */
export async function encryptMessage(peerDeviceId: string, plaintext: string): Promise<RatchetEnvelope> {
  const { deviceId: myDeviceId } = await ensureDeviceKeypair();
  const existing = await loadOrRecoverSession(myDeviceId, peerDeviceId);
  const state = existing ?? (await bootstrapSessionAsInitiator(peerDeviceId));

  const result = ratchetEncrypt(state, plaintext);
  const envelope: RatchetEnvelope = { dh: result.dh, pn: result.pn, n: result.n, ciphertext: result.ciphertext, nonce: result.nonce };

  let newState = result.state;
  if (newState.pendingInitialHeader) {
    envelope.initial = newState.pendingInitialHeader;
    newState = { ...newState, pendingInitialHeader: null };
  }
  saveSession(myDeviceId, peerDeviceId, newState);
  return envelope;
}

/** Decrypts a message from `peerDeviceId`, bootstrapping a session as the
 * RESPONDER first if this is the first message ever received from them
 * (its `initial` block carries what's needed to do so). Returns null --
 * never throws -- for any decryption failure, matching `crypto.ts`'s
 * `decryptFromSender` contract: a bad/tampered message degrades to "can't
 * show this one" rather than crashing the conversation. */
export async function decryptMessage(peerDeviceId: string, envelope: RatchetEnvelope): Promise<string | null> {
  const { deviceId: myDeviceId } = await ensureDeviceKeypair();
  let state = await loadOrRecoverSession(myDeviceId, peerDeviceId);

  if (!state) {
    if (!envelope.initial) {
      console.warn('Received a ratchet message with no local session and no X3DH handshake fields -- cannot decrypt.');
      return null;
    }
    try {
      state = await establishSessionAsResponder(peerDeviceId, envelope.initial);
    } catch (err) {
      console.warn('Failed to bootstrap a ratchet session as responder:', err);
      return null;
    }
  }

  let result: { state: RatchetState; plaintext: string } | null;
  try {
    result = ratchetDecrypt(state, envelope);
  } catch (err) {
    if (err instanceof RatchetTooManySkippedMessagesError) {
      console.warn('Dropping a ratchet message that would require skipping an unreasonable number of keys:', err);
      return null;
    }
    throw err;
  }
  if (!result) return null;

  saveSession(myDeviceId, peerDeviceId, result.state);
  return result.plaintext;
}
