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
  reportConsumedSkippedKey,
  fetchConsumedSkippedKeys,
  RatchetNotSupportedError,
  NoRatchetSessionError,
  RatchetSessionConflictError,
  type PrekeyUpload,
  type PrekeyBundle,
  type ConsumedSkippedKey,
} from './devices';

export { RatchetNotSupportedError };

// --- Base64 helpers (same ORIGINAL variant/convention as crypto.ts) -------
//
// Exported alongside `hmac`/`hkdfExpand` below for reuse by `message-history.ts`,
// which derives its own local encryption key the same deterministic,
// device-identity-derived way `derivePickleKey` does here -- no reason to
// duplicate these tiny, easy-to-get-subtly-wrong primitives in a second
// file.

export function b64(bytes: Uint8Array): string {
  return sodium.to_base64(bytes, sodium.base64_variants.ORIGINAL);
}
export function fromB64(str: string): Uint8Array {
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

export function hmac(key: Uint8Array, data: Uint8Array): Uint8Array {
  return sodium.crypto_auth_hmacsha256(data, key);
}

/** HKDF-Expand: stretches a pseudorandom key into `length` bytes of
 * output, bound to `info` so different purposes (root KDF, the pickle
 * backup key, `message-history.ts`'s own local cache key, say) never
 * collide even if fed the same `prk`. */
export function hkdfExpand(prk: Uint8Array, info: string, length: number): Uint8Array {
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

/** Big-endian 4-byte encoding, for mixing a plain JS number (always well
 * within uint32 range here -- message counts, not anything attacker-sized)
 * into associated data in a fixed, unambiguous width. */
function encodeUint32(n: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n, false);
  return out;
}

/** Builds the AEAD associated data for one message: the session's fixed
 * identity-pair bytes PLUS this specific message's own ratchet header
 * (`dh`, `pn`, `n`) -- binding the header into the same authenticated-data
 * the ciphertext itself is checked against, so tampering with any header
 * field is caught by Poly1305 the same way tampering with the ciphertext
 * already is, rather than relying on it happening to also break key
 * derivation (which it usually -- not always, and not by design -- already
 * did before this). `header` is deliberately the caller's own explicit
 * values, not read off `state`: on receive, that's the INCOMING envelope's
 * header (the thing being authenticated), not this device's own current
 * ratchet position, which is exactly the distinction that makes this
 * binding meaningful. See `ratchetEncrypt`/`ratchetDecrypt` for the two
 * call sites. */
function buildAD(state: RatchetState, header: { dh: string; pn: number; n: number }): Uint8Array {
  const low = fromB64(state.adLow);
  const high = fromB64(state.adHigh);
  const dhBytes = fromB64(header.dh);
  const pnBytes = encodeUint32(header.pn);
  const nBytes = encodeUint32(header.n);
  const out = new Uint8Array(low.length + high.length + dhBytes.length + pnBytes.length + nBytes.length);
  let offset = 0;
  out.set(low, offset);
  offset += low.length;
  out.set(high, offset);
  offset += high.length;
  out.set(dhBytes, offset);
  offset += dhBytes.length;
  out.set(pnBytes, offset);
  offset += pnBytes.length;
  out.set(nBytes, offset);
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
  /** This device's own identity public key at the moment this session was
   * created. A cached session is only ever valid for the identity it was
   * derived under -- its AD and DH math are both bound to it -- so this is
   * compared against the CURRENT identity on every load (see
   * `loadOrRecoverSession`) to catch the case where this device's active
   * identity keypair changes (e.g. `adoptRecoveredKeypair`) while a stale
   * per-peer session, keyed only by peer device id, is left behind.
   * Optional for backward compatibility with sessions persisted before
   * this field existed -- a missing value is treated as "assume valid"
   * rather than forcing every existing session to re-handshake. */
  myIdentityPublicKey?: string;
}

/** The X3DH-style handshake fields a session's INITIATOR must send, once,
 * attached to their first message -- everything the responder needs to
 * derive the same shared secret, since they can't fetch a "prekey bundle"
 * for someone who's never published one back. */
export interface InitialHandshakeFields {
  identityPublicKey: string;
  ephemeralPublicKey: string;
  usedOneTimePrekeyPublicKey: string | null;
  /** Which of the responder's signed prekeys this handshake's dh1/dh3 were
   * actually computed against -- needed because the responder's signed
   * prekey can rotate (weekly) in the time between the initiator fetching
   * a prekey bundle and this message actually being delivered (an offline
   * recipient, a slow retry, ...). Without it, `establishSessionAsResponder`
   * has no way to know whether to answer with its CURRENT signed prekey or
   * a just-retired one it kept around for exactly this (see
   * `ensureSignedPrekey`). Optional for backward compatibility with
   * envelopes from before this field existed -- absent, the responder
   * falls back to assuming its current key, exactly as before. */
  usedSignedPrekeyPublicKey?: string;
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
    myIdentityPublicKey: b64(myIdentityPublicKey),
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
    myIdentityPublicKey: b64(myIdentityPublicKey),
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
  const ad = buildAD(state, { dh: state.dhsPublic, pn, n });
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

/** `viaSkippedKey: true` marks a decrypt that consumed a cached
 * out-of-order message key (`tryDecryptWithSkippedKey`) rather than the
 * normal in-order chain advance -- see `decryptMessageLocked`'s use of it
 * to decide whether this save needs to be backed up eagerly. */
interface RatchetDecryptResult {
  state: RatchetState;
  plaintext: string;
  viaSkippedKey: boolean;
  /** Set only when `viaSkippedKey` is true: identifies exactly which
   * cached slot was consumed, in the same `(dhPublicKey, messageNumber)`
   * terms the server-side consumption ledger (migration 0041) uses -- see
   * `saveSessionEagerly`'s use of it to report the consumption, and
   * `stripConsumedSkippedKeys`'s use of the ledger on recovery. */
  consumedSkippedKeySlot?: { dhPublicKey: string; messageNumber: number };
}

/** Attempts to decrypt a message using an already-cached skipped message
 * key, for a message that arrived out of order relative to ones already
 * processed. Returns null if no cached key matches (the normal case for
 * an in-order message) or if decryption with a matching key still fails
 * (tampered ciphertext). */
function tryDecryptWithSkippedKey(state: RatchetState, envelope: RatchetEnvelope, ad: Uint8Array): RatchetDecryptResult | null {
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
    return {
      state: { ...state, skippedKeys },
      plaintext: sodium.to_string(plaintextBytes),
      viaSkippedKey: true,
      consumedSkippedKeySlot: { dhPublicKey: envelope.dh, messageNumber: envelope.n },
    };
  } catch {
    return null;
  }
}

/** Advances a session on receipt of a message, taking a DH ratchet step
 * first if needed. Returns the new state (to persist) and the decrypted
 * plaintext, or null if decryption genuinely failed (tampered ciphertext,
 * wrong key) -- in which case the ORIGINAL state should be kept, since
 * nothing about the session actually advanced. */
function ratchetDecrypt(state: RatchetState, envelope: RatchetEnvelope): RatchetDecryptResult | null {
  const ad = buildAD(state, { dh: envelope.dh, pn: envelope.pn, n: envelope.n });

  const fromSkipped = tryDecryptWithSkippedKey(state, envelope, ad);
  if (fromSkipped) return fromSkipped;

  let working: RatchetState;
  try {
    working = state;
    if (envelope.dh !== working.dhrPublic) {
      working = skipMessageKeys(working, envelope.pn);
      working = performDhRatchet(working, envelope.dh);
    }
    working = skipMessageKeys(working, envelope.n);
  } catch (err) {
    if (err instanceof RatchetTooManySkippedMessagesError) throw err; // the caller special-cases this one
    // Anything else here means `envelope.dh` (or another header field)
    // doesn't describe a usable ratchet step -- most concretely, a known
    // low-order X25519 point (e.g. all-zero) in `envelope.dh`, which
    // libsodium's `crypto_scalarmult` rejects outright as a "weak public
    // key" rather than returning a value at all. `dh`/`pn`/`n` are now
    // authenticated by `buildAD` above (confidentiality-review followup:
    // "AEAD associated-data not binding the ratchet header fields"), so a
    // genuine peer's own math can never land here -- only a deliberately
    // malformed header can, delivered to ANY recipient without needing to
    // intercept anything, since this runs before the AEAD tag is ever
    // checked. Treated exactly like any other tampered/corrupted message:
    // decryption failed, full stop, same as the AEAD-level catch below --
    // not a crash, not a special case a caller needs to know about.
    return null;
  }

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
    if (working.pendingInitialHeader && working.chainKeyRecv !== null) {
      // This is the initiator's side confirming its FIRST successful
      // decrypt of anything from the peer -- the session is now
      // bidirectionally established, so there's no more need to keep
      // repeating the X3DH handshake fields on every subsequent send (see
      // `encryptMessage`, which otherwise keeps attaching them to every
      // message for as long as they're present, precisely so an
      // unacknowledged retry or an overlapping concurrent first send isn't
      // left without the bootstrap data a fresh responder needs).
      working = { ...working, pendingInitialHeader: null };
    }
    return { state: working, plaintext: sodium.to_string(plaintextBytes), viaSkippedKey: false };
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
    usedSignedPrekeyPublicKey: bundle.signedPrekeyPublicKey,
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
  const currentSignedPrekeyPublic = localStorage.getItem(SIGNED_PREKEY_PUBLIC_KEY_STORAGE_KEY);
  const currentSignedPrekeyPrivate = localStorage.getItem(SIGNED_PREKEY_PRIVATE_KEY_STORAGE_KEY);

  // The sender's handshake may have been bootstrapped against a signed
  // prekey we've since rotated out (fetched before rotation, delivered
  // after -- an offline recipient, a slow retry, or more than one
  // rotation's worth of delay). Answer with whichever local key it
  // actually used, not blindly whatever is current. See
  // `SIGNED_PREKEY_RETIRED_STORAGE_KEY`'s doc for how many retired
  // generations are kept around, and
  // `InitialHandshakeFields.usedSignedPrekeyPublicKey`'s doc for the
  // backward-compatibility fallback when that field is absent.
  let signedPrekeyPublic: string | null = currentSignedPrekeyPublic;
  let signedPrekeyPrivate: string | null = currentSignedPrekeyPrivate;
  if (initial.usedSignedPrekeyPublicKey && initial.usedSignedPrekeyPublicKey !== currentSignedPrekeyPublic) {
    const retiredMatch = loadRetiredSignedPrekeys().find((r) => r.publicKey === initial.usedSignedPrekeyPublicKey);
    if (retiredMatch) {
      signedPrekeyPublic = retiredMatch.publicKey;
      signedPrekeyPrivate = retiredMatch.privateKey;
    }
  }
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
/** A bounded number of retired generations back (see
 * `SIGNED_PREKEY_RETIRED_KEEP`), kept so `establishSessionAsResponder` can
 * still answer a handshake bootstrapped against a signed prekey we've
 * since rotated past -- not just the ONE most-recently-retired key (an
 * offline recipient or a slow retry can span more than one rotation at
 * the default weekly cadence; durability-100 case 066). Still a BOUNDED
 * window, not unlimited retention: a message delayed past
 * `SIGNED_PREKEY_RETIRED_KEEP` rotations remains unanswerable, trading
 * storage and exposure window against reach. Each entry is
 * `{ publicKey, privateKey }`, most-recently-retired first. */
const SIGNED_PREKEY_RETIRED_STORAGE_KEY = 'svalinn_ratchet_signed_prekey_retired';
const SIGNED_PREKEY_RETIRED_KEEP = 3;
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

/** Returns whether the write actually succeeded, for the one call site
 * (`maintainOneTimePrekeys`) where that matters: it must not advertise new
 * one-time prekeys to the server unless their private keys are actually
 * saved locally first (see its own comment). Every other call site treats
 * this as fire-and-forget, same as before -- see `storeOneTimePrekeys`. */
function tryStoreOneTimePrekeys(keys: StoredOneTimePrekey[]): boolean {
  try {
    localStorage.setItem(ONE_TIME_PREKEYS_STORAGE_KEY, JSON.stringify(keys));
    return true;
  } catch {
    return false;
  }
}

function storeOneTimePrekeys(keys: StoredOneTimePrekey[]): void {
  // Best-effort -- see crypto.ts's `checkStorageAvailable` precedent; a
  // broken store here just means fewer one-time prekeys available
  // locally, not a correctness problem (X3DH degrades gracefully).
  tryStoreOneTimePrekeys(keys);
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

  // Persist locally BEFORE publishing to the server, not after -- same
  // fail-closed discipline as `ensureSignedPrekey`/`maintainOneTimePrekeys`
  // below, and for the same reason: if the local write fails, the server
  // must never be left advertising a signing public key whose private half
  // was never actually saved anywhere. That key would be permanently
  // unusable by this device (nothing can sign with it) while still being
  // exactly the key other devices' `verifySignedPrekey` checks would trust
  // -- and since this device never rotates its signing identity once
  // created, nothing would ever retry or replace it on its own. Failing
  // closed here means a storage failure throws before anything is
  // published, so a retry starts clean instead of orphaning the key.
  try {
    localStorage.setItem(SIGNING_PUBLIC_KEY_STORAGE_KEY, publicKey);
    localStorage.setItem(SIGNING_PRIVATE_KEY_STORAGE_KEY, privateKey);
  } catch {
    throw new DeviceSetupError(
      "This device cannot store its ratchet signing key (local storage is unavailable, full, or disabled)."
    );
  }
  await setSigningKey(deviceId, publicKey);
  return { publicKey, privateKey };
}

interface RetiredSignedPrekey {
  publicKey: string;
  privateKey: string;
}

function loadRetiredSignedPrekeys(): RetiredSignedPrekey[] {
  try {
    const raw = localStorage.getItem(SIGNED_PREKEY_RETIRED_STORAGE_KEY);
    return raw ? (JSON.parse(raw) as RetiredSignedPrekey[]) : [];
  } catch {
    return [];
  }
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

  // Persist locally BEFORE publishing to the server, not after. If the
  // local write fails, we must not leave the server advertising a public
  // key whose private half was never actually saved anywhere -- that key
  // becomes permanently unusable (nothing retries it: the NEXT call's
  // freshness check sees the unchanged, still-current OLD key and
  // concludes there's nothing to do) while still being exactly the key
  // future senders' X3DH handshakes bootstrap against. Failing closed here
  // means a storage failure throws before anything is published, so a
  // retry starts clean instead of orphaning a key.
  try {
    if (existingPublic && existingPrivate) {
      // An actual rotation, not first-ever creation: keep the outgoing key
      // around for a few generations (see `SIGNED_PREKEY_RETIRED_KEEP`'s
      // doc comment) so a handshake already bootstrapped against it --
      // possibly more than one rotation ago, for a slow or offline peer --
      // can still be answered instead of silently failing the moment the
      // server starts advertising a different one.
      const retired = [{ publicKey: existingPublic, privateKey: existingPrivate }, ...loadRetiredSignedPrekeys()].slice(
        0,
        SIGNED_PREKEY_RETIRED_KEEP
      );
      localStorage.setItem(SIGNED_PREKEY_RETIRED_STORAGE_KEY, JSON.stringify(retired));
    }
    localStorage.setItem(SIGNED_PREKEY_PUBLIC_KEY_STORAGE_KEY, publicKey);
    localStorage.setItem(SIGNED_PREKEY_PRIVATE_KEY_STORAGE_KEY, privateKey);
    localStorage.setItem(SIGNED_PREKEY_CREATED_AT_STORAGE_KEY, String(Date.now()));
  } catch {
    throw new DeviceSetupError(
      "This device cannot store its ratchet signed prekey (local storage is unavailable, full, or disabled)."
    );
  }
  await uploadPrekeys(deviceId, [{ keyType: 'signed', publicKey, signature }]);
}

async function maintainOneTimePrekeys(deviceId: string): Promise<void> {
  const counts = await fetchPrekeyCounts(deviceId);
  const localCount = loadOneTimePrekeys().length;
  // Replenish when EITHER signal looks low, not just the server's count.
  // Under normal operation the two track each other closely (each
  // consumed key is removed from both sides -- see
  // `findAndConsumeLocalOneTimePrekey`), but the server's count can look
  // perfectly healthy while this device's own local stash is corrupted or
  // was silently dropped (a parse failure in `loadOneTimePrekeys`, a
  // partial write, local storage cleared for just this one key). Every
  // one of those server-advertised "unconsumed" keys is then a phantom
  // this device can never actually answer a handshake against (see
  // `establishSessionAsResponder`'s 3-DH fallback) -- and with nothing
  // previously comparing the two counts, nothing ever noticed or
  // self-healed (durability-100 case 099). This doesn't retroactively fix
  // an already-phantom key already sitting on the server, but it stops
  // the drift from continuing: a steady stream of fresh, genuinely-usable
  // keys gradually displaces the old phantom ones as the local FIFO
  // (`MAX_LOCAL_ONE_TIME_PREKEYS`) and the server's own consumption both
  // turn over.
  if (counts.unconsumedOneTimePrekeys >= ONE_TIME_PREKEY_LOW_WATER_MARK && localCount >= ONE_TIME_PREKEY_LOW_WATER_MARK) {
    return;
  }

  const newKeys: StoredOneTimePrekey[] = [];
  const uploads: PrekeyUpload[] = [];
  for (let i = 0; i < ONE_TIME_PREKEY_REPLENISH_BATCH; i++) {
    const kp = generateRatchetKeypair();
    const publicKey = b64(kp.publicKey);
    newKeys.push({ publicKey, privateKey: b64(kp.privateKey) });
    uploads.push({ keyType: 'one_time', publicKey });
  }

  // Persist locally BEFORE publishing, not after: a batch the server
  // advertises as available but whose private keys this device never
  // actually saved is worse than useless. Any peer who consumes one of
  // those "phantom" prekeys derives a shared secret this device can never
  // reproduce (see `establishSessionAsResponder`'s fallback comment),
  // permanently breaking that one handshake with no way to detect or
  // retry it after the fact. Fail closed instead: if the local write
  // fails, publish nothing this attempt -- the next low-water-mark check
  // retries the whole batch from scratch.
  const merged = [...loadOneTimePrekeys(), ...newKeys];
  const bounded = merged.length > MAX_LOCAL_ONE_TIME_PREKEYS ? merged.slice(merged.length - MAX_LOCAL_ONE_TIME_PREKEYS) : merged;
  if (!tryStoreOneTimePrekeys(bounded)) return;

  await uploadPrekeys(deviceId, uploads);
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

// --- Ratchet identity material for the passphrase recovery backup --------
//
// `lib/recovery.ts`'s passphrase backup historically only carried
// `crypto.ts`'s core X25519 identity keypair (the one `ensureDeviceKeypair()`
// manages). This module's OWN signing identity + current signed prekey live
// in the SEPARATE localStorage keys above -- generated once per BROWSER the
// first time `ensureRatchetReady()` ever runs there, and never regenerated
// just because `crypto.ts`'s active identity keypair later gets swapped out
// (by `replaceActiveKeypair()`, the manual "Recover from backup" escape
// hatch, or by a brand-new device's own first-run recovery choice).
// Recovering the core identity key alone does NOT give a device access to
// the SIGNED PREKEY PRIVATE KEY that a past sender's X3DH handshake
// actually used: that private key only ever lived in the ORIGINAL device's
// own browser storage, and nothing backed it up. Exporting/importing it
// alongside the core identity key closes that gap -- see
// `recovery.ts`'s `createOrReplaceKeyBackup` and `restoreFromBackup`.
//
// The one-time prekey stash needs the same treatment, for the same
// reason: an X3DH handshake that consumed one of this device's one-time
// prekeys needs that SPECIFIC prekey's private key to complete the 4-DH
// computation (not just the signed prekey's), and that private key also
// only ever lived locally. Without it, a recovered device can still
// decrypt messages whose handshake happened to skip the one-time-prekey
// step (3-DH only), but silently gets a DIFFERENT, non-matching shared
// secret for any that didn't -- the current stash is included wholesale
// (it's already bounded to `MAX_LOCAL_ONE_TIME_PREKEYS`) so whichever one
// an old, not-yet-received message referenced is there to be found.

export interface RatchetIdentityBackup {
  signingPublicKey: string;
  signingPrivateKey: string;
  signedPrekeyPublicKey: string;
  signedPrekeyPrivateKey: string;
  signedPrekeyCreatedAt: string;
  oneTimePrekeys: StoredOneTimePrekey[];
}

/** Reads this browser's current ratchet signing identity + signed prekey
 * + one-time prekey stash, for inclusion in a passphrase recovery backup.
 * Returns null if this device has never completed `ensureRatchetReady()`
 * -- nothing to export yet; callers should simply omit this material from
 * the backup rather than treat that as an error. */
export function exportRatchetIdentityForBackup(): RatchetIdentityBackup | null {
  const signingPublicKey = localStorage.getItem(SIGNING_PUBLIC_KEY_STORAGE_KEY);
  const signingPrivateKey = localStorage.getItem(SIGNING_PRIVATE_KEY_STORAGE_KEY);
  const signedPrekeyPublicKey = localStorage.getItem(SIGNED_PREKEY_PUBLIC_KEY_STORAGE_KEY);
  const signedPrekeyPrivateKey = localStorage.getItem(SIGNED_PREKEY_PRIVATE_KEY_STORAGE_KEY);
  const signedPrekeyCreatedAt = localStorage.getItem(SIGNED_PREKEY_CREATED_AT_STORAGE_KEY);
  if (!signingPublicKey || !signingPrivateKey || !signedPrekeyPublicKey || !signedPrekeyPrivateKey || !signedPrekeyCreatedAt) {
    return null;
  }
  return {
    signingPublicKey,
    signingPrivateKey,
    signedPrekeyPublicKey,
    signedPrekeyPrivateKey,
    signedPrekeyCreatedAt,
    oneTimePrekeys: loadOneTimePrekeys(),
  };
}

/** Writes recovered ratchet identity material into this browser's local
 * storage. The signing identity and signed prekey OVERWRITE whatever this
 * browser had generated for itself before recovery -- see this section's
 * header comment for why that's exactly what lets a recovered device
 * respond to old messages that were X3DH-bootstrapped against the
 * ORIGINAL device's signed prekey. The one-time prekey stash is MERGED
 * (deduped by public key, bounded the same way `maintainOneTimePrekeys`
 * already bounds it) rather than replaced outright, so a key this browser
 * had already generated for itself isn't discarded for no reason. Callers
 * should run this BEFORE anything that might call `ensureRatchetReady()`
 * (e.g. `settleDeviceReady`'s fire-and-forget call), so its "already
 * fresh, nothing to do" check sees the recovered material rather than
 * racing to regenerate-and-republish a prekey this device just received
 * from backup. Best-effort, matching every other localStorage write in
 * this file: a failure here just means recovery falls back to today's
 * (non-matching, this-browser's-own) behavior, not a crash. */
export function importRecoveredRatchetIdentity(material: RatchetIdentityBackup): void {
  try {
    localStorage.setItem(SIGNING_PUBLIC_KEY_STORAGE_KEY, material.signingPublicKey);
    localStorage.setItem(SIGNING_PRIVATE_KEY_STORAGE_KEY, material.signingPrivateKey);
    localStorage.setItem(SIGNED_PREKEY_PUBLIC_KEY_STORAGE_KEY, material.signedPrekeyPublicKey);
    localStorage.setItem(SIGNED_PREKEY_PRIVATE_KEY_STORAGE_KEY, material.signedPrekeyPrivateKey);
    localStorage.setItem(SIGNED_PREKEY_CREATED_AT_STORAGE_KEY, material.signedPrekeyCreatedAt);

    const existing = loadOneTimePrekeys();
    const existingKeys = new Set(existing.map((k) => k.publicKey));
    const merged = [...existing, ...material.oneTimePrekeys.filter((k) => !existingKeys.has(k.publicKey))];
    const bounded = merged.length > MAX_LOCAL_ONE_TIME_PREKEYS ? merged.slice(merged.length - MAX_LOCAL_ONE_TIME_PREKEYS) : merged;
    storeOneTimePrekeys(bounded);
  } catch (err) {
    console.warn("Failed to import recovered ratchet identity material (falling back to this device's own):", err);
  }
}

// --- Session persistence (local cache + best-effort encrypted backup) -----

const SESSION_STORAGE_KEY_PREFIX = 'svalinn_ratchet_session_';

function sessionStorageKey(peerDeviceId: string): string {
  return `${SESSION_STORAGE_KEY_PREFIX}${peerDeviceId}`;
}

/** Wipes EVERY piece of this browser's local Double Ratchet state: the
 * signing identity, the current and retired signed prekeys, the one-time
 * prekey stash, and every cached per-peer session (there's no registry of
 * which peer device ids exist locally, so this scans for the
 * `SESSION_STORAGE_KEY_PREFIX` prefix rather than tracking them).
 *
 * Called by `recovery.ts` alongside `crypto.ts`'s own
 * `forgetLocalDeviceIdentity` when it detects that a DIFFERENT account has
 * just logged in on this browser than whoever it was last used for -- see
 * `crypto.ts`'s `ownerMatchesCurrentUser` for the full scenario. This
 * module's signing identity is deliberately independent of `crypto.ts`'s
 * own keypair (see this file's "Identity & prekey lifecycle" section
 * header comment: generated once per BROWSER, never regenerated just
 * because the core identity keypair changes) -- which is exactly why
 * clearing `crypto.ts`'s identity alone would NOT be enough to stop a
 * second account from inheriting this module's signing/prekey material
 * too. Safe to call even if `ensureRatchetReady()` was never run on this
 * browser (every removal is a no-op against a key that was never set). */
export function forgetLocalRatchetIdentity(): void {
  try {
    localStorage.removeItem(SIGNING_PUBLIC_KEY_STORAGE_KEY);
    localStorage.removeItem(SIGNING_PRIVATE_KEY_STORAGE_KEY);
    localStorage.removeItem(SIGNED_PREKEY_PUBLIC_KEY_STORAGE_KEY);
    localStorage.removeItem(SIGNED_PREKEY_PRIVATE_KEY_STORAGE_KEY);
    localStorage.removeItem(SIGNED_PREKEY_CREATED_AT_STORAGE_KEY);
    localStorage.removeItem(SIGNED_PREKEY_RETIRED_STORAGE_KEY);
    localStorage.removeItem(ONE_TIME_PREKEYS_STORAGE_KEY);
    const sessionKeys: string[] = [];
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (key?.startsWith(SESSION_STORAGE_KEY_PREFIX)) sessionKeys.push(key);
    }
    for (const key of sessionKeys) localStorage.removeItem(key);
  } catch {
    /* best-effort, same as every other local write in this module */
  }
  sessionLocks.clear();
}

/** Structural sanity check for a value that's about to be trusted as a
 * `RatchetState` -- whether freshly parsed from local storage or decrypted
 * out of the server-side backup. A value that merely parses as JSON
 * (`null`, `{}`, `[]`, `"text"`, or an object missing required fields) is
 * NOT a usable session: feeding it straight into the ratchet math throws
 * deep inside `ratchetDecrypt`/`ratchetEncrypt` instead of falling back to
 * a session that IS usable (the local cache's healthy twin, or the
 * server-side backup). Treating anything that fails this check as "no
 * session cached" lets the existing recovery path in `loadOrRecoverSession`
 * do its job instead. */
function isValidRatchetState(value: unknown): value is RatchetState {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const v = value as Record<string, unknown>;
  return (
    typeof v.dhsPublic === 'string' &&
    typeof v.dhsPrivate === 'string' &&
    (v.dhrPublic === null || typeof v.dhrPublic === 'string') &&
    typeof v.rootKey === 'string' &&
    (v.chainKeySend === null || typeof v.chainKeySend === 'string') &&
    (v.chainKeyRecv === null || typeof v.chainKeyRecv === 'string') &&
    typeof v.sendCount === 'number' &&
    typeof v.recvCount === 'number' &&
    typeof v.previousChainLength === 'number' &&
    typeof v.skippedKeys === 'object' &&
    v.skippedKeys !== null &&
    !Array.isArray(v.skippedKeys) &&
    typeof v.adLow === 'string' &&
    typeof v.adHigh === 'string'
  );
}

function loadLocalSession(peerDeviceId: string): RatchetState | null {
  try {
    const raw = localStorage.getItem(sessionStorageKey(peerDeviceId));
    if (!raw) return null;
    const parsed: unknown = JSON.parse(raw);
    return isValidRatchetState(parsed) ? parsed : null;
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
  const ciphertextB64 = b64(ciphertextBytes);
  const nonceB64 = b64(nonceBytes);

  // Bounded retry on conflict. A conflict means our bookkeeping of the
  // backup's `updated_at` is stale (e.g. another tab on this same device
  // backed it up in between) -- the ORIGINAL fix here just resynced that
  // timestamp and gave up, which silently dropped THIS state (the one the
  // caller actually asked to back up, and the most-advanced one this
  // device has) from ever reaching the server: the backup was left
  // pointing at whatever the other writer last pushed, invisible until
  // this device's local storage is later lost and recovery falls back to
  // that stale backup (durability-100 case 098). Retrying with a
  // freshly-fetched baseline instead actually lands THIS state, as long
  // as the conflicting writer has settled down within a few attempts.
  let expectedUpdatedAt = state.backupUpdatedAt;
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const saved = await putRatchetSession(myDeviceId, peerDeviceId, ciphertextB64, nonceB64, expectedUpdatedAt);
      const current = loadLocalSession(peerDeviceId);
      if (current) storeLocalSession(peerDeviceId, { ...current, backupUpdatedAt: saved.updatedAt });
      return;
    } catch (err) {
      if (!(err instanceof RatchetSessionConflictError)) throw err;
      try {
        const serverState = await fetchRatchetSession(myDeviceId, peerDeviceId);
        expectedUpdatedAt = serverState.updatedAt;
      } catch {
        // Can't even read the current backup right now -- nothing more to
        // try this round. The local session's actual ratchet state is
        // unaffected either way; the next message's `saveSession` call
        // retries the whole thing from scratch.
        return;
      }
    }
  }
  console.warn('Giving up on backing up this ratchet session after repeated write conflicts (local session is still fine).');
}

function saveSession(myDeviceId: string, peerDeviceId: string, state: RatchetState): void {
  storeLocalSession(peerDeviceId, state);
  backupSession(myDeviceId, peerDeviceId, state).catch((err) => {
    console.warn('Failed to back up a ratchet session to the server (local session is still fine):', err);
  });
}

/** Same as `saveSession`, but AWAITS the backup instead of firing it and
 * forgetting it, and ALSO reports the specific skipped-key slot that was
 * just consumed to the server-side consumption ledger (migration 0041,
 * `reportConsumedSkippedKey`). Used specifically right after consuming a
 * cached skipped message key (see
 * `tryDecryptWithSkippedKey`/`RatchetDecryptResult`): that key is now gone
 * from local state forever by design (a skipped key is single-use), so if
 * this device's local storage were lost before an eventual, fire-and-forget
 * backup caught up, recovery would restore an OLDER backup that still
 * lists the key as available -- letting a captured-and-replayed copy of
 * the original ciphertext decrypt a second time (confidentiality-review
 * followup case 15).
 *
 * Two independent, concurrent mitigations, run together via
 * `Promise.allSettled` (neither is allowed to block or fail the other):
 * the eager backup narrows the window during which a stale backup could
 * even be the one recovery finds; the ledger report means that even if a
 * stale backup IS the one recovered, `loadOrRecoverSession`'s
 * `stripConsumedSkippedKeys` can still catch and strip the stale entry, as
 * long as this report itself landed. Only if BOTH are lost (e.g. local
 * storage is wiped while fully offline, before either request ever
 * leaves the device) does the residual gap remain -- closing that fully
 * would need the server consulted synchronously as part of every decrypt,
 * which isn't compatible with offline-first E2EE messaging.
 *
 * Still best-effort like `saveSession`: the local session (the
 * authoritative copy) is already saved synchronously either way, so a
 * failure in either call here never blocks the caller from getting its
 * already-decrypted plaintext, only delays returning it slightly longer
 * than the fire-and-forget path would. */
async function saveSessionEagerly(
  myDeviceId: string,
  peerDeviceId: string,
  state: RatchetState,
  consumedSlot: { dhPublicKey: string; messageNumber: number }
): Promise<void> {
  storeLocalSession(peerDeviceId, state);
  const results = await Promise.allSettled([
    backupSession(myDeviceId, peerDeviceId, state),
    reportConsumedSkippedKey(myDeviceId, peerDeviceId, consumedSlot.dhPublicKey, consumedSlot.messageNumber),
  ]);
  for (const result of results) {
    if (result.status === 'rejected') {
      console.warn(
        'Failed to eagerly persist a consumed skipped message key (session backup and/or consumption ledger; local session is still fine):',
        result.reason
      );
    }
  }
}

/** True if a loaded session was created under a DIFFERENT local identity
 * than the one now active. Its AD and DH math were both derived from the
 * OLD identity key (see `initRatchetAsInitiator`/`initRatchetAsResponder`)
 * and can never produce a matching ciphertext under a new one -- most
 * directly after `adoptRecoveredKeypair` switches this device to a
 * different legitimate identity while a session cached only by peer
 * device id is left behind. A session with no recorded identity at all
 * (persisted before this field existed) is treated as valid rather than
 * forcing every pre-existing session to re-handshake on upgrade. */
function belongsToAnotherIdentity(state: RatchetState, myIdentityPublicKeyB64: string): boolean {
  return Boolean(state.myIdentityPublicKey) && state.myIdentityPublicKey !== myIdentityPublicKeyB64;
}

/** Cross-checks a just-recovered session's `skippedKeys` map against the
 * server-side consumed-skipped-key ledger (migration 0041) before trusting
 * it, and strips anything the ledger confirms this device already
 * consumed. This is what actually CLOSES most of the gap that the eager
 * backup in `saveSessionEagerly` only narrows: the ledger is written
 * per-consumption, independently of the whole-session backup blob, so it
 * can't be stale in the same way the backup itself can be (see that
 * function's doc comment for the full picture of the two mitigations
 * together).
 *
 * Fails CLOSED, not open: if the ledger can't be fetched at all, this
 * drops every cached skipped key rather than trusting an unverified map.
 * The cost of that is availability, not security -- any message that
 * genuinely still needs one of those keys simply can't be decrypted until
 * it's re-sent or the chain naturally catches up, the same outcome as a
 * skipped key that aged out past `RatchetTooManySkippedMessagesError`'s
 * cap. The alternative -- trusting the map when the check itself couldn't
 * even run -- would silently defeat the whole mitigation on exactly the
 * kind of network hiccup it exists to guard against. */
async function stripConsumedSkippedKeys(
  myDeviceId: string,
  peerDeviceId: string,
  skippedKeys: Record<string, string>
): Promise<Record<string, string>> {
  if (Object.keys(skippedKeys).length === 0) return skippedKeys;
  let consumed: ConsumedSkippedKey[];
  try {
    consumed = await fetchConsumedSkippedKeys(myDeviceId, peerDeviceId);
  } catch (err) {
    console.warn(
      "Could not verify a recovered session's cached skipped keys against the server-side consumption ledger; dropping all of them to be safe:",
      err
    );
    return {};
  }
  if (consumed.length === 0) return skippedKeys;
  const consumedSlots = new Set(consumed.map((c) => `${c.dhPublicKey}:${c.messageNumber}`));
  const filtered: Record<string, string> = {};
  for (const [slot, key] of Object.entries(skippedKeys)) {
    if (!consumedSlots.has(slot)) filtered[slot] = key;
  }
  return filtered;
}

/** Loads a session's local state, falling back to recovering it from the
 * server-side encrypted backup if nothing's cached locally (e.g. local
 * storage was cleared) -- see this file's header comment. Returns null if
 * there's truly no session yet either way. */
async function loadOrRecoverSession(
  myDeviceId: string,
  peerDeviceId: string,
  myIdentityPublicKeyB64: string
): Promise<RatchetState | null> {
  const local = loadLocalSession(peerDeviceId);
  if (local) {
    if (!belongsToAnotherIdentity(local, myIdentityPublicKeyB64)) return local;
    // Stale: clear it rather than silently feeding it to the ratchet math
    // on every future call for this peer, so the next check short-circuits
    // on "nothing cached" instead of re-deriving this same answer.
    try {
      localStorage.removeItem(sessionStorageKey(peerDeviceId));
    } catch {
      /* best-effort, same as every other local write in this file */
    }
  }

  try {
    const backup = await fetchRatchetSession(myDeviceId, peerDeviceId);
    const { privateKey } = await ensureDeviceKeypair();
    const pickleKey = derivePickleKey(fromB64(privateKey));
    const plaintextBytes = sodium.crypto_secretbox_open_easy(fromB64(backup.pickleCiphertext), fromB64(backup.pickleNonce), pickleKey);
    const parsed: unknown = JSON.parse(sodium.to_string(plaintextBytes));
    if (!isValidRatchetState(parsed) || belongsToAnotherIdentity(parsed, myIdentityPublicKeyB64)) return null;
    const skippedKeys = await stripConsumedSkippedKeys(myDeviceId, peerDeviceId, parsed.skippedKeys);
    const state: RatchetState = { ...parsed, skippedKeys, backupUpdatedAt: backup.updatedAt };
    storeLocalSession(peerDeviceId, state);
    return state;
  } catch (err) {
    if (err instanceof NoRatchetSessionError) return null;
    console.warn('Failed to recover a ratchet session from its server-side backup:', err);
    return null;
  }
}

// --- Public send/receive API ----------------------------------------------

/** Serializes every load-mutate-persist cycle for one (my device, peer
 * device) session pair. Without this, two overlapping calls -- a user
 * firing off several messages in quick succession before the first one's
 * state write lands, or two incoming messages from the same peer arriving
 * close together -- can both load the SAME starting chain key before
 * either has persisted its advance. That derives and transmits the SAME
 * message key under two different ciphertexts (a real per-message-key
 * invariant violation, not just a UI race), and can equally regress a
 * receive counter that a second concurrent decrypt already moved forward.
 * Plain (non-`async`) on purpose: the get-then-set below must happen with
 * no `await` in between, or two overlapping calls could both see the
 * queue as empty and run concurrently anyway. A failed call never poisons
 * the queue for whoever's waiting behind it (`.catch(() => undefined)`
 * below) -- it's still rejected for ITS OWN caller via the returned
 * promise, just not propagated to anyone else's turn. */
const sessionLocks = new Map<string, Promise<unknown>>();

function withSessionLock<T>(myDeviceId: string, peerDeviceId: string, fn: () => Promise<T>): Promise<T> {
  const key = `${myDeviceId}:${peerDeviceId}`;
  const prior = sessionLocks.get(key) ?? Promise.resolve();
  const next = prior.then(fn, fn);
  sessionLocks.set(key, next.catch(() => undefined));
  return next;
}

/** Encrypts `plaintext` for `peerDeviceId`, establishing a brand-new
 * session via the X3DH-style handshake first if none exists yet. Throws
 * `RatchetNotSupportedError` if the peer device hasn't opted into the
 * Double Ratchet (no published signed prekey) -- callers should catch
 * that and fall back to `crypto.ts`'s stateless per-device encryption. */
export async function encryptMessage(peerDeviceId: string, plaintext: string): Promise<RatchetEnvelope> {
  const { deviceId: myDeviceId, publicKey: myIdentityPublicKeyB64 } = await ensureDeviceKeypair();
  return withSessionLock(myDeviceId, peerDeviceId, async () => {
    const existing = await loadOrRecoverSession(myDeviceId, peerDeviceId, myIdentityPublicKeyB64);
    const state = existing ?? (await bootstrapSessionAsInitiator(peerDeviceId));

    const result = ratchetEncrypt(state, plaintext);
    const envelope: RatchetEnvelope = { dh: result.dh, pn: result.pn, n: result.n, ciphertext: result.ciphertext, nonce: result.nonce };

    const newState = result.state;
    if (newState.pendingInitialHeader) {
      // Kept attached to EVERY message for as long as it's present (see
      // `ratchetDecrypt`'s matching comment on when it's cleared) -- not
      // just the first one -- so an unacknowledged retry, or the other
      // side of an overlapping concurrent first send that arrives before
      // this one, is never left without the bootstrap data a fresh
      // responder needs to decrypt it at all.
      envelope.initial = newState.pendingInitialHeader;
    }
    saveSession(myDeviceId, peerDeviceId, newState);
    return envelope;
  });
}

/** Decrypts a message from `peerDeviceId`, bootstrapping a session as the
 * RESPONDER first if this is the first message ever received from them
 * (its `initial` block carries what's needed to do so). Returns null --
 * never throws -- for any decryption failure, matching `crypto.ts`'s
 * `decryptFromSender` contract: a bad/tampered message degrades to "can't
 * show this one" rather than crashing the conversation. */
export async function decryptMessage(peerDeviceId: string, envelope: RatchetEnvelope): Promise<string | null> {
  const { deviceId: myDeviceId, publicKey: myIdentityPublicKeyB64 } = await ensureDeviceKeypair();
  return withSessionLock(myDeviceId, peerDeviceId, () => decryptMessageLocked(myDeviceId, peerDeviceId, myIdentityPublicKeyB64, envelope));
}

async function decryptMessageLocked(
  myDeviceId: string,
  peerDeviceId: string,
  myIdentityPublicKeyB64: string,
  envelope: RatchetEnvelope
): Promise<string | null> {
  let state = await loadOrRecoverSession(myDeviceId, peerDeviceId, myIdentityPublicKeyB64);

  // Mutual X3DH initiation collision: both sides of a brand-new (device,
  // peer device) pair can simultaneously find no session and self-initiate
  // toward each other before either has received anything back. Each
  // derives a DIFFERENT shared secret (initiator math run independently in
  // each direction isn't symmetric across two unrelated handshakes), so
  // `state` here -- our own un-replied initiator attempt -- has nothing to
  // do with the secret this incoming message was actually encrypted under.
  // Blindly reusing it (the pre-fix behavior) decrypt-fails every time.
  //
  // Resolve with a deterministic tie-break both sides can compute
  // independently, with no coordination: compare identity public keys
  // (the same canonical byte-ordering `canonicalPair` uses for AD). The
  // side that loses discards its own attempt and adopts the winner's
  // handshake as canonical (falls through to the normal responder-bootstrap
  // path below). The side that wins keeps its own session untouched for
  // future sends, but still owes the peer a decrypt of this one race
  // message -- it derives a one-off responder session purely to read it,
  // and never persists that derivation, so the two sides converge on a
  // single matching chain afterward instead of drifting onto two
  // unrelated ones (which is exactly what naively re-bootstrapping on
  // every `initial` block, regardless of who's unaffected, would cause).
  //
  // Scoped tightly to an actual race: only when the existing session has
  // never RECEIVED a real message yet (`chainKeyRecv === null`), which is
  // the genuine invariant -- not `sendCount === 0`. In practice, each side
  // finishes sending its own race message (bumping `sendCount` to 1) well
  // before the peer's colliding message arrives over the network, so a
  // `sendCount === 0` requirement here would almost never actually fire
  // in the realistic timing this is meant to catch. `chainKeyRecv` stays
  // null regardless of how many unanswered messages we've sent, and that's
  // exactly the state that means "this session has never been confirmed
  // by an actual reply" -- which is also implied by the peer's message
  // still carrying `initial` fields at all (the sender keeps attaching
  // those to EVERY message for as long as its own `chainKeyRecv` is still
  // null -- see `encryptMessage`/`ratchetDecrypt` -- so a still-present
  // `initial` means the SENDER hasn't heard back from us either). A
  // session with any genuine received traffic (`chainKeyRecv` set) is
  // never second-guessed here, whatever headers show up on top of it.
  const isRaceCandidate = !!state && !!envelope.initial && state.chainKeyRecv === null;

  if (isRaceCandidate && envelope.initial) {
    const myIdentityPublicKey = fromB64(myIdentityPublicKeyB64);
    const peerIdentityPublicKey = fromB64(envelope.initial.identityPublicKey);
    const iAmCanonical = canonicalPair(myIdentityPublicKey, peerIdentityPublicKey).low === myIdentityPublicKey;

    if (iAmCanonical) {
      try {
        const throwaway = await establishSessionAsResponder(peerDeviceId, envelope.initial);
        const oneOff = ratchetDecrypt(throwaway, envelope);
        return oneOff ? oneOff.plaintext : null;
      } catch (err) {
        console.warn('Failed to decrypt the losing side of a mutual X3DH initiation race:', err);
        return null;
      }
    }
    // We lose the tie: discard our own un-replied initiator attempt and
    // fall through to establish fresh as responder below, which becomes
    // our new canonical session.
    state = null;
  }

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

  let result: RatchetDecryptResult | null;
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

  if (result.viaSkippedKey && result.consumedSkippedKeySlot) {
    // See `saveSessionEagerly`'s doc comment: a consumed skipped key is
    // gone from local state forever, so this one save can't wait for some
    // later message to flush it -- it's backed up, and reported to the
    // consumption ledger, right away.
    await saveSessionEagerly(myDeviceId, peerDeviceId, result.state, result.consumedSkippedKeySlot);
  } else {
    saveSession(myDeviceId, peerDeviceId, result.state);
  }
  return result.plaintext;
}
