// A local, encrypted-at-rest cache of already-decrypted message plaintexts,
// so a message a user has genuinely already read stays readable later --
// after a reload, after scrolling back up, after this device's Double
// Ratchet session has naturally advanced past that message's position and
// deleted the one-time key that decrypted it (forward secrecy, by design --
// see ratchet.ts's header comment, and its `skippedKeys` map, whose entries
// are deleted the instant they're used specifically so a later re-decrypt
// attempt of the SAME message can't succeed).
//
// That last point is why this module exists, not just as a nicety: without
// it, re-rendering a conversation (e.g. after a reload, when every message
// on screen gets decrypted again from scratch) would re-run
// `decryptMessage` on messages it already successfully decrypted once --
// and for any message that was originally received out of order, that
// second attempt fails outright, because the cached skipped key it needs
// was already consumed and deleted the first time around. So the cache
// below isn't an optional performance layer on top of a working decrypt
// path; it's load-bearing for "a message I've already read stays
// readable", independent of whatever the ratchet's own internal state
// looks like by the time you look again.
//
// --- The trade this makes, explicitly -------------------------------------
//
// Svalinn's forward secrecy guarantee is that a device compromised TODAY
// can't read messages whose keys are already gone -- compromising the
// ratchet's current state reveals nothing about the past. Caching
// plaintext here necessarily gives that up for any message that gets
// cached: from the moment it's cached, that message's content persists on
// this one device (encrypted under a key derived from this device's own
// long-term identity, same protection level as the ratchet session
// backup's pickle) until it is explicitly cleared or the message itself is
// deleted. This is the same trade Signal and WhatsApp make in practice --
// message history has to live somewhere to be re-readable at all -- but it
// is a real trade, not a free win, so it's on by default rather than hidden,
// and `clearMessageHistoryCache` below exists specifically so a user who
// wants today's stricter guarantee back can wipe it.
//
// --- Never touches the server, never touches another device ---------------
//
// Message plaintext is NEVER sent to the server in any form, encrypted or
// not -- this cache lives purely in this one device's own IndexedDB
// database, is never backed up, synced, or shared with any other device
// this user owns (exactly like `ratchet.ts`'s own per-device local session
// state is never shared between a user's devices either -- see that file's
// header comment on why a ratchet session itself is directed and
// per-device, not a shared channel). A second device of the same user
// starts with an empty cache of its own and can only show history it has
// personally decrypted, same as today.
//
// --- Why IndexedDB, not localStorage (same pattern as everywhere else in
// this app) ------------------------------------------------------------
//
// Every other local value this app keeps (device keypairs, one ratchet
// session's worth of state) is small and roughly fixed-size, so
// `localStorage` is a fine fit. Message history has no such bound -- a
// long-lived, active conversation can accumulate thousands of entries --
// so this uses IndexedDB instead, which both has a much larger practical
// quota and doesn't require this module to synchronously serialize the
// whole cache on every write the way a `localStorage`-backed map would.
import sodium from 'libsodium-wrappers-sumo';
import { ensureDeviceKeypair } from './crypto';
import { b64, fromB64, hmac, hkdfExpand } from './ratchet';

const DB_NAME = 'svalinn-message-history';
const DB_VERSION = 1;
const STORE_NAME = 'messages';

interface StoredEntry {
  id: string;
  ciphertext: string;
  nonce: string;
}

let dbPromise: Promise<IDBDatabase> | null = null;

/** Opens (creating on first use) this device's message-history database.
 * Memoized per module instance -- every caller in this tab/process shares
 * one connection, same pattern as `ensureDeviceKeypair`'s own memoization
 * in `crypto.ts`. Rejects if IndexedDB genuinely isn't available or usable
 * here (disabled, private-browsing-style restrictions, a browser that
 * doesn't support it) -- every public function below treats that as "the
 * cache just isn't available right now" rather than letting it become an
 * uncaught error that could interrupt actually showing a message. */
function openDb(): Promise<IDBDatabase> {
  if (!dbPromise) {
    dbPromise = new Promise<IDBDatabase>((resolve, reject) => {
      if (typeof indexedDB === 'undefined') {
        reject(new Error('IndexedDB is not available in this environment'));
        return;
      }
      const request = indexedDB.open(DB_NAME, DB_VERSION);
      request.onupgradeneeded = () => {
        const db = request.result;
        if (!db.objectStoreNames.contains(STORE_NAME)) {
          db.createObjectStore(STORE_NAME, { keyPath: 'id' });
        }
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error ?? new Error('Failed to open the message history database'));
    });
  }
  return dbPromise;
}

/** Deterministically derives this device's message-history encryption key
 * from its own long-term identity private key via HKDF -- same approach,
 * and same reasoning, as `ratchet.ts`'s `derivePickleKey` for the session
 * backup, just under a different `info` string so the two keys can never
 * collide even though they're both derived from the same private key.
 * Never stored separately; never shared with any other device, since each
 * device's identity private key is unique to it (so, same as the pickle
 * key, this also means a cache entry written before an identity change --
 * see `adoptRecoveredKeypair` in `recovery.ts` -- simply becomes
 * undecryptable afterward; `getCachedPlaintext` below treats that exactly
 * like any other cache miss, not an error). */
async function deriveHistoryKey(): Promise<Uint8Array> {
  const { privateKey } = await ensureDeviceKeypair();
  const zeroSalt = new Uint8Array(sodium.crypto_auth_hmacsha256_KEYBYTES);
  const prk = hmac(zeroSalt, fromB64(privateKey));
  return hkdfExpand(prk, 'SvalinnMessageHistoryKey', sodium.crypto_secretbox_KEYBYTES);
}

function withStore<T>(mode: IDBTransactionMode, fn: (store: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  return openDb().then(
    (db) =>
      new Promise<T>((resolve, reject) => {
        const tx = db.transaction(STORE_NAME, mode);
        const request = fn(tx.objectStore(STORE_NAME));
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error ?? new Error('Message history store operation failed'));
      })
  );
}

/** Returns a message's cached plaintext, or null if it isn't cached (never
 * decrypted before on this device, the cache is unavailable, or it was
 * cached under a now-superseded identity key -- see `deriveHistoryKey`).
 * Callers should treat null exactly like "not cached yet" and fall back to
 * the real decrypt path; this function never throws. */
export async function getCachedPlaintext(messageId: string): Promise<string | null> {
  try {
    const entry = await withStore<StoredEntry | undefined>('readonly', (store) => store.get(messageId));
    if (!entry) return null;
    const key = await deriveHistoryKey();
    const plaintextBytes = sodium.crypto_secretbox_open_easy(fromB64(entry.ciphertext), fromB64(entry.nonce), key);
    return sodium.to_string(plaintextBytes);
  } catch {
    // Covers both "the store itself is unavailable" and "this entry can't
    // be decrypted under the current identity key" -- both are cache
    // misses from the caller's point of view, never hard failures.
    return null;
  }
}

/** Caches a message's plaintext, once successfully decrypted, so later
 * reads of it never need the ratchet (or any key the ratchet may have
 * already discarded) again. Best-effort, like every other local write in
 * this app: a failure here (storage full, IndexedDB unavailable) never
 * blocks the caller from showing the plaintext it already has -- it just
 * means this one message won't survive to be re-read later. */
export async function cachePlaintext(messageId: string, plaintext: string): Promise<void> {
  try {
    const key = await deriveHistoryKey();
    const nonceBytes = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
    const ciphertextBytes = sodium.crypto_secretbox_easy(sodium.from_string(plaintext), nonceBytes, key);
    const entry: StoredEntry = { id: messageId, ciphertext: b64(ciphertextBytes), nonce: b64(nonceBytes) };
    await withStore<IDBValidKey>('readwrite', (store) => store.put(entry));
  } catch (err) {
    console.warn('Failed to cache a decrypted message locally (it will need to be re-decrypted next time):', err);
  }
}

/** Removes one message's cached plaintext -- call this wherever a message
 * is deleted (`deleteMessage`), so an explicit delete is honored here too,
 * not just against the server's copy. Best-effort and silent: a failure
 * here leaves an orphaned cache entry for a message that no longer shows
 * anywhere in the UI, which is harmless (it's simply never looked up
 * again under that id), not a correctness problem worth surfacing. */
export async function deleteCachedPlaintext(messageId: string): Promise<void> {
  try {
    await withStore<undefined>('readwrite', (store) => store.delete(messageId));
  } catch {
    /* best-effort, see doc comment above */
  }
}

/** Wipes this device's ENTIRE message history cache -- the user-facing
 * "clear message history on this device" action (see
 * `AccountSettings.svelte`), for anyone who wants today's stricter
 * forward-secrecy guarantee back and is fine losing the ability to
 * re-read old messages whose live ratchet keys are already gone. Does not
 * touch any other device, and does not delete anything server-side --
 * this cache never had a server-side copy to begin with. */
export async function clearMessageHistoryCache(): Promise<void> {
  await withStore<undefined>('readwrite', (store) => store.clear());
}
