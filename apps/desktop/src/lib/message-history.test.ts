// Tests for the local, encrypted-at-rest message history cache (case 16:
// "can't re-read old messages after reload" -- see that module's header
// comment for the full design and the trade it makes). Runs against a real
// (in-memory, pure-JS) IndexedDB implementation via `fake-indexeddb`, not a
// hand-rolled mock of the IndexedDB API -- that API has enough transaction/
// request-callback subtlety that a mock would risk testing the mock's
// behavior instead of the module's.
import 'fake-indexeddb/auto';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { IDBFactory } from 'fake-indexeddb';

// `ensureDeviceKeypair` normally touches `localStorage` and the network
// (registering a brand-new device). None of that is this module's
// concern -- it just needs A stable keypair to derive its cache key from --
// so it's mocked to a fixed value, same approach `ratchet.test.ts` and
// friends take for `./devices`.
const fakeKeypair = {
  publicKey: 'ZmFrZS1wdWJsaWMta2V5LWZvci1oaXN0b3J5LXRlc3RzMDA',
  privateKey: 'ZmFrZS1wcml2YXRlLWtleS1mb3ItaGlzdG9yeS10ZXN0czAw',
  deviceId: 'device-under-test',
};
let currentKeypair = fakeKeypair;

vi.mock('./crypto', () => ({
  ensureDeviceKeypair: async () => currentKeypair,
}));

describe('message-history', () => {
  beforeEach(async () => {
    // A fresh, empty IndexedDB for every test, and a fresh module instance
    // so its memoized `dbPromise` doesn't carry a connection to the
    // PREVIOUS test's (now-replaced) database across tests.
    (globalThis as unknown as { indexedDB: IDBFactory }).indexedDB = new IDBFactory();
    currentKeypair = fakeKeypair;
    vi.resetModules();
  });

  it('a message is not cached until cachePlaintext is called for it', async () => {
    const { getCachedPlaintext } = await import('./message-history');
    expect(await getCachedPlaintext('msg-1')).toBeNull();
  });

  it('round-trips a cached plaintext', async () => {
    const { getCachedPlaintext, cachePlaintext } = await import('./message-history');
    await cachePlaintext('msg-1', 'hello from the past');
    expect(await getCachedPlaintext('msg-1')).toBe('hello from the past');
  });

  it('caches multiple messages independently', async () => {
    const { getCachedPlaintext, cachePlaintext } = await import('./message-history');
    await cachePlaintext('msg-1', 'first');
    await cachePlaintext('msg-2', 'second');
    expect(await getCachedPlaintext('msg-1')).toBe('first');
    expect(await getCachedPlaintext('msg-2')).toBe('second');
    expect(await getCachedPlaintext('msg-3')).toBeNull();
  });

  it('overwrites a message cached twice under the same id', async () => {
    const { getCachedPlaintext, cachePlaintext } = await import('./message-history');
    await cachePlaintext('msg-1', 'original');
    await cachePlaintext('msg-1', 'edited');
    expect(await getCachedPlaintext('msg-1')).toBe('edited');
  });

  it('deleteCachedPlaintext removes exactly the targeted entry', async () => {
    const { getCachedPlaintext, cachePlaintext, deleteCachedPlaintext } = await import('./message-history');
    await cachePlaintext('msg-1', 'keep me');
    await cachePlaintext('msg-2', 'delete me');
    await deleteCachedPlaintext('msg-2');
    expect(await getCachedPlaintext('msg-1')).toBe('keep me');
    expect(await getCachedPlaintext('msg-2')).toBeNull();
  });

  it('deleting a message that was never cached is a harmless no-op', async () => {
    const { deleteCachedPlaintext } = await import('./message-history');
    await expect(deleteCachedPlaintext('never-existed')).resolves.toBeUndefined();
  });

  it('clearMessageHistoryCache wipes every cached entry', async () => {
    const { getCachedPlaintext, cachePlaintext, clearMessageHistoryCache } = await import('./message-history');
    await cachePlaintext('msg-1', 'one');
    await cachePlaintext('msg-2', 'two');
    await clearMessageHistoryCache();
    expect(await getCachedPlaintext('msg-1')).toBeNull();
    expect(await getCachedPlaintext('msg-2')).toBeNull();
  });

  it(
    'a cache entry written under one identity key cannot be read back after the identity changes -- ' +
      'this is treated as a plain cache miss, not an error',
    async () => {
      const { getCachedPlaintext, cachePlaintext } = await import('./message-history');
      await cachePlaintext('msg-1', 'written under identity A');

      // Simulate `adoptRecoveredKeypair` switching this device to a
      // different identity (see `recovery.ts`) -- the history key is
      // deterministically derived from the identity private key, so a
      // different identity derives a completely different key.
      currentKeypair = {
        publicKey: 'ZGlmZmVyZW50LXB1YmxpYy1rZXktZm9yLWlkZW50aXR5LWIwMA',
        privateKey: 'ZGlmZmVyZW50LXByaXZhdGUta2V5LWZvci1pZGVudGl0eS1iMDA',
        deviceId: 'device-under-test',
      };

      expect(await getCachedPlaintext('msg-1')).toBeNull();
    }
  );

  it('getCachedPlaintext never throws even when IndexedDB is entirely unavailable', async () => {
    // Simulate an environment (or a disabled/broken implementation) with no
    // usable IndexedDB at all -- `openDb` should reject internally, and
    // every public function should swallow that into "not cached", never
    // letting it escape as an uncaught rejection into a caller that's
    // mid-render.
    delete (globalThis as { indexedDB?: unknown }).indexedDB;
    const { getCachedPlaintext, cachePlaintext, deleteCachedPlaintext } = await import('./message-history');
    await expect(getCachedPlaintext('msg-1')).resolves.toBeNull();
    await expect(cachePlaintext('msg-1', 'anything')).resolves.toBeUndefined();
    await expect(deleteCachedPlaintext('msg-1')).resolves.toBeUndefined();
  });
});
