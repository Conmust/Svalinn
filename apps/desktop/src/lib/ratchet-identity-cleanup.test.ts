// Regression test for `forgetLocalRatchetIdentity` -- part of the fix for
// the cross-account device-identity leak on a shared computer (see
// `crypto.ts`'s `ownerMatchesCurrentUser` and `recovery.ts`'s
// `forgetStaleIdentityFromPreviousAccount` for the full scenario). This
// module's signing identity/signed prekey/one-time prekeys/per-peer
// sessions are deliberately independent of `crypto.ts`'s own keypair (see
// this file's "Identity & prekey lifecycle" section), so clearing
// `crypto.ts`'s identity alone would not stop a second account from
// inheriting this module's material too -- this is the function that
// actually clears it.
import { describe, expect, it } from 'vitest';

class FakeLocalStorage {
  private store = new Map<string, string>();
  getItem(key: string): string | null {
    return this.store.has(key) ? (this.store.get(key) as string) : null;
  }
  setItem(key: string, value: string): void {
    this.store.set(key, value);
  }
  removeItem(key: string): void {
    this.store.delete(key);
  }
  get length(): number {
    return this.store.size;
  }
  key(index: number): string | null {
    return Array.from(this.store.keys())[index] ?? null;
  }
}

function activate(storage: FakeLocalStorage): void {
  (globalThis as unknown as { localStorage: FakeLocalStorage }).localStorage = storage;
}

describe('forgetLocalRatchetIdentity', () => {
  it('wipes the signing identity, signed prekey (current + retired), one-time prekeys, and every per-peer session', async () => {
    const storage = new FakeLocalStorage();
    activate(storage);

    // Seed every piece of local ratchet state this function is responsible
    // for clearing, exactly as a real browser would hold it after some
    // use -- including TWO different peer sessions, since there's no
    // registry of peer ids to consult; the function has to scan for them.
    storage.setItem('svalinn_ratchet_signing_public_key', 'sig-pub');
    storage.setItem('svalinn_ratchet_signing_private_key', 'sig-priv');
    storage.setItem('svalinn_ratchet_signed_prekey_public_key', 'spk-pub');
    storage.setItem('svalinn_ratchet_signed_prekey_private_key', 'spk-priv');
    storage.setItem('svalinn_ratchet_signed_prekey_created_at', String(Date.now()));
    storage.setItem('svalinn_ratchet_signed_prekey_retired', '[{"publicKey":"old","privateKey":"old"}]');
    storage.setItem('svalinn_ratchet_one_time_prekeys', '[{"publicKey":"a","privateKey":"b"}]');
    storage.setItem('svalinn_ratchet_session_device-bob', '{"dhsPublic":"x"}');
    storage.setItem('svalinn_ratchet_session_device-carol', '{"dhsPublic":"y"}');
    // Something unrelated that must survive untouched.
    storage.setItem('svalinn_e2ee_public_key', 'unrelated-keep-me');

    const { forgetLocalRatchetIdentity } = await import('./ratchet');
    forgetLocalRatchetIdentity();

    expect(storage.getItem('svalinn_ratchet_signing_public_key')).toBeNull();
    expect(storage.getItem('svalinn_ratchet_signing_private_key')).toBeNull();
    expect(storage.getItem('svalinn_ratchet_signed_prekey_public_key')).toBeNull();
    expect(storage.getItem('svalinn_ratchet_signed_prekey_private_key')).toBeNull();
    expect(storage.getItem('svalinn_ratchet_signed_prekey_created_at')).toBeNull();
    expect(storage.getItem('svalinn_ratchet_signed_prekey_retired')).toBeNull();
    expect(storage.getItem('svalinn_ratchet_one_time_prekeys')).toBeNull();
    expect(storage.getItem('svalinn_ratchet_session_device-bob')).toBeNull();
    expect(storage.getItem('svalinn_ratchet_session_device-carol')).toBeNull();

    // Unrelated storage (another module's) is left alone.
    expect(storage.getItem('svalinn_e2ee_public_key')).toBe('unrelated-keep-me');
  });

  it('is a safe no-op when nothing was ever set up', async () => {
    const storage = new FakeLocalStorage();
    activate(storage);
    const { forgetLocalRatchetIdentity } = await import('./ratchet');
    expect(() => forgetLocalRatchetIdentity()).not.toThrow();
  });
});
