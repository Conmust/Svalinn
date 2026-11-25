// Regression tests for specific bugs found by four external review
// reports run against the ratchet (commit 0f6a738): two "Svalinn Client
// Durability" reports (35-scenario and 100-scenario) and two "Svalinn /
// Confidentiality Review" reports (original and follow-up). Each test
// below reproduces one reported FAILING scenario by its report ID,
// confirms it now passes, and documents which code fix addresses it. See
// `ratchet.ts`'s comments at each fix site for the full root-cause
// reasoning; this file exists so a future change that reintroduces one of
// these bugs fails a targeted test immediately, by name, instead of only
// showing up (if at all) as an unexplained e2e flake much later.
//
// Uses the exact same fake-server/per-device-harness infrastructure as
// `ratchet.test.ts` -- see that file's header comment for how it works.
// Deliberately a SEPARATE file (matching this repo's existing
// `dm-race-retest.spec.ts` / `recovery-open-conversation.spec.ts`
// convention for "test added to pin down one specific reported bug" sets)
// rather than appended to `ratchet.test.ts`, which stays focused on
// general round-trip correctness.
import { beforeEach, describe, expect, it, vi } from 'vitest';

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
}

interface FakeServerDevice {
  identityPublicKey: string;
  identitySigningPublicKey?: string;
  signedPrekeyPublicKey?: string;
  signedPrekeySignature?: string;
  oneTimePrekeys: Map<string, boolean>;
}
interface FakeSessionBackup {
  pickleCiphertext: string;
  pickleNonce: string;
  updatedAt: string;
}

const fakeServer = {
  devices: new Map<string, FakeServerDevice>(),
  sessions: new Map<string, FakeSessionBackup>(),
  nextDeviceId: 1,
};

function resetFakeServer(): void {
  fakeServer.devices.clear();
  fakeServer.sessions.clear();
  fakeServer.nextDeviceId = 1;
}

let backupSerial = 0;

vi.mock('./devices', async () => {
  class RatchetNotSupportedError extends Error {
    constructor(message = "This device has not opted into the Double Ratchet yet.") {
      super(message);
      this.name = 'RatchetNotSupportedError';
    }
  }
  class NoRatchetSessionError extends Error {
    constructor(message = 'No ratchet session backup exists yet for this device pair.') {
      super(message);
      this.name = 'NoRatchetSessionError';
    }
  }
  class RatchetSessionConflictError extends Error {
    constructor(message = 'This ratchet session backup was updated elsewhere; re-fetch before writing again.') {
      super(message);
      this.name = 'RatchetSessionConflictError';
    }
  }

  async function registerDevice(publicKey: string, _label: string): Promise<string> {
    const id = `device-${fakeServer.nextDeviceId++}`;
    fakeServer.devices.set(id, { identityPublicKey: publicKey, oneTimePrekeys: new Map() });
    return id;
  }

  async function setSigningKey(deviceId: string, signingPublicKey: string): Promise<void> {
    const dev = fakeServer.devices.get(deviceId);
    if (!dev) throw new Error('unknown device in fake server');
    dev.identitySigningPublicKey = signingPublicKey;
  }

  async function uploadPrekeys(
    deviceId: string,
    prekeys: { keyType: 'signed' | 'one_time'; publicKey: string; signature?: string }[]
  ): Promise<void> {
    const dev = fakeServer.devices.get(deviceId);
    if (!dev) throw new Error('unknown device in fake server');
    for (const pk of prekeys) {
      if (pk.keyType === 'signed') {
        dev.signedPrekeyPublicKey = pk.publicKey;
        dev.signedPrekeySignature = pk.signature;
      } else {
        dev.oneTimePrekeys.set(pk.publicKey, false);
      }
    }
  }

  async function fetchPrekeyCounts(deviceId: string): Promise<{ unconsumedOneTimePrekeys: number; hasSignedPrekey: boolean }> {
    const dev = fakeServer.devices.get(deviceId);
    if (!dev) throw new Error('unknown device in fake server');
    let unconsumed = 0;
    for (const consumed of dev.oneTimePrekeys.values()) if (!consumed) unconsumed += 1;
    return { unconsumedOneTimePrekeys: unconsumed, hasSignedPrekey: Boolean(dev.signedPrekeyPublicKey) };
  }

  async function fetchPrekeyBundle(deviceId: string) {
    const dev = fakeServer.devices.get(deviceId);
    if (!dev || !dev.signedPrekeyPublicKey || !dev.identitySigningPublicKey) {
      throw new RatchetNotSupportedError();
    }
    let oneTimePrekeyPublicKey: string | null = null;
    for (const [pub, consumed] of dev.oneTimePrekeys.entries()) {
      if (!consumed) {
        dev.oneTimePrekeys.set(pub, true);
        oneTimePrekeyPublicKey = pub;
        break;
      }
    }
    return {
      deviceId,
      identityPublicKey: dev.identityPublicKey,
      identitySigningPublicKey: dev.identitySigningPublicKey,
      signedPrekeyPublicKey: dev.signedPrekeyPublicKey,
      signedPrekeySignature: dev.signedPrekeySignature as string,
      oneTimePrekeyId: oneTimePrekeyPublicKey ? `otpk-${oneTimePrekeyPublicKey}` : null,
      oneTimePrekeyPublicKey,
    };
  }

  async function fetchRatchetSession(deviceId: string, peerDeviceId: string) {
    const backup = fakeServer.sessions.get(`${deviceId}:${peerDeviceId}`);
    if (!backup) throw new NoRatchetSessionError();
    return { pickleCiphertext: backup.pickleCiphertext, pickleNonce: backup.pickleNonce, updatedAt: backup.updatedAt };
  }

  async function putRatchetSession(
    deviceId: string,
    peerDeviceId: string,
    pickleCiphertext: string,
    pickleNonce: string,
    expectedUpdatedAt: string | null
  ) {
    const key = `${deviceId}:${peerDeviceId}`;
    const existing = fakeServer.sessions.get(key);
    if (expectedUpdatedAt !== null) {
      if (!existing || existing.updatedAt !== expectedUpdatedAt) throw new RatchetSessionConflictError();
    } else if (existing) {
      throw new RatchetSessionConflictError();
    }
    backupSerial += 1;
    const updatedAt = `backup-${backupSerial}`;
    fakeServer.sessions.set(key, { pickleCiphertext, pickleNonce, updatedAt });
    return { pickleCiphertext, pickleNonce, updatedAt };
  }

  return {
    registerDevice,
    fetchMyDevices: async () => [],
    renameDevice: async () => {
      throw new Error('not implemented in fake devices module');
    },
    removeDevice: async () => {},
    fetchParticipantDevices: async () => [],
    setSigningKey,
    uploadPrekeys,
    fetchPrekeyCounts,
    fetchPrekeyBundle,
    fetchRatchetSession,
    putRatchetSession,
    RatchetNotSupportedError,
    NoRatchetSessionError,
    RatchetSessionConflictError,
  };
});

interface DeviceHarness {
  ratchet: typeof import('./ratchet');
  crypto: typeof import('./crypto');
  storage: FakeLocalStorage;
  deviceId: string;
}

function activate(device: Pick<DeviceHarness, 'storage'>): void {
  (globalThis as unknown as { localStorage: FakeLocalStorage }).localStorage = device.storage;
}

async function on<T>(device: DeviceHarness, fn: (mods: Pick<DeviceHarness, 'ratchet' | 'crypto'>) => Promise<T>): Promise<T> {
  activate(device);
  return fn(device);
}

async function createDeviceHarness(): Promise<DeviceHarness> {
  vi.resetModules();
  const storage = new FakeLocalStorage();
  (globalThis as unknown as { localStorage: FakeLocalStorage }).localStorage = storage;
  const ratchet = await import('./ratchet');
  const crypto = await import('./crypto');
  const { deviceId } = await crypto.ensureDeviceKeypair();
  await ratchet.ensureRatchetReady();
  return { ratchet, crypto, storage, deviceId };
}

describe('Ratchet regressions (reported by external review)', () => {
  beforeEach(() => {
    resetFakeServer();
    backupSerial = 0;
  });

  describe('Fix A: per-session serialization (mutex)', () => {
    it(
      'confidentiality report case 08 / durability-100 cases 036-043: ' +
        'overlapping established-session sends each get a DISTINCT message key, and both decrypt',
      async () => {
        const alice = await createDeviceHarness();
        const bob = await createDeviceHarness();

        // Establish a confirmed (bidirectional) session first, so this
        // exercises the general "overlapping sends on an established
        // chain" case, not the first-contact-specific one below.
        const hello = await on(alice, ({ ratchet }) => ratchet.encryptMessage(bob.deviceId, 'hi'));
        await on(bob, ({ ratchet }) => ratchet.decryptMessage(alice.deviceId, hello));
        const reply = await on(bob, ({ ratchet }) => ratchet.encryptMessage(alice.deviceId, 'hi back'));
        await on(alice, ({ ratchet }) => ratchet.decryptMessage(bob.deviceId, reply));

        // Fire THREE overlapping sends from Alice without awaiting any of
        // them individually -- simulating a user (or a retry/resend path)
        // firing off several messages before the first one's state write
        // has landed. Without the per-session lock, these would all read
        // the same starting chain key and derive the SAME message key.
        activate(alice);
        const [envA, envB, envC] = await Promise.all([
          alice.ratchet.encryptMessage(bob.deviceId, 'one'),
          alice.ratchet.encryptMessage(bob.deviceId, 'two'),
          alice.ratchet.encryptMessage(bob.deviceId, 'three'),
        ]);

        // Each message occupies a DISTINCT ratchet position...
        const positions = new Set([envA.n, envB.n, envC.n]);
        expect(positions.size).toBe(3);
        // ...and every single one is independently readable by Bob --
        // not just the first, which is what "one message key across
        // three sends" (the reported failure) would otherwise cause.
        const [plainA, plainB, plainC] = await Promise.all([
          on(bob, ({ ratchet }) => ratchet.decryptMessage(alice.deviceId, envA)),
          on(bob, ({ ratchet }) => ratchet.decryptMessage(alice.deviceId, envB)),
          on(bob, ({ ratchet }) => ratchet.decryptMessage(alice.deviceId, envC)),
        ]);
        expect([plainA, plainB, plainC].sort()).toEqual(['one', 'three', 'two']);
      }
    );

    it('durability-100 case 011: concurrent receives both decrypt AND leave the saved receive counter at its true value', async () => {
      const alice = await createDeviceHarness();
      const bob = await createDeviceHarness();

      const hello = await on(alice, ({ ratchet }) => ratchet.encryptMessage(bob.deviceId, 'hi'));
      await on(bob, ({ ratchet }) => ratchet.decryptMessage(alice.deviceId, hello));
      const reply = await on(bob, ({ ratchet }) => ratchet.encryptMessage(alice.deviceId, 'hi back'));
      await on(alice, ({ ratchet }) => ratchet.decryptMessage(bob.deviceId, reply));

      const env1 = await on(alice, ({ ratchet }) => ratchet.encryptMessage(bob.deviceId, 'first'));
      const env2 = await on(alice, ({ ratchet }) => ratchet.encryptMessage(bob.deviceId, 'second'));
      const env3 = await on(alice, ({ ratchet }) => ratchet.encryptMessage(bob.deviceId, 'third'));

      // Bob processes all three concurrently (out-of-order network
      // delivery is normal; the point here is overlap, not ordering).
      activate(bob);
      const [p1, p2, p3] = await Promise.all([
        bob.ratchet.decryptMessage(alice.deviceId, env1),
        bob.ratchet.decryptMessage(alice.deviceId, env2),
        bob.ratchet.decryptMessage(alice.deviceId, env3),
      ]);
      expect([p1, p2, p3].sort()).toEqual(['first', 'second', 'third']);

      // The reported bug: the saved `recvCount` could regress to an
      // earlier value if an older concurrent receive's write landed
      // after a newer one's. A fourth, genuinely NEXT message must still
      // decrypt cleanly afterward -- it wouldn't if the persisted state
      // had fallen behind.
      const env4 = await on(alice, ({ ratchet }) => ratchet.encryptMessage(bob.deviceId, 'fourth'));
      expect(await on(bob, ({ ratchet }) => ratchet.decryptMessage(alice.deviceId, env4))).toBe('fourth');
    });
  });

  describe('Fix A + B: overlapping / retried first sends', () => {
    it('durability cases 017/021: two overlapping first sends to a brand-new peer BOTH decrypt, in either arrival order', async () => {
      const alice = await createDeviceHarness();
      const bob = await createDeviceHarness();

      // No session exists yet in either direction. Fire two concurrent
      // first sends before either has a chance to persist.
      activate(alice);
      const [env1, env2] = await Promise.all([
        alice.ratchet.encryptMessage(bob.deviceId, 'first contact A'),
        alice.ratchet.encryptMessage(bob.deviceId, 'first contact B'),
      ]);

      // Both must carry the X3DH handshake fields a brand-new responder
      // needs -- not just whichever happened to be encrypted first.
      expect(env1.initial).toBeDefined();
      expect(env2.initial).toBeDefined();

      // Deliver out of order: the SECOND encrypted message arrives FIRST.
      // Before this fix, a responder receiving a message with no
      // `initial` block and no existing session couldn't decrypt it at
      // all; here env2 always carries it regardless of arrival order.
      expect(await on(bob, ({ ratchet }) => ratchet.decryptMessage(alice.deviceId, env2))).toBe('first contact B');
      expect(await on(bob, ({ ratchet }) => ratchet.decryptMessage(alice.deviceId, env1))).toBe('first contact A');
    });

    it('durability case 017 (retry framing): a resend of a never-delivered first message still carries the handshake the receiver needs', async () => {
      const alice = await createDeviceHarness();
      const bob = await createDeviceHarness();

      // Alice's "first send" is encrypted but simulated as lost on the
      // wire (never handed to Bob). A caller-level retry just calls
      // `encryptMessage` again for the same peer.
      const lost = await on(alice, ({ ratchet }) => ratchet.encryptMessage(bob.deviceId, 'are you there?'));
      void lost; // never delivered
      const retry = await on(alice, ({ ratchet }) => ratchet.encryptMessage(bob.deviceId, 'are you there? (retry)'));

      // Before this fix, `pendingInitialHeader` was cleared the moment it
      // was attached to the FIRST encrypt call, so this retry would have
      // no `initial` block at all and Bob -- who never saw the lost
      // message -- would have no way to bootstrap a session from it.
      expect(retry.initial).toBeDefined();
      expect(await on(bob, ({ ratchet }) => ratchet.decryptMessage(alice.deviceId, retry))).toBe('are you there? (retry)');
    });

    it('stops attaching the handshake fields once the session is actually confirmed by a reply', async () => {
      const alice = await createDeviceHarness();
      const bob = await createDeviceHarness();

      const env1 = await on(alice, ({ ratchet }) => ratchet.encryptMessage(bob.deviceId, 'hi'));
      expect(env1.initial).toBeDefined();
      await on(bob, ({ ratchet }) => ratchet.decryptMessage(alice.deviceId, env1));
      const reply = await on(bob, ({ ratchet }) => ratchet.encryptMessage(alice.deviceId, 'hi back'));
      await on(alice, ({ ratchet }) => ratchet.decryptMessage(bob.deviceId, reply));

      // Now that Alice has received a confirmed reply, a further send
      // from her should NOT keep repeating the handshake fields forever.
      const env2 = await on(alice, ({ ratchet }) => ratchet.encryptMessage(bob.deviceId, 'how about now'));
      expect(env2.initial).toBeUndefined();
    });
  });

  describe('Fix C: stale session after a device identity change', () => {
    // Note on scope: Fix C protects a device's OWN send/receive logic from
    // its OWN retained-but-now-foreign session state after it adopts a
    // different identity keypair. It does not (and cannot) make a PEER
    // who still has no idea the identity changed correctly decrypt
    // against the new identity's math -- that would require the peer to
    // detect a mid-conversation identity change, which is a distinct,
    // harder problem (Signal's answer to it is a user-facing "safety
    // number changed" warning, not silent protocol-level recovery) and is
    // explicitly out of scope for this fix. Nor can recovery fall back to
    // the server-side session backup in this situation: that backup is
    // itself encrypted (pickled) under a key derived from the identity
    // private key, so a backup made under the OLD identity is, correctly,
    // undecryptable after adopting a new one. These tests instead pin the
    // two guarantees Fix C actually provides.

    it(
      'durability-100 case 068 (receive side): a fresh first-contact handshake ' +
        'succeeds after adopting a new identity, discarding the stale local session instead of using it',
      async () => {
        const alice = await createDeviceHarness();
        const bob = await createDeviceHarness();
        activate(bob);
        const sodium = (await import('libsodium-wrappers-sumo')).default;
        await sodium.ready;

        // Seed Bob's storage with a structurally-valid session for Alice,
        // tagged as belonging to a DIFFERENT (old) identity than Bob's
        // current one -- simulating local state retained across an
        // identity swap, without needing to actually negotiate (and
        // thereby consume Bob's real one-time prekey stash for) a real
        // session first. What matters for this fix is purely whether
        // stale state tagged with a foreign identity gets used or
        // discarded; the exact cryptographic content of that stale state
        // is irrelevant since it should never be touched.
        const fakeStaleSession = {
          dhsPublic: 'stale-dhs-pub',
          dhsPrivate: 'stale-dhs-priv',
          dhrPublic: null,
          rootKey: 'stale-root',
          chainKeySend: null,
          chainKeyRecv: null,
          sendCount: 0,
          recvCount: 0,
          previousChainLength: 0,
          skippedKeys: {},
          adLow: 'stale-ad-low',
          adHigh: 'stale-ad-high',
          myIdentityPublicKey: 'not-bobs-real-identity-key',
        };
        bob.storage.setItem(`svalinn_ratchet_session_${alice.deviceId}`, JSON.stringify(fakeStaleSession));

        // Bob now adopts a (different, genuinely his) identity keypair --
        // simulating a recovery flow -- while that stale session for
        // Alice remains in local storage (the reported failure mode;
        // clearing it first already worked, per cases 072-075).
        const newIdentity = sodium.crypto_box_keypair();
        const newIdentityPublicB64 = sodium.to_base64(newIdentity.publicKey, sodium.base64_variants.ORIGINAL);
        bob.crypto.adoptRecoveredKeypair({
          publicKey: newIdentityPublicB64,
          privateKey: sodium.to_base64(newIdentity.privateKey, sodium.base64_variants.ORIGINAL),
          deviceId: bob.deviceId,
        });
        // The device-identity-registration update itself (telling the
        // server about the new identity key so others can reach this
        // device at all) is handled elsewhere, outside ratchet.ts's
        // scope -- modeled here directly so this test isolates exactly
        // what Fix C covers: local ratchet-session consistency, not
        // identity-registration propagation.
        const bobServerRecord = fakeServer.devices.get(bob.deviceId);
        if (bobServerRecord) bobServerRecord.identityPublicKey = newIdentityPublicB64;
        expect(bob.storage.getItem(`svalinn_ratchet_session_${alice.deviceId}`)).not.toBeNull();

        // Alice makes genuine first contact with Bob (a real, fresh X3DH
        // handshake against Bob's currently-published prekey bundle).
        // Bob must recognize his cached session as belonging to a
        // different identity, discard it instead of feeding it to the
        // ratchet math (which would throw on the bogus key material), and
        // bootstrap a brand-new responder session from the envelope's
        // handshake fields under his current identity.
        const env = await on(alice, ({ ratchet }) => ratchet.encryptMessage(bob.deviceId, 'hello'));
        expect(env.initial).toBeDefined();
        expect(await on(bob, ({ ratchet }) => ratchet.decryptMessage(alice.deviceId, env))).toBe('hello');
      }
    );

    it('durability-100 case 069 (send side): encrypting to a peer after adopting a new identity bootstraps fresh instead of reusing the stale session', async () => {
      const alice = await createDeviceHarness();
      const bob = await createDeviceHarness();

      // Bob receives a first message from Alice, creating a local
      // session for her under Bob's ORIGINAL identity.
      const env1 = await on(alice, ({ ratchet }) => ratchet.encryptMessage(bob.deviceId, 'hi'));
      expect(await on(bob, ({ ratchet }) => ratchet.decryptMessage(alice.deviceId, env1))).toBe('hi');
      expect(bob.storage.getItem(`svalinn_ratchet_session_${alice.deviceId}`)).not.toBeNull();

      // Bob adopts a new identity, same device id, stale session retained.
      activate(bob);
      const sodium = (await import('libsodium-wrappers-sumo')).default;
      await sodium.ready;
      const newIdentity = sodium.crypto_box_keypair();
      const newIdentityPublicB64 = sodium.to_base64(newIdentity.publicKey, sodium.base64_variants.ORIGINAL);
      bob.crypto.adoptRecoveredKeypair({
        publicKey: newIdentityPublicB64,
        privateKey: sodium.to_base64(newIdentity.privateKey, sodium.base64_variants.ORIGINAL),
        deviceId: bob.deviceId,
      });

      // Bob composes a brand-new message to Alice. Without Fix C this
      // either throws (AD/key mismatch against the stale session) or
      // silently reuses state computed under an identity Bob no longer
      // holds. With Fix C, the stale session is recognized as belonging
      // to the old identity and discarded, so this bootstraps a FRESH
      // initiator handshake under Bob's new identity -- visible as a
      // fresh `initial` block whose identity key is the NEW one.
      const outgoing = await on(bob, ({ ratchet }) => bob.ratchet.encryptMessage(alice.deviceId, 'yes, new key now'));
      expect(outgoing.initial).toBeDefined();
      expect(outgoing.initial?.identityPublicKey).toBe(newIdentityPublicB64);
    });
  });

  describe('Fix D: malformed local session state falls back instead of crashing', () => {
    it.each([
      ['durability case 004 / 100-scenario case 004', '{}'],
      ['durability-100 case 055', '[]'],
      ['durability-100 case 056', '"text"'],
      ['durability-100 case 057', '{"skippedKeys":{}}'],
      ['durability-100 case 058', '{"adLow":null}'],
      ['durability-100 case 059', '{"recvCount":0}'],
    ])('%s: a structurally-invalid local session value recovers from the server backup instead of throwing', async (_label, malformedJson) => {
      const alice = await createDeviceHarness();
      const bob = await createDeviceHarness();

      const env1 = await on(alice, ({ ratchet }) => ratchet.encryptMessage(bob.deviceId, 'hi'));
      expect(await on(bob, ({ ratchet }) => ratchet.decryptMessage(alice.deviceId, env1))).toBe('hi');

      // Let Bob's fire-and-forget backup of the session land.
      activate(bob);
      await new Promise((resolve) => setTimeout(resolve, 0));
      await new Promise((resolve) => setTimeout(resolve, 0));
      expect(fakeServer.sessions.has(`${bob.deviceId}:${alice.deviceId}`)).toBe(true);

      // Corrupt Bob's LOCAL copy to a structurally-invalid-but-parseable
      // value (not a JSON syntax error -- `loadLocalSession`'s try/catch
      // already handled that case; this is the harder "parses fine, but
      // isn't actually a usable session" case).
      bob.storage.setItem(`svalinn_ratchet_session_${alice.deviceId}`, malformedJson);

      // Must recover via the healthy server-side backup instead of
      // treating the malformed value as real and throwing deep inside
      // the ratchet math.
      const env2 = await on(alice, ({ ratchet }) => ratchet.encryptMessage(bob.deviceId, 'still there?'));
      await expect(on(bob, ({ ratchet }) => ratchet.decryptMessage(alice.deviceId, env2))).resolves.toBe('still there?');
    });
  });

  describe('Fix E: signed-prekey rotation', () => {
    it('durability cases 020/064: a first-contact message bootstrapped against a JUST-rotated-out signed prekey still decrypts', async () => {
      const alice = await createDeviceHarness();
      const bob = await createDeviceHarness();

      // Alice fetches Bob's bundle (capturing his CURRENT signed prekey)
      // and encrypts, but delivery is simulated as delayed until AFTER
      // Bob rotates.
      const queued = await on(alice, ({ ratchet }) => ratchet.encryptMessage(bob.deviceId, 'queued before rotation'));
      expect(queued.initial?.usedSignedPrekeyPublicKey).toBeDefined();

      // Force Bob's signed prekey to look old enough to rotate, then run
      // readiness again -- exactly what happens on a later app launch.
      activate(bob);
      bob.storage.setItem('svalinn_ratchet_signed_prekey_created_at', '0');
      const oldSignedPrekeyPublic = bob.storage.getItem('svalinn_ratchet_signed_prekey_public_key');
      await bob.ratchet.ensureRatchetReady();
      const newSignedPrekeyPublic = bob.storage.getItem('svalinn_ratchet_signed_prekey_public_key');
      expect(newSignedPrekeyPublic).not.toBe(oldSignedPrekeyPublic);
      expect(queued.initial?.usedSignedPrekeyPublicKey).toBe(oldSignedPrekeyPublic);

      // The message queued against the now-retired key must still open --
      // it was answerable before this fix only by accident (no rotation
      // yet), and would otherwise now fail since the responder would
      // blindly use its CURRENT (different) signed prekey.
      expect(await on(bob, ({ ratchet }) => ratchet.decryptMessage(alice.deviceId, queued))).toBe('queued before rotation');
    });

    it('durability case 066: a first-contact message bootstrapped TWO rotations ago still decrypts (bounded multi-generation retention)', async () => {
      const alice = await createDeviceHarness();
      const bob = await createDeviceHarness();

      // Alice's handshake captures Bob's signed prekey from generation 1.
      const queued = await on(alice, ({ ratchet }) => ratchet.encryptMessage(bob.deviceId, 'queued two rotations ago'));
      const usedPublicKey = queued.initial?.usedSignedPrekeyPublicKey;
      expect(usedPublicKey).toBeDefined();

      activate(bob);
      const generation1Public = bob.storage.getItem('svalinn_ratchet_signed_prekey_public_key');
      expect(usedPublicKey).toBe(generation1Public);

      // Bob rotates TWICE before the message is actually delivered --
      // generation 1 is now two rotations back, not just one. A single
      // retained "previous" generation (the original fix) would no
      // longer have it; the bounded multi-generation retention does.
      bob.storage.setItem('svalinn_ratchet_signed_prekey_created_at', '0');
      await bob.ratchet.ensureRatchetReady(); // rotates to generation 2
      const generation2Public = bob.storage.getItem('svalinn_ratchet_signed_prekey_public_key');
      expect(generation2Public).not.toBe(generation1Public);
      bob.storage.setItem('svalinn_ratchet_signed_prekey_created_at', '0');
      await bob.ratchet.ensureRatchetReady(); // rotates to generation 3
      const generation3Public = bob.storage.getItem('svalinn_ratchet_signed_prekey_public_key');
      expect(generation3Public).not.toBe(generation2Public);

      // Generation 1 is retained in the bounded retired-key list (kept
      // two generations back, within `SIGNED_PREKEY_RETIRED_KEEP`), so the
      // message queued against it can still be answered.
      expect(await on(bob, ({ ratchet }) => ratchet.decryptMessage(alice.deviceId, queued))).toBe('queued two rotations ago');
    });

    it('durability-100 cases 082-083: a local-storage failure during rotation never leaves an orphaned key advertised to the server', async () => {
      const bob = await createDeviceHarness();
      activate(bob);

      const beforePublic = bob.storage.getItem('svalinn_ratchet_signed_prekey_public_key');
      const beforeSignature = fakeServer.devices.get(bob.deviceId)?.signedPrekeySignature;

      // Make the device old enough to rotate, then make EVERY local write
      // fail for this one call -- simulating a full/unavailable storage
      // at exactly the wrong moment.
      bob.storage.setItem('svalinn_ratchet_signed_prekey_created_at', '0');
      const originalSetItem = bob.storage.setItem.bind(bob.storage);
      bob.storage.setItem = () => {
        throw new Error('simulated storage failure');
      };
      await expect(bob.ratchet.ensureRatchetReady()).rejects.toThrow();
      bob.storage.setItem = originalSetItem;

      // The server must NOT have been told about a new key whose private
      // half was never actually saved -- the old (still fully usable)
      // key must remain the one advertised.
      const afterFailedAttemptSignature = fakeServer.devices.get(bob.deviceId)?.signedPrekeySignature;
      expect(afterFailedAttemptSignature).toBe(beforeSignature);
      expect(bob.storage.getItem('svalinn_ratchet_signed_prekey_public_key')).toBe(beforePublic);

      // A later retry (storage healthy again) rotates cleanly from
      // scratch, since nothing was orphaned in between.
      await bob.ratchet.ensureRatchetReady();
      const afterRetryPublic = bob.storage.getItem('svalinn_ratchet_signed_prekey_public_key');
      expect(afterRetryPublic).not.toBeNull();
    });
  });

  describe('Fix F: one-time prekey publication', () => {
    it('durability-100 case 081: a local-storage failure while topping up one-time prekeys never advertises keys with no saved private half', async () => {
      const bob = await createDeviceHarness();
      activate(bob);

      const beforeCount = fakeServer.devices.get(bob.deviceId)?.oneTimePrekeys.size ?? 0;
      expect(beforeCount).toBeGreaterThan(0); // ensureRatchetReady already published a batch

      // Exhaust the server-visible stash to below the low-water mark so
      // the next `ensureRatchetReady()` call attempts to top it up, and
      // make the local write fail for that attempt.
      const dev = fakeServer.devices.get(bob.deviceId);
      expect(dev).toBeDefined();
      for (const pub of dev!.oneTimePrekeys.keys()) dev!.oneTimePrekeys.set(pub, true);

      const originalSetItem = bob.storage.setItem.bind(bob.storage);
      bob.storage.setItem = (key: string, value: string) => {
        if (key === 'svalinn_ratchet_one_time_prekeys') throw new Error('simulated storage failure');
        originalSetItem(key, value);
      };
      await bob.ratchet.ensureRatchetReady();
      bob.storage.setItem = originalSetItem;

      // Nothing new should have been advertised: every prekey the server
      // knows about is still one whose private half Bob actually has
      // locally (the already-consumed originals), not a phantom batch
      // uploaded without a matching local save.
      const stillUnconsumed = [...fakeServer.devices.get(bob.deviceId)!.oneTimePrekeys.values()].filter((c) => !c).length;
      expect(stillUnconsumed).toBe(0);

      // A later retry, with storage healthy, successfully tops the stash
      // back up.
      await bob.ratchet.ensureRatchetReady();
      const afterRetryUnconsumed = [...fakeServer.devices.get(bob.deviceId)!.oneTimePrekeys.values()].filter((c) => !c).length;
      expect(afterRetryUnconsumed).toBeGreaterThan(0);
    });
  });

  describe('Fix: backup write-conflict retries instead of silently giving up', () => {
    it(
      'durability-100 case 098: a stale backup-conflict on save still lands this device\'s ' +
        "newest state, rather than only resyncing the timestamp and giving up on it",
      async () => {
        const alice = await createDeviceHarness();
        const bob = await createDeviceHarness();

        const env1 = await on(alice, ({ ratchet }) => ratchet.encryptMessage(bob.deviceId, 'hi'));
        expect(await on(bob, ({ ratchet }) => ratchet.decryptMessage(alice.deviceId, env1))).toBe('hi');

        // Let Bob's own fire-and-forget backup of the post-message-1 state
        // land first.
        activate(bob);
        await new Promise((resolve) => setTimeout(resolve, 0));
        await new Promise((resolve) => setTimeout(resolve, 0));
        const key = `${bob.deviceId}:${alice.deviceId}`;
        const afterMsg1 = fakeServer.sessions.get(key);
        expect(afterMsg1).toBeDefined();

        // Simulate another tab/process on Bob's OWN device concurrently
        // pushing a newer backup in between -- Bob's local bookkeeping of
        // `backupUpdatedAt` still points at the OLDER version above, so
        // his next save is guaranteed to conflict.
        fakeServer.sessions.set(key, {
          pickleCiphertext: afterMsg1!.pickleCiphertext,
          pickleNonce: afterMsg1!.pickleNonce,
          updatedAt: 'backup-injected-conflict',
        });

        // Bob processes a SECOND message, advancing his local ratchet
        // state further. The fire-and-forget backup this triggers will
        // conflict against the injected version above.
        const env2 = await on(alice, ({ ratchet }) => ratchet.encryptMessage(bob.deviceId, 'second message'));
        expect(await on(bob, ({ ratchet }) => ratchet.decryptMessage(alice.deviceId, env2))).toBe('second message');

        // Let the conflict-then-retry settle.
        activate(bob);
        await new Promise((resolve) => setTimeout(resolve, 0));
        await new Promise((resolve) => setTimeout(resolve, 0));
        await new Promise((resolve) => setTimeout(resolve, 0));

        // The ORIGINAL behavior, on hitting this conflict, only resynced
        // its local `backupUpdatedAt` bookkeeping to match the server and
        // gave up -- the server's stored backup would be left exactly at
        // the injected conflicting value, never advancing to reflect
        // message 2 at all. The fix retries with the corrected baseline
        // and actually lands this device's newer state.
        const afterMsg2 = fakeServer.sessions.get(key);
        expect(afterMsg2).toBeDefined();
        expect(afterMsg2!.updatedAt).not.toBe('backup-injected-conflict');
        expect(afterMsg2!.updatedAt).not.toBe(afterMsg1!.updatedAt);
      }
    );
  });

  describe('Fix: one-time-prekey replenishment also checks local stash health', () => {
    it('durability-100 case 099: a corrupted local one-time-prekey stash triggers replenishment even though the server count still looks healthy', async () => {
      const bob = await createDeviceHarness();
      activate(bob);

      // The server, from Bob's initial `ensureRatchetReady()` call during
      // harness setup, already has a healthy batch of unconsumed one-time
      // prekeys on file.
      const dev = fakeServer.devices.get(bob.deviceId);
      expect(dev).toBeDefined();
      const unconsumedBefore = [...dev!.oneTimePrekeys.values()].filter((c) => !c).length;
      expect(unconsumedBefore).toBeGreaterThan(0);

      // Corrupt Bob's LOCAL one-time-prekey stash directly (simulating a
      // partial write, a JSON parse failure, or local storage cleared for
      // just this one key) -- the SERVER still thinks everything's fine,
      // since nothing told it otherwise.
      bob.storage.setItem('svalinn_ratchet_one_time_prekeys', 'not valid json{{{');

      // Calling `ensureRatchetReady()` again (e.g. the next app startup)
      // must notice the local stash is unusable and top it up with a
      // fresh, genuinely-local batch, even though the server-reported
      // count alone would say there's nothing to do.
      await bob.ratchet.ensureRatchetReady();

      const localRaw = bob.storage.getItem('svalinn_ratchet_one_time_prekeys');
      expect(localRaw).not.toBeNull();
      const localKeys = JSON.parse(localRaw as string) as unknown[];
      expect(localKeys.length).toBeGreaterThan(0);

      const unconsumedAfter = [...dev!.oneTimePrekeys.values()].filter((c) => !c).length;
      expect(unconsumedAfter).toBeGreaterThan(unconsumedBefore);
    });
  });
});
