// End-to-end correctness tests for the Double Ratchet implementation in
// `ratchet.ts`, run against a completely in-memory fake of `devices.ts`'s
// server calls (prekey publication/consumption, session backups) -- no
// real network, no real Postgres. Each simulated "device" (Alice's,
// Bob's) gets its OWN fresh module instance of `ratchet.ts`/`crypto.ts`
// (via `vi.resetModules()`) and its own fake `localStorage`, exactly
// mirroring two actually-separate devices that happen to share a process
// here only for test convenience. The fake server (`fakeServer` below) is
// the one thing genuinely shared between them, standing in for the real
// `svalinn-server`.
import { beforeEach, describe, expect, it, vi } from 'vitest';

// --- Fake localStorage, one instance per simulated device -----------------

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

// --- Fake server, shared across every simulated device's module instance --
//
// Lives at the test file's own module scope (NOT inside the `vi.mock`
// factory) so that `vi.resetModules()` -- which re-runs mock factories --
// never resets it: the factory below just closes over this same object
// every time it's re-invoked.

interface FakeServerDevice {
  identityPublicKey: string;
  identitySigningPublicKey?: string;
  signedPrekeyPublicKey?: string;
  signedPrekeySignature?: string;
  oneTimePrekeys: Map<string, boolean>; // publicKey -> consumed
}
interface FakeSessionBackup {
  pickleCiphertext: string;
  pickleNonce: string;
  updatedAt: string;
}

const fakeServer = {
  devices: new Map<string, FakeServerDevice>(),
  sessions: new Map<string, FakeSessionBackup>(), // key: `${ownerDeviceId}:${peerDeviceId}`
  // key: `${ownerDeviceId}:${peerDeviceId}`, value: set of `${dhPublicKey}:${messageNumber}`
  consumedSkippedKeys: new Map<string, Set<string>>(),
  nextDeviceId: 1,
};

function resetFakeServer(): void {
  fakeServer.devices.clear();
  fakeServer.sessions.clear();
  fakeServer.consumedSkippedKeys.clear();
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

  async function reportConsumedSkippedKey(
    deviceId: string,
    peerDeviceId: string,
    dhPublicKey: string,
    messageNumber: number
  ): Promise<void> {
    const key = `${deviceId}:${peerDeviceId}`;
    let slots = fakeServer.consumedSkippedKeys.get(key);
    if (!slots) {
      slots = new Set<string>();
      fakeServer.consumedSkippedKeys.set(key, slots);
    }
    slots.add(`${dhPublicKey}:${messageNumber}`);
  }

  async function fetchConsumedSkippedKeys(
    deviceId: string,
    peerDeviceId: string
  ): Promise<{ dhPublicKey: string; messageNumber: number }[]> {
    const slots = fakeServer.consumedSkippedKeys.get(`${deviceId}:${peerDeviceId}`);
    if (!slots) return [];
    return [...slots].map((slot) => {
      const sep = slot.lastIndexOf(':');
      return { dhPublicKey: slot.slice(0, sep), messageNumber: Number(slot.slice(sep + 1)) };
    });
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
    reportConsumedSkippedKey,
    fetchConsumedSkippedKeys,
    RatchetNotSupportedError,
    NoRatchetSessionError,
    RatchetSessionConflictError,
  };
});

// --- Per-"device" module harness ------------------------------------------
//
// `localStorage` is read by `crypto.ts`/`ratchet.ts` as a bare global, not
// an injected dependency, so simulating two independent devices in one
// process means swapping `globalThis.localStorage` to the right device's
// store immediately before touching that device's functions (`on` below),
// and never interleaving two devices' calls within a single `await` chain.

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

describe('Double Ratchet session (ratchet.ts)', () => {
  beforeEach(() => {
    resetFakeServer();
    backupSerial = 0;
  });

  it('round-trips messages in order, out of order, and across both sides replying', async () => {
    const alice = await createDeviceHarness();
    const bob = await createDeviceHarness();

    // Alice's first message bootstraps the session as initiator (X3DH).
    const env1 = await on(alice, ({ ratchet }) => ratchet.encryptMessage(bob.deviceId, 'hello bob'));
    expect(env1.initial).toBeDefined();
    expect(await on(bob, ({ ratchet }) => ratchet.decryptMessage(alice.deviceId, env1))).toBe('hello bob');

    // Two more in the same sending chain, delivered OUT OF ORDER.
    const env2 = await on(alice, ({ ratchet }) => ratchet.encryptMessage(bob.deviceId, 'are you there?'));
    const env3 = await on(alice, ({ ratchet }) => ratchet.encryptMessage(bob.deviceId, 'hello??'));
    expect(await on(bob, ({ ratchet }) => ratchet.decryptMessage(alice.deviceId, env3))).toBe('hello??');
    expect(await on(bob, ({ ratchet }) => ratchet.decryptMessage(alice.deviceId, env2))).toBe('are you there?');

    // Bob's first send -- his first DH ratchet step, since he's only ever received so far.
    const replyEnv = await on(bob, ({ ratchet }) => ratchet.encryptMessage(alice.deviceId, 'yep, here'));
    expect(await on(alice, ({ ratchet }) => ratchet.decryptMessage(bob.deviceId, replyEnv))).toBe('yep, here');

    // Alice replies again -- her second DH ratchet step.
    const env4 = await on(alice, ({ ratchet }) => ratchet.encryptMessage(bob.deviceId, 'great, glad you got those'));
    expect(await on(bob, ({ ratchet }) => ratchet.decryptMessage(alice.deviceId, env4))).toBe('great, glad you got those');

    // And a further back-and-forth, to exercise repeated ratchet steps.
    const env5 = await on(bob, ({ ratchet }) => ratchet.encryptMessage(alice.deviceId, 'cool, talk soon'));
    expect(await on(alice, ({ ratchet }) => ratchet.decryptMessage(bob.deviceId, env5))).toBe('cool, talk soon');
  });

  it('returns null for a tampered ciphertext instead of throwing', async () => {
    const alice = await createDeviceHarness();
    const bob = await createDeviceHarness();

    const env = await on(alice, ({ ratchet }) => ratchet.encryptMessage(bob.deviceId, 'secret'));
    const flipped = env.ciphertext.slice(0, -4) + (env.ciphertext.slice(-4) === 'AAAA' ? 'BBBB' : 'AAAA');
    const tampered = { ...env, ciphertext: flipped };

    const result = await on(bob, ({ ratchet }) => ratchet.decryptMessage(alice.deviceId, tampered));
    expect(result).toBeNull();
  });

  it('refuses to bootstrap a session with a device that has not opted into the ratchet', async () => {
    const alice = await createDeviceHarness();

    // A device that was never given `ensureRatchetReady()` -- i.e. no
    // signed prekey published -- just an identity, same as any device
    // still only using the legacy `crypto.ts` path.
    vi.resetModules();
    const legacyStorage = new FakeLocalStorage();
    (globalThis as unknown as { localStorage: FakeLocalStorage }).localStorage = legacyStorage;
    const legacyCrypto = await import('./crypto');
    const { deviceId: legacyDeviceId } = await legacyCrypto.ensureDeviceKeypair();

    const { RatchetNotSupportedError } = await import('./devices');
    await expect(on(alice, ({ ratchet }) => ratchet.encryptMessage(legacyDeviceId, 'hi'))).rejects.toBeInstanceOf(
      RatchetNotSupportedError
    );
  });

  it('recovers a session from its server-side encrypted backup when the local copy is missing', async () => {
    const alice = await createDeviceHarness();
    const bob = await createDeviceHarness();

    const env1 = await on(alice, ({ ratchet }) => ratchet.encryptMessage(bob.deviceId, 'hi'));
    expect(await on(bob, ({ ratchet }) => ratchet.decryptMessage(alice.deviceId, env1))).toBe('hi');

    // Let Bob's fire-and-forget backup of the session land.
    activate(bob);
    await new Promise((resolve) => setTimeout(resolve, 0));
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(fakeServer.sessions.has(`${bob.deviceId}:${alice.deviceId}`)).toBe(true);

    // Simulate partial local storage loss on Bob's device: the ratchet
    // session specifically is gone, but his identity key (which the
    // backup's encryption key is derived from) survives.
    bob.storage.removeItem(`svalinn_ratchet_session_${alice.deviceId}`);

    // A further message from Alice should still decrypt, via recovery from
    // Bob's own server-side backup rather than failing outright.
    const env2 = await on(alice, ({ ratchet }) => ratchet.encryptMessage(bob.deviceId, 'still there?'));
    expect(await on(bob, ({ ratchet }) => ratchet.decryptMessage(alice.deviceId, env2))).toBe('still there?');
  });

  it('round-trips an envelope through the JSON wire format DMChatArea.svelte actually sends', async () => {
    // `DMChatArea.svelte`'s `encryptForDevice` splits a `RatchetEnvelope`
    // into `{ ciphertext, nonce }` (their own `message_recipients` columns)
    // plus a `ratchetHeaderJson` string carrying `{ dh, pn, n, initial }` --
    // see migration 0040. `ensureRatchetMessageDecrypted` reassembles the
    // envelope from those two pieces before calling `decryptMessage`. This
    // test exercises that exact split/reassemble step, not just calling
    // `decryptMessage` with the envelope `encryptMessage` handed back
    // untouched (every other test here does that).
    const alice = await createDeviceHarness();
    const bob = await createDeviceHarness();

    const envelope = await on(alice, ({ ratchet }) => ratchet.encryptMessage(bob.deviceId, 'split me up'));
    const ratchetHeaderJson = JSON.stringify({
      dh: envelope.dh,
      pn: envelope.pn,
      n: envelope.n,
      initial: envelope.initial,
    });

    // What a `message_recipients` row (and thus `MessageRecipientEntry`)
    // actually carries: `ciphertext`/`nonce` as their own fields, the rest
    // folded into one opaque JSON string.
    const row = { ciphertext: envelope.ciphertext, nonce: envelope.nonce, ratchet_header_json: ratchetHeaderJson };

    const header = JSON.parse(row.ratchet_header_json);
    const reassembled = { dh: header.dh, pn: header.pn, n: header.n, ciphertext: row.ciphertext, nonce: row.nonce, initial: header.initial };

    expect(await on(bob, ({ ratchet }) => ratchet.decryptMessage(alice.deviceId, reassembled))).toBe('split me up');
  });
});
