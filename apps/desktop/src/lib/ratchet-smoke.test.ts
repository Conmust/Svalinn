// Broad, fast happy-path sanity checks for the ratchet, meant as a quick
// CI gate distinct from `ratchet.test.ts` (detailed round-trip/format
// correctness) and `ratchet-regressions.test.ts` (deep edge cases pinned
// to specific external-review report findings). If this file goes red,
// something basic about the overall message lifecycle is broken; if only
// `ratchet-regressions.test.ts` goes red, a specific edge case regressed
// while the common path still works.
//
// Shares the same fake-server/per-device-harness pattern as the other two
// ratchet test files -- see `ratchet.test.ts`'s header comment for how it
// works.
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
    async reportConsumedSkippedKey(deviceId: string, peerDeviceId: string, dhPublicKey: string, messageNumber: number): Promise<void> {
      const key = `${deviceId}:${peerDeviceId}`;
      let slots = fakeServer.consumedSkippedKeys.get(key);
      if (!slots) {
        slots = new Set<string>();
        fakeServer.consumedSkippedKeys.set(key, slots);
      }
      slots.add(`${dhPublicKey}:${messageNumber}`);
    },
    async fetchConsumedSkippedKeys(
      deviceId: string,
      peerDeviceId: string
    ): Promise<{ dhPublicKey: string; messageNumber: number }[]> {
      const slots = fakeServer.consumedSkippedKeys.get(`${deviceId}:${peerDeviceId}`);
      if (!slots) return [];
      return [...slots].map((slot) => {
        const sep = slot.lastIndexOf(':');
        return { dhPublicKey: slot.slice(0, sep), messageNumber: Number(slot.slice(sep + 1)) };
      });
    },
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

describe('Ratchet smoke tests (fast, broad happy-path sanity)', () => {
  beforeEach(() => {
    resetFakeServer();
    backupSerial = 0;
  });

  it('two fresh devices can set up, make first contact, and read a message', async () => {
    const alice = await createDeviceHarness();
    const bob = await createDeviceHarness();
    expect(alice.deviceId).not.toBe(bob.deviceId);

    const env = await on(alice, ({ ratchet }) => ratchet.encryptMessage(bob.deviceId, 'hello bob'));
    expect(await on(bob, ({ ratchet }) => ratchet.decryptMessage(alice.deviceId, env))).toBe('hello bob');
  });

  it('a full back-and-forth conversation of many messages, both directions, round-trips correctly', async () => {
    const alice = await createDeviceHarness();
    const bob = await createDeviceHarness();

    const transcript: { from: 'alice' | 'bob'; text: string }[] = [
      { from: 'alice', text: 'hey, you around?' },
      { from: 'bob', text: 'yep, whats up' },
      { from: 'alice', text: 'wanted to check on the project' },
      { from: 'bob', text: 'going well, should be done friday' },
      { from: 'alice', text: 'great, thanks!' },
      { from: 'bob', text: 'no problem' },
      { from: 'alice', text: 'one more thing actually' },
      { from: 'bob', text: 'sure, go ahead' },
    ];

    for (const { from, text } of transcript) {
      const sender = from === 'alice' ? alice : bob;
      const receiver = from === 'alice' ? bob : alice;
      const senderId = from === 'alice' ? alice.deviceId : bob.deviceId;
      const env = await on(sender, ({ ratchet }) => ratchet.encryptMessage(from === 'alice' ? bob.deviceId : alice.deviceId, text));
      expect(await on(receiver, ({ ratchet }) => ratchet.decryptMessage(senderId, env))).toBe(text);
    }
  });

  it('messages delivered out of order still all decrypt', async () => {
    const alice = await createDeviceHarness();
    const bob = await createDeviceHarness();

    // Establish a confirmed session first.
    const hello = await on(alice, ({ ratchet }) => ratchet.encryptMessage(bob.deviceId, 'hi'));
    await on(bob, ({ ratchet }) => ratchet.decryptMessage(alice.deviceId, hello));
    const reply = await on(bob, ({ ratchet }) => ratchet.encryptMessage(alice.deviceId, 'hi back'));
    await on(alice, ({ ratchet }) => ratchet.decryptMessage(bob.deviceId, reply));

    const env1 = await on(alice, ({ ratchet }) => ratchet.encryptMessage(bob.deviceId, 'one'));
    const env2 = await on(alice, ({ ratchet }) => ratchet.encryptMessage(bob.deviceId, 'two'));
    const env3 = await on(alice, ({ ratchet }) => ratchet.encryptMessage(bob.deviceId, 'three'));

    // Deliver 3, 1, 2.
    expect(await on(bob, ({ ratchet }) => ratchet.decryptMessage(alice.deviceId, env3))).toBe('three');
    expect(await on(bob, ({ ratchet }) => ratchet.decryptMessage(alice.deviceId, env1))).toBe('one');
    expect(await on(bob, ({ ratchet }) => ratchet.decryptMessage(alice.deviceId, env2))).toBe('two');
  });

  it('a session survives a signed-prekey rotation and keeps working', async () => {
    const alice = await createDeviceHarness();
    const bob = await createDeviceHarness();

    const env1 = await on(alice, ({ ratchet }) => ratchet.encryptMessage(bob.deviceId, 'before rotation'));
    expect(await on(bob, ({ ratchet }) => ratchet.decryptMessage(alice.deviceId, env1))).toBe('before rotation');

    activate(bob);
    bob.storage.setItem('svalinn_ratchet_signed_prekey_created_at', '0');
    await bob.ratchet.ensureRatchetReady(); // rotates

    const env2 = await on(bob, ({ ratchet }) => ratchet.encryptMessage(alice.deviceId, 'after rotation'));
    expect(await on(alice, ({ ratchet }) => ratchet.decryptMessage(bob.deviceId, env2))).toBe('after rotation');
  });

  it('a device recovers its session from the server-side backup after losing local storage', async () => {
    const alice = await createDeviceHarness();
    const bob = await createDeviceHarness();

    const env1 = await on(alice, ({ ratchet }) => ratchet.encryptMessage(bob.deviceId, 'hi'));
    expect(await on(bob, ({ ratchet }) => ratchet.decryptMessage(alice.deviceId, env1))).toBe('hi');

    // Let Bob's fire-and-forget backup land.
    activate(bob);
    await new Promise((resolve) => setTimeout(resolve, 0));
    await new Promise((resolve) => setTimeout(resolve, 0));

    // Simulate Bob losing local storage (new browser profile, cleared data).
    bob.storage.removeItem(`svalinn_ratchet_session_${alice.deviceId}`);

    const env2 = await on(alice, ({ ratchet }) => ratchet.encryptMessage(bob.deviceId, 'still there?'));
    expect(await on(bob, ({ ratchet }) => ratchet.decryptMessage(alice.deviceId, env2))).toBe('still there?');
  });

  it('a tampered message fails closed (returns null) without breaking the session for the next real message', async () => {
    const alice = await createDeviceHarness();
    const bob = await createDeviceHarness();

    const good1 = await on(alice, ({ ratchet }) => ratchet.encryptMessage(bob.deviceId, 'real message'));
    expect(await on(bob, ({ ratchet }) => ratchet.decryptMessage(alice.deviceId, good1))).toBe('real message');

    const tampered = await on(alice, ({ ratchet }) => ratchet.encryptMessage(bob.deviceId, 'another real one'));
    tampered.ciphertext = tampered.ciphertext.slice(0, -4) + 'abcd';
    expect(await on(bob, ({ ratchet }) => ratchet.decryptMessage(alice.deviceId, tampered))).toBeNull();

    const good2 = await on(alice, ({ ratchet }) => ratchet.encryptMessage(bob.deviceId, 'carrying on'));
    expect(await on(bob, ({ ratchet }) => ratchet.decryptMessage(alice.deviceId, good2))).toBe('carrying on');
  });

  it('a device with no published prekeys is reported as not yet supporting the ratchet', async () => {
    const alice = await createDeviceHarness();
    vi.resetModules();
    const bareStorage = new FakeLocalStorage();
    (globalThis as unknown as { localStorage: FakeLocalStorage }).localStorage = bareStorage;
    const bareCrypto = await import('./crypto');
    const { deviceId: bareDeviceId } = await bareCrypto.ensureDeviceKeypair();
    // Deliberately never call ensureRatchetReady() for this device, so it
    // has no signed prekey published.

    activate(alice);
    await expect(alice.ratchet.encryptMessage(bareDeviceId, 'hi')).rejects.toThrow();
  });
});
