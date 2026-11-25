// Regression tests for confidentiality-review followup cases 12-13:
// "device-identity-split during overlapping registration" -- see
// `ensureDeviceKeypair`'s doc comment and the "Cross-tab/window setup
// leadership" block comment above `claimSetupLeadership` in `crypto.ts`
// for the full scenario this guards against.
//
// Simulates two browser TABS sharing one `localStorage` (the actual
// production scenario for the web build; the Tauri desktop build's
// equivalent -- two launches of the native app -- is closed off instead by
// the `tauri-plugin-single-instance` plugin added alongside this, which
// has no meaningful equivalent to unit-test here). Each "tab" is a freshly
// re-imported `./crypto` module (`vi.resetModules()`), matching the
// per-device-harness pattern `ratchet-regressions.test.ts` already uses --
// a fresh import gets its own module-scope `keypairPromise`, exactly like
// a real second tab would, while both point at the SAME shared
// `FakeLocalStorage` instance, exactly like two real tabs on one origin
// share one browser-level `localStorage`.
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

/** Set from a test to make the mock `registerDevice` below block until
 * explicitly released, so a test can deterministically force two
 * `ensureDeviceKeypair()` calls to overlap instead of hoping they happen
 * to race in real time. */
let registerDeviceGate: Promise<void> | null = null;
let registeredDevices: { publicKey: string; label: string }[] = [];
let nextDeviceId = 1;

vi.mock('./devices', () => ({
  registerDevice: vi.fn(async (publicKey: string, label: string) => {
    if (registerDeviceGate) await registerDeviceGate;
    registeredDevices.push({ publicKey, label });
    return `device-${nextDeviceId++}`;
  }),
}));

function activate(storage: FakeLocalStorage): void {
  (globalThis as unknown as { localStorage: FakeLocalStorage }).localStorage = storage;
}

/** Imports a fresh instance of `./crypto`, as a new tab/window sharing
 * `storage` would see it: no in-memory state carried over, but the same
 * underlying `localStorage`. */
async function freshTab(storage: FakeLocalStorage): Promise<typeof import('./crypto')> {
  vi.resetModules();
  activate(storage);
  return import('./crypto');
}

describe('ensureDeviceKeypair cross-tab setup leadership (confidentiality followup cases 12-13)', () => {
  beforeEach(() => {
    registerDeviceGate = null;
    registeredDevices = [];
    nextDeviceId = 1;
  });

  it(
    'two tabs calling ensureDeviceKeypair at once on a brand-new install ' +
      'register exactly ONE device and both end up with the SAME keypair',
    async () => {
      const storage = new FakeLocalStorage();

      // Both tabs reach `registerDevice` and block there at the same
      // time -- the worst-case overlap the original bug hit on a
      // brand-new install with no keypair saved yet.
      let releaseGate: () => void = () => {};
      registerDeviceGate = new Promise((resolve) => {
        releaseGate = resolve;
      });

      const tabA = await freshTab(storage);
      const tabB = await freshTab(storage);

      const resultA = tabA.ensureDeviceKeypair();
      const resultB = tabB.ensureDeviceKeypair();

      // Give both calls a chance to reach (and block on) the gate before
      // releasing it, so this actually exercises the overlap rather than
      // accidentally serializing them.
      await new Promise((resolve) => setTimeout(resolve, 10));
      releaseGate();

      const [keypairA, keypairB] = await Promise.all([resultA, resultB]);

      expect(registeredDevices).toHaveLength(1);
      expect(keypairA).toEqual(keypairB);
      expect(keypairA.deviceId).toBe('device-1');
    }
  );

  it('the mutex generalizes beyond two-way races: three overlapping tabs still register only one device', async () => {
    const storage = new FakeLocalStorage();
    let releaseGate: () => void = () => {};
    registerDeviceGate = new Promise((resolve) => {
      releaseGate = resolve;
    });

    const tabA = await freshTab(storage);
    const tabB = await freshTab(storage);
    const tabC = await freshTab(storage);

    const resultA = tabA.ensureDeviceKeypair();
    const resultB = tabB.ensureDeviceKeypair();
    const resultC = tabC.ensureDeviceKeypair();
    await new Promise((resolve) => setTimeout(resolve, 10));
    releaseGate();

    const [keypairA, keypairB, keypairC] = await Promise.all([resultA, resultB, resultC]);

    expect(registeredDevices).toHaveLength(1);
    expect(keypairA).toEqual(keypairB);
    expect(keypairB).toEqual(keypairC);
  });

  it('a lost claim from a tab that crashed mid-setup does not block setup forever', async () => {
    const storage = new FakeLocalStorage();

    // Simulate a tab that claimed leadership a while ago and then vanished
    // (closed, crashed) before ever registering or persisting anything --
    // write the claim directly, already older than SETUP_CLAIM_STALE_MS,
    // exactly as that tab's abandoned claim would eventually look from the
    // outside. (A claim that's still FRESH is covered by the other tests
    // above -- a genuinely live claim is supposed to make a second tab
    // wait, not barge in; this test is specifically about one that's gone
    // stale.)
    storage.setItem(
      'svalinn_e2ee_setup_claim',
      JSON.stringify({ token: 'ghost-tab', claimedAt: Date.now() - 40_000 })
    );

    const tabA = await freshTab(storage);
    const keypair = await tabA.ensureDeviceKeypair();

    // Setup still completes -- the stale ghost claim doesn't block this
    // tab from claiming leadership itself and proceeding.
    expect(keypair.deviceId).toBe('device-1');
    expect(registeredDevices).toHaveLength(1);
  });

  it('a single tab with no contention still sets up normally (no regression for the common case)', async () => {
    const storage = new FakeLocalStorage();
    const tab = await freshTab(storage);
    const keypair = await tab.ensureDeviceKeypair();

    expect(keypair.deviceId).toBe('device-1');
    expect(registeredDevices).toHaveLength(1);

    // Calling it again on the same tab, or a later one that sees the now-
    // persisted keypair, never re-registers.
    const second = await (await freshTab(storage)).ensureDeviceKeypair();
    expect(second).toEqual(keypair);
    expect(registeredDevices).toHaveLength(1);
  });
});
