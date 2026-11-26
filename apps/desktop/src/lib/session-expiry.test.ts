// Regression test: a 401 with no refresh token available (so `apiFetch`
// itself never even attempts a refresh -- see `api.ts`'s own early-return
// `if (response.status !== 401 || !localStorage.getItem('refresh_token'))
// return response;`) used to be "handled" by `servers.ts`/`members.ts` with
// hand-rolled logic that removed `svalinn_token`/`svalinn_user` from
// localStorage and reloaded the page. Those were never this app's real
// session keys (see `api.ts`'s `token`/`refresh_token`/`user`), so the
// removal was a no-op: the real stale `token`/`user` were left in place,
// and the reload landed right back in the same broken, still-"logged-in"
// state -- which would 401 again on the very next fetch, looping forever.
// This checks that the real session storage is now actually cleared
// (via `api.ts`'s own `endSession`) when that path is hit.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

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

function activate(storage: FakeLocalStorage): void {
  (globalThis as unknown as { localStorage: FakeLocalStorage }).localStorage = storage;
}

describe('a 401 with no refresh token actually clears the real session', () => {
  let storage: FakeLocalStorage;
  let reload: ReturnType<typeof vi.fn>;
  let originalFetch: typeof fetch;
  let originalLocation: Location | undefined;

  beforeEach(async () => {
    vi.resetModules();
    storage = new FakeLocalStorage();
    activate(storage);
    storage.setItem('token', 'a-stale-access-token');
    storage.setItem('user', JSON.stringify({ id: 'user-a', username: 'alice' }));
    // Deliberately no `refresh_token` -- the specific case where `apiFetch`
    // returns the 401 to the caller unchanged instead of trying a refresh.

    reload = vi.fn();
    originalLocation = (globalThis as unknown as { location?: Location }).location;
    (globalThis as unknown as { location: { reload: () => void } }).location = { reload };

    originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn(async () => new Response(JSON.stringify({ error: 'unauthorized' }), { status: 401 })) as typeof fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    if (originalLocation) (globalThis as unknown as { location: Location }).location = originalLocation;
  });

  it('fetchUserServers clears the real token/user and reloads instead of leaving the stale session in place', async () => {
    const { fetchUserServers } = await import('./servers');
    await expect(fetchUserServers()).rejects.toThrow('Session expired');

    expect(storage.getItem('token')).toBeNull();
    expect(storage.getItem('user')).toBeNull();
    expect(reload).toHaveBeenCalledTimes(1);
  });

  it('fetchServerMembers clears the real token/user and reloads instead of leaving the stale session in place', async () => {
    const { fetchServerMembers } = await import('./members');
    await expect(fetchServerMembers('server-1')).rejects.toThrow('Session expired');

    expect(storage.getItem('token')).toBeNull();
    expect(storage.getItem('user')).toBeNull();
    expect(reload).toHaveBeenCalledTimes(1);
  });
});
