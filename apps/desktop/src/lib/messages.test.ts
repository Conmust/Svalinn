// Tests for the request-shape logic in messages.ts added alongside the
// server's unpin-confirmation and slowmode features: the query param
// unpinMessage sends, the response shapes it passes through unchanged,
// and what SendChannelMessageError captures off a failed send (including
// the 429 Retry-After header slowmode relies on).
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

let storage: FakeLocalStorage;
let originalFetch: typeof fetch;

beforeEach(() => {
  vi.resetModules();
  storage = new FakeLocalStorage();
  (globalThis as unknown as { localStorage: FakeLocalStorage }).localStorage = storage;
  storage.setItem('token', 'a-test-token');
  originalFetch = globalThis.fetch;
});

afterEach(() => {
  globalThis.fetch = originalFetch;
});

describe('unpinMessage', () => {
  it('sends a plain DELETE with no query string when not confirming', async () => {
    let requestedUrl = '';
    let requestedMethod = '';
    globalThis.fetch = vi.fn(async (url: string | URL, init?: RequestInit) => {
      requestedUrl = url.toString();
      requestedMethod = init?.method ?? '';
      return new Response(JSON.stringify({ id: 'msg-1' }), { status: 200 });
    }) as typeof fetch;

    const { unpinMessage } = await import('./messages');
    await unpinMessage('msg-1');

    expect(requestedMethod).toBe('DELETE');
    expect(requestedUrl).toMatch(/\/api\/v1\/messages\/msg-1\/pin$/);
    expect(requestedUrl).not.toContain('?');
  });

  it('appends ?confirm=true when confirming', async () => {
    let requestedUrl = '';
    globalThis.fetch = vi.fn(async (url: string | URL) => {
      requestedUrl = url.toString();
      return new Response(JSON.stringify({ id: 'msg-1', deleted: true }), { status: 200 });
    }) as typeof fetch;

    const { unpinMessage } = await import('./messages');
    await unpinMessage('msg-1', true);

    expect(requestedUrl).toMatch(/\/pin\?confirm=true$/);
  });

  it('returns a requires_confirmation response as-is rather than treating it as success-and-done', async () => {
    globalThis.fetch = vi.fn(async () =>
      new Response(
        JSON.stringify({ id: 'msg-1', requires_confirmation: true, warning: 'This message is older than...' }),
        { status: 200 }
      )
    ) as typeof fetch;

    const { unpinMessage } = await import('./messages');
    const result = await unpinMessage('msg-1');

    expect(result.requires_confirmation).toBe(true);
    expect(result.warning).toContain('older than');
    expect(result.deleted).toBeUndefined();
  });

  it('returns a deleted:true response as-is after a confirmed unpin', async () => {
    globalThis.fetch = vi.fn(async () =>
      new Response(JSON.stringify({ id: 'msg-1', deleted: true }), { status: 200 })
    ) as typeof fetch;

    const { unpinMessage } = await import('./messages');
    const result = await unpinMessage('msg-1', true);

    expect(result.deleted).toBe(true);
  });
});

describe('SendChannelMessageError, via sendChannelMessage', () => {
  const minimalOptions = { encryptedFor: [], senderDeviceId: 'device-1' };

  it('captures the status and the server\'s JSON error message on a 400', async () => {
    globalThis.fetch = vi.fn(async () =>
      new Response(
        JSON.stringify({ error: "This attachment doesn't fit even after freeing everything..." }),
        { status: 400 }
      )
    ) as typeof fetch;

    const { sendChannelMessage, SendChannelMessageError } = await import('./messages');
    expect.assertions(4);
    try {
      await sendChannelMessage('channel-1', null, minimalOptions);
    } catch (e) {
      expect(e).toBeInstanceOf(SendChannelMessageError);
      const err = e as InstanceType<typeof SendChannelMessageError>;
      expect(err.status).toBe(400);
      expect(err.serverMessage).toBe("This attachment doesn't fit even after freeing everything...");
      expect(err.retryAfterSeconds).toBeNull();
    }
  });

  it('captures retryAfterSeconds from the Retry-After header on a 429 (slowmode)', async () => {
    globalThis.fetch = vi.fn(async () =>
      new Response(JSON.stringify({ error: 'Too many attempts. Try again in 12s.' }), {
        status: 429,
        headers: { 'Retry-After': '12' },
      })
    ) as typeof fetch;

    const { sendChannelMessage, SendChannelMessageError } = await import('./messages');
    expect.assertions(3);
    try {
      await sendChannelMessage('channel-1', null, minimalOptions);
    } catch (e) {
      expect(e).toBeInstanceOf(SendChannelMessageError);
      const err = e as InstanceType<typeof SendChannelMessageError>;
      expect(err.status).toBe(429);
      expect(err.retryAfterSeconds).toBe(12);
    }
  });

  it('leaves serverMessage and retryAfterSeconds null when the error body is not JSON', async () => {
    globalThis.fetch = vi.fn(async () => new Response('not json', { status: 500 })) as typeof fetch;

    const { sendChannelMessage, SendChannelMessageError } = await import('./messages');
    expect.assertions(4);
    try {
      await sendChannelMessage('channel-1', null, minimalOptions);
    } catch (e) {
      expect(e).toBeInstanceOf(SendChannelMessageError);
      const err = e as InstanceType<typeof SendChannelMessageError>;
      expect(err.status).toBe(500);
      expect(err.serverMessage).toBeNull();
      expect(err.retryAfterSeconds).toBeNull();
    }
  });

  it('resolves normally (no error) on a 2xx', async () => {
    globalThis.fetch = vi.fn(async () =>
      new Response(JSON.stringify({ id: 'msg-1' }), { status: 201 })
    ) as typeof fetch;

    const { sendChannelMessage } = await import('./messages');
    const message = await sendChannelMessage('channel-1', null, minimalOptions);
    expect(message.id).toBe('msg-1');
  });
});
