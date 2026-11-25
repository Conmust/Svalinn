// Tests for the blind-RSA patron-tier flow in `blind-tokens.ts`, against a
// fake server built on a REAL RSABSSA keypair and REAL blind-signing (via
// the same @cloudflare/blindrsa-ts library the client uses) -- no network,
// no real Postgres, but genuine crypto. This exercises the actual
// blind/finalize/verify math, not just request plumbing.
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { RSABSSA } from '@cloudflare/blindrsa-ts';

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

function b64(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}
function fromB64(s: string): Uint8Array {
  const binary = atob(s);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

// --- A real keypair + an in-memory server standing in for svalinn-server --

const suite = RSABSSA.SHA384.PSS.Randomized();
let keyPair: CryptoKeyPair;
let publicKeyDer: Uint8Array;

/** receipt token -> { tier, consumed } */
const receipts = new Map<string, { tier: string; consumed: boolean }>();
/** serial hash -> tier, i.e. the redemption ledger. */
const redemptions = new Map<string, string>();

function sha256Hex(bytes: Uint8Array): string {
  // Not actually SHA-256 -- just needs to be a stable, collision-free-enough
  // stand-in so the fake server's double-spend check works the same way
  // the real one does (keyed on the original serial, not the full prepared
  // message). Good enough for a test double.
  return Array.from(bytes).join(',');
}

async function fakeFetch(url: string, init: RequestInit = {}): Promise<Response> {
  const body = init.body ? JSON.parse(init.body as string) : {};
  const hasAuth = new Headers(init.headers).has('Authorization');

  if (url.endsWith('/api/v1/blind-tokens/skus')) {
    return new Response(JSON.stringify([{ tier: 'patron', public_key_der: b64(publicKeyDer) }]), { status: 200 });
  }

  if (url.endsWith('/api/v1/blind-tokens/blind-sign')) {
    if (hasAuth) {
      return new Response(JSON.stringify({ error: 'must not send auth here' }), { status: 400 });
    }
    const receipt = receipts.get(body.receipt_token);
    if (!receipt || receipt.consumed || receipt.tier !== body.tier) {
      return new Response(JSON.stringify({ error: 'That receipt is invalid or has already been used' }), { status: 403 });
    }
    receipt.consumed = true;
    const blindSig = await suite.blindSign(keyPair.privateKey, fromB64(body.blinded_message));
    return new Response(JSON.stringify({ blind_signature: b64(blindSig) }), { status: 200 });
  }

  if (url.endsWith('/api/v1/blind-tokens/redeem')) {
    const prepared = fromB64(body.prepared_message);
    const signature = fromB64(body.signature);
    const valid = await suite.verify(keyPair.publicKey, signature, prepared);
    if (!valid) return new Response(JSON.stringify({ error: "That token isn't valid" }), { status: 400 });
    const serial = prepared.slice(32); // RANDOMIZE prefixes a 32-byte randomizer
    const key = sha256Hex(serial);
    if (redemptions.has(key)) {
      return new Response(JSON.stringify({ error: 'That token has already been redeemed' }), { status: 400 });
    }
    redemptions.set(key, body.tier);
    return new Response(JSON.stringify({ tier: body.tier }), { status: 200 });
  }

  throw new Error(`Unhandled fake fetch: ${url}`);
}

vi.mock('./api', () => ({
  apiBase: () => 'http://localhost:3001',
  apiFetch: (url: string, init?: RequestInit) => fakeFetch(url, init),
}));

beforeEach(async () => {
  vi.resetModules();
  (globalThis as any).localStorage = new FakeLocalStorage();
  (globalThis as any).fetch = (url: string, init?: RequestInit) => fakeFetch(url, init);

  receipts.clear();
  redemptions.clear();
  keyPair = await suite.generateKey({ modulusLength: 2048, publicExponent: Uint8Array.from([1, 0, 1]) });
  publicKeyDer = new Uint8Array(await crypto.subtle.exportKey('spki', keyPair.publicKey));
});

function mintReceipt(tier: string): string {
  const token = crypto.randomUUID();
  receipts.set(token, { tier, consumed: false });
  return token;
}

describe('blind-tokens', () => {
  it('requests a token without sending any auth header, then redeems it', async () => {
    const { requestToken, redeemToken } = await import('./blind-tokens');
    const receipt = mintReceipt('patron');

    const token = await requestToken('patron', receipt);
    expect(token.tier).toBe('patron');

    const result = await redeemToken(token);
    expect(result.tier).toBe('patron');
  });

  it('refuses to spend the same receipt twice', async () => {
    const { requestToken, BlindTokenError } = await import('./blind-tokens');
    const receipt = mintReceipt('patron');

    await requestToken('patron', receipt);
    await expect(requestToken('patron', receipt)).rejects.toBeInstanceOf(BlindTokenError);
  });

  it('refuses to redeem the same finished token twice', async () => {
    const { requestToken, redeemToken, BlindTokenError } = await import('./blind-tokens');
    const receipt = mintReceipt('patron');
    const token = await requestToken('patron', receipt);

    await redeemToken(token);
    await expect(redeemToken(token)).rejects.toBeInstanceOf(BlindTokenError);
  });

  it('keeps pending tokens in local storage until they are removed', async () => {
    const { requestToken, storePendingToken, listPendingTokens, removePendingToken } = await import('./blind-tokens');
    const receipt = mintReceipt('patron');
    const token = await requestToken('patron', receipt);

    expect(listPendingTokens()).toEqual([]);
    storePendingToken(token);
    expect(listPendingTokens()).toHaveLength(1);

    removePendingToken(token);
    expect(listPendingTokens()).toEqual([]);
  });
});
