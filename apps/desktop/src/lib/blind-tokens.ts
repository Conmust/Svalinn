// Anonymous patron-tier redemption via RFC 9474 blind RSA signatures.
//
// See migrations/0042_blind_tokens.sql and crate::blind_tokens (server)
// for the full design. The short version: a payment can happen through
// any channel (cash, a voucher, a card) without the server ever being
// able to link *which* payment produced *which* account's tier upgrade.
// That unlinkability comes entirely from the blind-signing math below --
// not from the payment method itself, which can be completely ordinary.
//
// The three calls below map onto the three steps of the protocol:
//
//   1. requestToken(tier, receiptToken) -- spends a one-time receipt (see
//      `apiFetch`-based admin tooling that mints one) to get a finished,
//      unblinded (preparedMessage, signature) pair. Deliberately uses a
//      bare `fetch`, never `apiFetch`: sending this device's access token
//      alongside a blind-signing request would attach an identity to the
//      one moment this protocol is designed to keep anonymous, even
//      though the message content itself stays hidden from the server.
//   2. storePendingToken / listPendingTokens / removePendingToken -- a
//      finished token is worth real money, so it's kept in localStorage
//      until redeemed, surviving an app restart in between.
//   3. redeemToken(tier, token) -- spends a token on the *currently
//      logged in* account. This can happen on a different device, at a
//      different time, under a different login than step 1 -- the more
//      separation, the better the anonymity set.
import { RSABSSA } from '@cloudflare/blindrsa-ts';
import { apiFetch, apiBase } from './api';
import { withTimeout } from './timeout';

const NETWORK_TIMEOUT_MS = 15_000;
const PENDING_TOKENS_STORAGE_KEY = 'svalinn_pending_blind_tokens';

/** The suite both this client and the server (`blind_rsa_signatures`'
 * `KeyPairSha384PSSRandomized`) implement: RSABSSA-SHA384-PSS-Randomized,
 * RFC 9474's recommended ciphersuite. */
function suite() {
  return RSABSSA.SHA384.PSS.Randomized();
}

export class BlindTokenError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'BlindTokenError';
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

export interface Sku {
  tier: string;
  publicKeyDer: Uint8Array;
}

/** Fetches every tier's blind-signing public key. Public endpoint, no auth. */
export async function fetchSkus(): Promise<Sku[]> {
  const res = await withTimeout(
    fetch(`${apiBase()}/api/v1/blind-tokens/skus`),
    NETWORK_TIMEOUT_MS,
    'Timed out fetching blind-token SKUs'
  );
  if (!res.ok) throw new BlindTokenError(`Couldn't fetch blind-token SKUs (${res.status})`);
  const skus: Array<{ tier: string; public_key_der: string }> = await res.json();
  return skus.map((s) => ({ tier: s.tier, publicKeyDer: fromB64(s.public_key_der) }));
}

async function importPublicKey(der: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey('spki', der as BufferSource, { name: 'RSA-PSS', hash: 'SHA-384' }, true, ['verify']);
}

/** A finished, unblinded token: valid proof the server once blind-signed
 * it, with nothing in it that ties back to the receipt that authorized
 * the signing. Worth exactly one tier upgrade until it's redeemed. */
export interface PendingToken {
  tier: string;
  /** base64 of (32-byte message randomizer || original random serial). */
  preparedMessage: string;
  /** base64 signature. */
  signature: string;
  createdAt: string;
}

/**
 * Spends a one-time receipt token to mint a finished blind token for
 * `tier`. This is the anonymous half of the protocol: no login, no
 * account, nothing identifying goes out with this request. Store the
 * result (see `storePendingToken`) and redeem it whenever and wherever
 * you like -- ideally not from this same request.
 */
export async function requestToken(tier: string, receiptToken: string): Promise<PendingToken> {
  const skus = await fetchSkus();
  const sku = skus.find((s) => s.tier === tier);
  if (!sku) throw new BlindTokenError(`No blind-token SKU for tier "${tier}"`);
  const publicKey = await importPublicKey(sku.publicKeyDer);
  const blindSuite = suite();

  const serial = crypto.getRandomValues(new Uint8Array(32));
  const preparedMsg = blindSuite.prepare(serial);
  const { blindedMsg, inv } = await blindSuite.blind(publicKey, preparedMsg);

  // Deliberately `fetch`, not `apiFetch` -- see the module comment.
  const res = await withTimeout(
    fetch(`${apiBase()}/api/v1/blind-tokens/blind-sign`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tier, receipt_token: receiptToken, blinded_message: b64(blindedMsg) }),
    }),
    NETWORK_TIMEOUT_MS,
    'Timed out requesting a blind signature'
  );
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new BlindTokenError(body.error || `Blind-signing failed (${res.status})`);
  }
  const { blind_signature }: { blind_signature: string } = await res.json();

  const signature = await blindSuite.finalize(publicKey, preparedMsg, fromB64(blind_signature), inv);

  return {
    tier,
    preparedMessage: b64(preparedMsg),
    signature: b64(signature),
    createdAt: new Date().toISOString(),
  };
}

/** Redeems a finished token on whichever account is currently logged in.
 * Requires login (the tier has to land on some account), but nothing here
 * -- or anywhere server-side -- records which receipt or payment produced
 * this token. */
export async function redeemToken(token: PendingToken): Promise<{ tier: string }> {
  const res = await withTimeout(
    apiFetch(`${apiBase()}/api/v1/blind-tokens/redeem`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        tier: token.tier,
        prepared_message: token.preparedMessage,
        signature: token.signature,
      }),
    }),
    NETWORK_TIMEOUT_MS,
    'Timed out redeeming the token'
  );
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new BlindTokenError(body.error || `Redeeming failed (${res.status})`);
  }
  return res.json();
}

// --- Local storage for tokens awaiting redemption -------------------------
//
// A finished token is a bearer instrument -- worth real money, usable by
// whoever holds it -- so it's kept only in this browser's storage, never
// sent anywhere except the one redeem call that spends it.

function readPendingTokens(): PendingToken[] {
  try {
    const raw = localStorage.getItem(PENDING_TOKENS_STORAGE_KEY);
    return raw ? (JSON.parse(raw) as PendingToken[]) : [];
  } catch {
    return [];
  }
}

function writePendingTokens(tokens: PendingToken[]): void {
  try {
    localStorage.setItem(PENDING_TOKENS_STORAGE_KEY, JSON.stringify(tokens));
  } catch {
    // Best-effort; worst case the token has to be re-requested.
  }
}

export function listPendingTokens(): PendingToken[] {
  return readPendingTokens();
}

export function storePendingToken(token: PendingToken): void {
  writePendingTokens([...readPendingTokens(), token]);
}

export function removePendingToken(token: PendingToken): void {
  writePendingTokens(readPendingTokens().filter((t) => t.preparedMessage !== token.preparedMessage));
}
