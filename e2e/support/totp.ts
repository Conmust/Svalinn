// A from-scratch TOTP code generator for e2e tests, mirroring
// svalinn-server's `totp.rs` (RFC 6238, HMAC-SHA1, 6 digits, 30s steps).
// There's no otplib/speakeasy dependency in this package, and pulling one
// in for a ~20-line algorithm the server already implements (and tests
// against the RFC's own vectors) isn't worth it -- this just needs to
// compute the same code a real authenticator app would show.
import crypto from 'node:crypto';

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Decode(input: string): Buffer {
  const clean = input.replace(/=+$/, '').toUpperCase();
  let bits = '';
  for (const char of clean) {
    const val = BASE32_ALPHABET.indexOf(char);
    if (val === -1) throw new Error(`invalid base32 character: ${char}`);
    bits += val.toString(2).padStart(5, '0');
  }
  const bytes: number[] = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }
  return Buffer.from(bytes);
}

/** The 6-digit code for `secretBase32` at `unixTimeSeconds` (default: now). */
export function totpCode(secretBase32: string, unixTimeSeconds = Math.floor(Date.now() / 1000)): string {
  const key = base32Decode(secretBase32);
  const counter = Math.floor(unixTimeSeconds / 30);
  const counterBuf = Buffer.alloc(8);
  counterBuf.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac('sha1', key).update(counterBuf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const truncated =
    ((hmac[offset] & 0x7f) << 24) | ((hmac[offset + 1] & 0xff) << 16) | ((hmac[offset + 2] & 0xff) << 8) | (hmac[offset + 3] & 0xff);
  return (truncated % 1_000_000).toString().padStart(6, '0');
}

/** The code for the step after `unixTimeSeconds` (default: now) -- useful
 * when a prior step's code was already consumed (e.g. by `enable`) and
 * replay protection means it can't be reused immediately after. */
export function nextTotpCode(secretBase32: string, unixTimeSeconds = Math.floor(Date.now() / 1000)): string {
  return totpCode(secretBase32, unixTimeSeconds + 30);
}
