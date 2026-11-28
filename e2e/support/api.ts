// Helpers for talking to the server under test.
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import pg from 'pg';
import { API_URL, DATABASE_URL, EMAIL_BLIND_INDEX_PEPPER, EMAIL_ENCRYPTION_KEY, JWT_SECRET, ROOT, exe } from './config';
import { genKeypair, encryptForRecipient, encryptFileForFanout, wrapFileKey, type TestDeviceKeypair } from './crypto';

export const API = `${API_URL}/api/v1`;

let counter = 0;
/** A short name that's unique across test runs and parallel workers. */
export function uniq(prefix: string): string {
  counter += 1;
  return `${prefix}${process.pid % 1000}${Date.now() % 1_000_000}${counter}`;
}

/** A made-up client address, so per-IP rate limits apply per test user. */
export function randomIp(): string {
  const b = crypto.randomBytes(3);
  return `10.${b[0]}.${b[1]}.${b[2] || 1}`;
}

export interface User {
  token: string;
  refresh_token: string;
  user: { id: string; username: string };
  email: string;
  password: string;
  ip: string;
  /** Lazily set the first time this user needs an encrypted channel/DM
   * device -- see `ensureDevice`. Channel messages are mandatory
   * end-to-end encrypted, so any test sending one needs this. */
  device?: { id: string } & TestDeviceKeypair;
}

export interface Res<T = any> {
  status: number;
  body: T;
  headers: Headers;
}

async function send<T>(method: string, path: string, opts: { token?: string; body?: unknown; form?: FormData; ip?: string; headers?: Record<string, string> } = {}): Promise<Res<T>> {
  const headers: Record<string, string> = { ...(opts.headers ?? {}) };
  if (opts.token) headers.Authorization = `Bearer ${opts.token}`;
  if (opts.ip) headers['X-Forwarded-For'] = opts.ip;
  let body: BodyInit | undefined;
  if (opts.form) body = opts.form;
  else if (opts.body !== undefined) {
    headers['Content-Type'] = 'application/json';
    body = JSON.stringify(opts.body);
  }
  const res = await fetch(path.startsWith('http') ? path : API + path, { method, headers, body });
  const text = await res.text();
  let parsed: any = text;
  try {
    parsed = text ? JSON.parse(text) : null;
  } catch {
    // not JSON
  }
  return { status: res.status, body: parsed, headers: res.headers };
}

/** Calls the API as `user` (or anonymously). */
export function call<T = any>(user: User | null, method: string, path: string, body?: unknown): Promise<Res<T>> {
  return send<T>(method, path, { token: user?.token, body, ip: user?.ip });
}

export function callForm<T = any>(user: User, method: string, path: string, form: FormData): Promise<Res<T>> {
  return send<T>(method, path, { token: user.token, form, ip: user.ip });
}

export function post<T = any>(path: string, body: unknown, ip = randomIp()): Promise<Res<T>> {
  return send<T>('POST', path, { body, ip });
}

export async function register(prefix = 'user', password = 'secret123'): Promise<User> {
  const username = uniq(prefix);
  const email = `${username}@example.test`;
  const ip = randomIp();
  const res = await send<any>('POST', '/auth/register', { body: { username, email, password }, ip });
  if (res.status !== 200) throw new Error(`register failed: ${res.status} ${JSON.stringify(res.body)}`);
  const user = { ...res.body, email, password, ip };
  // Joining a server now requires a verified email (see routes/invites.rs).
  // Real verification happens by clicking the emailed link; test users
  // skip straight to "verified" via the same direct-DB escape hatch
  // `sql()` already provides for things the API has no self-service path
  // for (see `createServer`'s tier bump) -- this suite isn't exercising
  // the verification flow itself, just everything that's gated on it.
  await sql('UPDATE users SET email_verified_at = NOW() WHERE id = $1', [user.user.id]);
  return user;
}

export async function login(email: string, password: string, ip = randomIp()): Promise<Res> {
  return send('POST', '/auth/login', { body: { email, password }, ip });
}

/** A server with one channel "general", owned by `owner`. */
export async function createServer(owner: User, name = uniq('srv')) {
  // Server creation now requires guild tier or higher, and there's no
  // self-service way to get there anymore (tier changes are site-owner-only,
  // granted from a user's profile in the app) -- so test setup needs the
  // same direct-DB escape hatch `sql()` already exists for.
  await sql('UPDATE users SET patron_tier = $1 WHERE id = $2', ['guild', owner.user.id]);
  const server = (await call(owner, 'POST', '/servers', { name })).body;
  const channel = (await call(owner, 'POST', `/servers/${server.id}/channels`, { name: 'general' })).body;
  return { server, channel };
}

/** Invites `users` into the server via a fresh invite. */
export async function join(owner: User, serverId: string, ...users: User[]) {
  const invite = (await call(owner, 'POST', `/servers/${serverId}/invites`, {})).body;
  for (const u of users) {
    const res = await call(u, 'POST', `/invites/${invite.code}`);
    if (res.status !== 200) throw new Error(`join failed: ${res.status} ${JSON.stringify(res.body)}`);
  }
}

/** Registers an X25519 device keypair for `user` with the server, once --
 * cached on `user.device`. Channel messages are mandatory end-to-end
 * encrypted, so any test sending or decrypting one needs this. Mirrors
 * `ensureDeviceKeypair` in `lib/crypto.ts`, minus the localStorage part
 * (nothing here persists between test runs). */
export async function ensureDevice(user: User): Promise<{ id: string } & TestDeviceKeypair> {
  if (user.device) return user.device;
  const keypair = await genKeypair();
  const res = await call<{ id: string }>(user, 'POST', '/users/me/devices', {
    public_key: keypair.publicKey,
    device_label: 'e2e-test-device',
  });
  if (res.status !== 200) throw new Error(`failed to register a test device: ${res.status} ${JSON.stringify(res.body)}`);
  user.device = { id: res.body.id, ...keypair };
  return user.device;
}

/** Sends a channel message as `user`, end-to-end encrypted exactly the
 * way the real client does (mandatory -- there is no plaintext channel
 * send path anymore): registers `user`'s device if needed, fetches every
 * current member's device from the channel's own member-devices endpoint,
 * encrypts `content` once per device, and -- if `file` is given -- the
 * file once with a fresh symmetric key wrapped per device. `content` is
 * never sent to the server in the clear.
 *
 * Returns the same `{ status, body, headers }` shape as `call`, so
 * existing assertions on the result keep working; a non-200 from the
 * member-devices lookup (e.g. 403 for a non-member) is returned as-is,
 * without attempting to encrypt or send anything. */
export async function postMessage(
  user: User,
  channelId: string,
  content: string,
  file?: { name: string; type: string; data: Uint8Array | string },
  mentionedUserIds?: string[]
): Promise<Res> {
  const device = await ensureDevice(user);
  const devicesRes = await call<Array<{ device_id: string; public_key: string }>>(
    user, 'GET', `/channels/${channelId}/member-devices`,
  );
  if (devicesRes.status !== 200) return devicesRes;
  const devices = devicesRes.body;

  const body: Record<string, unknown> = { sender_device_id: device.id };
  if (mentionedUserIds) body.mentioned_user_ids = mentionedUserIds;

  if (file) {
    const fileBytes = typeof file.data === 'string' ? new TextEncoder().encode(file.data) : file.data;
    const { ciphertext: fileCiphertext, nonce: attachmentNonce, fileKey } = await encryptFileForFanout(fileBytes);
    const uploadForm = new FormData();
    uploadForm.append('file', new Blob([fileCiphertext], { type: 'application/octet-stream' }), file.name);
    const uploaded = await callForm<{ url: string }>(user, 'POST', '/upload', uploadForm);
    if (uploaded.status !== 200) return uploaded;

    body.attachment_url = uploaded.body.url;
    body.attachment_filename = file.name;
    body.attachment_size = fileBytes.length;
    body.attachment_mime_type = file.type;
    body.attachment_nonce = attachmentNonce;
    body.encrypted_for = await Promise.all(devices.map(async (d) => {
      const { ciphertext, nonce } = await encryptForRecipient(content, d.public_key, device.privateKey);
      const wrapped = await wrapFileKey(fileKey, d.public_key, device.privateKey);
      return {
        device_id: d.device_id, ciphertext, nonce,
        attachment_key_ciphertext: wrapped.ciphertext, attachment_key_nonce: wrapped.nonce,
      };
    }));
  } else {
    body.encrypted_for = await Promise.all(devices.map(async (d) => {
      const { ciphertext, nonce } = await encryptForRecipient(content, d.public_key, device.privateKey);
      return { device_id: d.device_id, ciphertext, nonce };
    }));
  }

  return call(user, 'POST', `/channels/${channelId}/messages`, body);
}

/** An open WebSocket that records events and how it closed. */
export interface Socket {
  events: any[];
  closed: { code: number; reason: string } | null;
  close(): void;
  waitFor(pred: (e: any) => boolean, timeoutMs?: number): Promise<any>;
  waitClosed(timeoutMs?: number): Promise<{ code: number; reason: string }>;
}

export async function openSocket(user: User): Promise<Socket> {
  const ws = new WebSocket(`${API_URL.replace(/^http/, 'ws')}/api/v1/ws?token=${encodeURIComponent(user.token)}`);
  const socket: Socket = {
    events: [],
    closed: null,
    close: () => ws.close(),
    waitFor: (pred, timeoutMs = 5000) => poll(() => socket.events.find(pred), timeoutMs, 'WebSocket event'),
    waitClosed: (timeoutMs = 5000) => poll(() => socket.closed, timeoutMs, 'WebSocket close'),
  };
  ws.onmessage = (e) => socket.events.push(JSON.parse(String(e.data)));
  ws.onclose = (e) => (socket.closed = { code: e.code, reason: e.reason });
  await new Promise<void>((resolve, reject) => {
    ws.onopen = () => resolve();
    ws.onerror = () => reject(new Error('WebSocket failed to open'));
  });
  // Let the server register the connection before the test acts.
  await sleep(150);
  return socket;
}

export const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export async function poll<T>(get: () => T | null | undefined, timeoutMs: number, what: string): Promise<T> {
  const start = Date.now();
  for (;;) {
    const value = get();
    if (value) return value;
    if (Date.now() - start > timeoutMs) throw new Error(`Timed out waiting for ${what}`);
    await sleep(25);
  }
}

/** Runs the svalinn-admin tool against the test database. */
export function admin(...args: string[]): string {
  try {
    // Must agree with the webServer's own copy of these two (SERVER_ENV in
    // config.ts) -- svalinn-admin computes the same email_hash/encrypted
    // email the running server does, and a different pepper here would
    // make every account this CLI creates permanently unable to log in
    // (right email_hash column, wrong value in it) with no error to say
    // why. Pass them explicitly rather than hoping dotenv/ambient env
    // happens to agree.
    return execFileSync(exe('svalinn-admin'), args, {
      cwd: ROOT,
      env: { ...process.env, DATABASE_URL, EMAIL_ENCRYPTION_KEY, EMAIL_BLIND_INDEX_PEPPER },
      encoding: 'utf8',
    }).trim();
  } catch (e: any) {
    return `${e.stdout ?? ''}${e.stderr ?? ''}`.trim();
  }
}

let pool: pg.Pool | null = null;
/** Direct database access, only for setup the API can't do (e.g. ageing a token). */
export async function sql<T = any>(query: string, params: unknown[] = []): Promise<T[]> {
  pool ??= new pg.Pool({ connectionString: DATABASE_URL, max: 2 });
  return (await pool.query(query, params)).rows as T[];
}

/** Decodes a JWT's payload (no verification). */
export function jwtPayload(token: string): any {
  return JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString());
}

/** Signs a JWT with the test secret, to build expired or tampered tokens. */
export function signJwt(payload: object): string {
  const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const unsigned = `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64(payload)}`;
  return `${unsigned}.${crypto.createHmac('sha256', JWT_SECRET).update(unsigned).digest('base64url')}`;
}

/** Builds a signed file link the way the server does. */
export function signFileLink(name: string, userId: string, sessionId: string, expires: number): string {
  const sig = crypto.createHmac('sha256', JWT_SECRET).update(`file\0${name}\0${userId}\0${sessionId}\0${expires}`).digest('hex');
  return `/api/v1/files/${name}?u=${userId}&s=${sessionId}&e=${expires}&sig=${sig}`;
}

export const nowSeconds = () => Math.floor(Date.now() / 1000);
