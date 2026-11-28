import { test, expect } from '@playwright/test';
import { spawnSync } from 'node:child_process';
import os from 'node:os';
import crypto from 'node:crypto';
import { API, call, jwtPayload, login, nowSeconds, post, randomIp, register, signJwt, sql, uniq } from '../../support/api';
import { APP_URL, DATABASE_URL, exe } from '../../support/config';

test.describe('login tokens', () => {
  test('register returns a 5-minute access token and a hashed 90-day refresh token', async () => {
    const u = await register('tok');
    const claims = jwtPayload(u.token);
    expect(claims.exp - nowSeconds()).toBeGreaterThan(290);
    expect(claims.exp - nowSeconds()).toBeLessThanOrEqual(300);
    expect(claims.sid).toBeTruthy();
    expect(u.refresh_token).toMatch(/^[0-9a-f]{64}$/);

    const hash = crypto.createHash('sha256').update(u.refresh_token).digest('hex');
    const rows = await sql(
      `SELECT token_hash, round(extract(epoch from expires_at - now()) / 86400) AS days FROM refresh_tokens WHERE user_id = $1`,
      [u.user.id],
    );
    expect(rows).toHaveLength(1);
    expect(rows[0].token_hash).toBe(hash); // only the hash is stored
    expect(Number(rows[0].days)).toBe(90);
  });

  test('expired, forged and session-less access tokens are rejected', async () => {
    const u = await register('tok');
    const sid = jwtPayload(u.token).sid;
    expect((await call(u, 'GET', '/servers')).status).toBe(200);

    const expired = signJwt({ sub: u.user.id, username: 'x', sid, exp: nowSeconds() - 10 });
    expect((await call({ ...u, token: expired }, 'GET', '/servers')).status).toBe(401);

    const forged = u.token.slice(0, -4) + 'AAAA';
    expect((await call({ ...u, token: forged }, 'GET', '/servers')).status).toBe(401);

    // Tokens from before sessions existed have no "sid" and are refused.
    const noSession = signJwt({ sub: u.user.id, username: 'x', exp: nowSeconds() + 300 });
    expect((await call({ ...u, token: noSession }, 'GET', '/servers')).status).toBe(401);
  });

  test('refresh rotates the refresh token', async () => {
    const u = await register('tok');
    const r1 = await post('/auth/refresh', { refresh_token: u.refresh_token });
    expect(r1.status).toBe(200);
    expect(r1.body.refresh_token).not.toBe(u.refresh_token);
    expect((await call({ ...u, token: r1.body.token }, 'GET', '/servers')).status).toBe(200);

    // A retry within 30s (two windows refreshing at once) fails but doesn't end the session.
    expect((await post('/auth/refresh', { refresh_token: u.refresh_token })).status).toBe(401);
    expect((await post('/auth/refresh', { refresh_token: r1.body.refresh_token })).status).toBe(200);
  });

  test('replaying an old refresh token later revokes the whole session', async () => {
    const u = await register('tok');
    const r1 = (await post('/auth/refresh', { refresh_token: u.refresh_token })).body;
    // Pretend the first token was replaced a while ago, so this looks like theft.
    await sql(`UPDATE refresh_tokens SET replaced_at = now() - interval '5 minutes' WHERE user_id = $1 AND replaced_at IS NOT NULL`, [u.user.id]);

    expect((await post('/auth/refresh', { refresh_token: u.refresh_token })).status).toBe(401);
    // The legitimate newer token is dead too, and so is its access token.
    expect((await post('/auth/refresh', { refresh_token: r1.refresh_token })).status).toBe(401);
    expect((await call({ ...u, token: r1.token }, 'GET', '/servers')).status).toBe(401);
  });

  test('refresh tokens past 90 days are refused', async () => {
    const u = await register('tok');
    await sql(`UPDATE refresh_tokens SET expires_at = now() - interval '1 second' WHERE user_id = $1`, [u.user.id]);
    const res = await post('/auth/refresh', { refresh_token: u.refresh_token });
    expect(res.status).toBe(401);
    expect(res.body.error).toContain('expired');
  });

  test('logout revokes the session at once', async () => {
    const u = await register('tok');
    expect((await post('/auth/logout', { refresh_token: u.refresh_token })).status).toBe(204);
    expect((await post('/auth/refresh', { refresh_token: u.refresh_token })).status).toBe(401);
    // The access token stops working immediately, not after 5 minutes.
    expect((await call(u, 'GET', '/servers')).status).toBe(401);
  });
});

test.describe('password reset', () => {
  test('forgot-password never reveals whether the account exists', async () => {
    const u = await register('fp');

    const known = await post('/auth/forgot-password', { email: u.email });
    const unknown = await post('/auth/forgot-password', { email: `${uniq('nobody')}@example.test` });

    // Same status, same shape, both times -- including for the known
    // account, since the suite runs with APP_ENV=test (see support/config.ts),
    // where `dev_reset_link` is just as absent as it is in real production.
    expect(known.status).toBe(200);
    expect(unknown.status).toBe(200);
    expect(known.body).toEqual(unknown.body);
    expect(known.body.dev_reset_link).toBeUndefined();
  });

  test('a reset token actually changes the password and ends every existing session, not just other ones', async () => {
    const u = await register('fp');
    const second = await login(u.email, u.password); // a second, independent session for the same account
    expect(second.status).toBe(200);

    // No real email provider is wired up, and the suite's APP_ENV=test means
    // even the dev-link convenience is off -- so the token is minted here
    // directly, hashed exactly the way the server stores it (SHA-256 hex of
    // the raw token -- see `routes::auth::hash_token`), standing in for "the
    // user clicked the link they were emailed."
    const token = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    await sql(
      "INSERT INTO password_reset_tokens (token_hash, user_id, expires_at) VALUES ($1, $2, NOW() + interval '1 hour')",
      [tokenHash, u.user.id],
    );

    const reset = await post('/auth/reset-password', { token, new_password: 'a-brand-new-password' });
    expect(reset.status).toBe(204);

    expect((await login(u.email, u.password)).status).toBe(400);
    expect((await login(u.email, 'a-brand-new-password')).status).toBe(200);

    // Unlike `change_password` (which spares the session making the
    // change), a forgot-password reset has no "current session" to spare --
    // every refresh token for the account, including the second session
    // opened above, should be revoked.
    expect((await post('/auth/refresh', { refresh_token: u.refresh_token })).status).toBe(401);
    expect((await post('/auth/refresh', { refresh_token: second.body.refresh_token })).status).toBe(401);
  });

  test('a reset token can only be used once, and an unknown token is rejected', async () => {
    const u = await register('fp');
    const token = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    await sql(
      "INSERT INTO password_reset_tokens (token_hash, user_id, expires_at) VALUES ($1, $2, NOW() + interval '1 hour')",
      [tokenHash, u.user.id],
    );

    expect((await post('/auth/reset-password', { token: 'not-a-real-token', new_password: 'a-brand-new-password' })).status).toBe(400);
    expect((await post('/auth/reset-password', { token, new_password: 'a-brand-new-password' })).status).toBe(204);
    expect((await post('/auth/reset-password', { token, new_password: 'yet-another-password' })).status).toBe(400); // already used
  });

  test('an expired reset token is rejected', async () => {
    const u = await register('fp');
    const token = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    await sql(
      "INSERT INTO password_reset_tokens (token_hash, user_id, expires_at) VALUES ($1, $2, NOW() - interval '1 minute')",
      [tokenHash, u.user.id],
    );

    expect((await post('/auth/reset-password', { token, new_password: 'a-brand-new-password' })).status).toBe(400);
  });

  test('limits forgot-password requests per IP address', async () => {
    const ip = randomIp();
    for (let i = 0; i < 10; i++) expect((await post('/auth/forgot-password', { email: `${uniq('nobody')}@example.test` }, ip)).status).toBe(200);
    expect((await post('/auth/forgot-password', { email: `${uniq('nobody')}@example.test` }, ip)).status).toBe(429);
  });
});

test.describe('rate limits', () => {
  test('locks an account from one IP after 5 wrong passwords, without locking the real owner out from elsewhere or affecting others', async () => {
    const u = await register('rl');
    const ip = randomIp();
    for (let i = 0; i < 5; i++) expect((await login(u.email, 'wrong', ip)).status).toBe(400);

    // The 6th attempt from the SAME ip is locked -- this is the real
    // brute-force throttle, keyed on (account, ip).
    const locked = await login(u.email, 'wrong', ip);
    expect(locked.status).toBe(429);
    expect(Number(locked.headers.get('retry-after'))).toBeGreaterThan(800);
    expect((await login(u.email, u.password, ip)).status).toBe(429); // even the right password, same ip

    // But the real owner, logging in from anywhere else, is never locked
    // out just because someone else has been guessing their password from
    // one IP -- that was the vulnerability this throttle used to have.
    expect((await login(u.email, u.password, randomIp())).status).toBe(200);

    // And an unrelated account is unaffected by the same ip being throttled.
    const other = await register('rl');
    expect((await login(other.email, other.password, ip)).status).toBe(200);
  });

  test('a distributed guess still locks the account even though no single IP hits the per-IP limit', async () => {
    const u = await register('rl');
    // One wrong guess from each of many IPs -- never enough from any one
    // of them to trip the tight (account, ip) rule, but the looser,
    // account-wide backstop (limit 30) still catches it eventually.
    let locked: Awaited<ReturnType<typeof login>> | null = null;
    for (let i = 0; i < 31 && !locked; i++) {
      const res = await login(u.email, 'wrong', randomIp());
      if (res.status === 429) locked = res;
      else expect(res.status).toBe(400);
    }
    expect(locked?.status).toBe(429);
  });

  test('limits logins per IP address', async () => {
    const ip = randomIp();
    for (let i = 0; i < 20; i++) await login(`${uniq('nobody')}@example.test`, 'x', ip);
    expect((await login(`${uniq('nobody')}@example.test`, 'x', ip)).status).toBe(429);
  });

  test('limits new accounts per IP address', async () => {
    const ip = randomIp();
    for (let i = 0; i < 5; i++) {
      const n = uniq('reg');
      expect((await post('/auth/register', { username: n, email: `${n}@example.test`, password: 'secret123' }, ip)).status).toBe(200);
    }
    const n = uniq('reg');
    expect((await post('/auth/register', { username: n, email: `${n}@example.test`, password: 'secret123' }, ip)).status).toBe(429);
  });
});

test.describe('server startup', () => {
  const start = (env: Record<string, string>) =>
    spawnSync(exe('svalinn-server'), [], {
      // Not the repository folder: the server would read your .env file there.
      cwd: os.tmpdir(),
      // A port nothing listens on: if the server did start, it fails to bind instead of running.
      env: { PATH: process.env.PATH ?? '', DATABASE_URL, PORT: '1', ...env },
      encoding: 'utf8',
      timeout: 20_000,
    });

  test('refuses to start without a proper JWT secret', () => {
    expect(start({}).stderr).toContain('JWT_SECRET is not set');
    expect(start({ JWT_SECRET: 'dev-secret-change-me-in-production' }).stderr).toContain('old built-in default');
    expect(start({ JWT_SECRET: 'short', APP_ENV: 'production' }).stderr).toContain('shorter than 32');
  });
});

test('CORS allows the app (including PUT) and blocks other sites', async () => {
  const preflight = (origin: string, method: string) =>
    fetch(`${API}/users/me/password`, {
      method: 'OPTIONS',
      headers: { Origin: origin, 'Access-Control-Request-Method': method, 'Access-Control-Request-Headers': 'authorization,content-type' },
    });
  const ok = await preflight(APP_URL, 'PUT');
  expect(ok.headers.get('access-control-allow-origin')).toBe(APP_URL);
  expect(ok.headers.get('access-control-allow-methods')).toContain('PUT');

  const evil = await preflight('https://evil.example', 'PUT');
  expect(evil.headers.get('access-control-allow-origin')).toBeNull();
});
