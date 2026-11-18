import { test, expect } from '@playwright/test';
import {
  admin, call, createServer, join, login, openSocket, post, postMessage, register, sql, uniq,
} from '../../support/api';

test.describe('account bans and revocation', () => {
  test('a ban cuts off connections, tokens, refresh and login at once', async () => {
    const bad = await register('bad');
    const bystander = await register('ok');
    const [badWs, okWs] = await Promise.all([openSocket(bad), openSocket(bystander)]);

    expect(admin('ban', bad.user.username, 'spamming')).toContain('Banned');
    const closed = await badWs.waitClosed();
    expect(closed.code).toBe(4003);
    expect(closed.reason).toContain('spamming');

    const api = await call(bad, 'GET', '/servers');
    expect(api.status).toBe(401);
    expect(api.body.error).toContain('banned');
    expect((await post('/auth/refresh', { refresh_token: bad.refresh_token })).body.error).toContain('banned: spamming');
    expect((await login(bad.email, bad.password)).status).toBe(403);

    expect(okWs.closed).toBeNull();
    expect((await call(bystander, 'GET', '/servers')).status).toBe(200);

    expect(admin('unban', bad.user.username)).toContain('Unbanned');
    expect((await login(bad.email, bad.password)).status).toBe(200);
    expect((await post('/auth/refresh', { refresh_token: bad.refresh_token })).status).toBe(401); // old sessions stay dead
    okWs.close();
  });

  test('bans made directly in the database also apply immediately', async () => {
    const u = await register('bad');
    const ws = await openSocket(u);
    await sql(`UPDATE users SET banned_at = now() WHERE id = $1`, [u.user.id]);
    expect((await ws.waitClosed()).code).toBe(4003);
    expect((await call(u, 'GET', '/servers')).status).toBe(401);
    admin('unban', u.user.username);
  });

  test('logout closes only that session', async () => {
    const u = await register('multi');
    const second = { ...u, ...(await login(u.email, u.password)).body };
    const [ws1, ws2] = await Promise.all([openSocket(u), openSocket(second)]);
    await post('/auth/logout', { refresh_token: u.refresh_token });
    expect((await ws1.waitClosed()).code).toBe(4001);
    expect((await call(u, 'GET', '/servers')).status).toBe(401);
    expect(ws2.closed).toBeNull();
    expect((await call(second, 'GET', '/servers')).status).toBe(200);

    expect(admin('revoke-sessions', u.user.username)).toContain('Ended');
    expect((await ws2.waitClosed()).code).toBe(4001);
  });
});

test.describe('invites', () => {
  test('create, preview, join, and use limits', async () => {
    const owner = await register('own');
    const [amy, bob, cat] = await Promise.all([register('amy'), register('bob'), register('cat')]);
    const { server } = await createServer(owner, uniq('Inv'));

    const invite = (await call(owner, 'POST', `/servers/${server.id}/invites`, { expires_in_hours: 24, max_uses: 2 })).body;
    expect(invite.code).toMatch(/^[a-zA-Z2-9]{10}$/);
    expect((await call(owner, 'POST', `/servers/${server.id}/invites`, { expires_in_hours: 99999 })).status).toBe(400);

    const preview = await call(amy, 'GET', `/invites/${encodeURIComponent(`https://example.test/invite/${invite.code}`)}`);
    expect(preview.body).toMatchObject({ server_name: server.name, member_count: 1, already_member: false });

    expect((await call(amy, 'POST', `/invites/${invite.code}`)).status).toBe(200);
    expect((await call(amy, 'POST', `/invites/${invite.code}`)).status).toBe(200); // already a member: no extra use
    expect((await call(bob, 'POST', `/invites/${invite.code}`)).status).toBe(200);
    expect((await call(cat, 'POST', `/invites/${invite.code}`)).status).toBe(404); // used up

    expect((await call(amy, 'POST', `/servers/${server.id}/invites`, {})).status).toBe(403); // members can't create
  });

  test('a one-use invite can only be used once, even in a race', async () => {
    const owner = await register('own');
    const racers = await Promise.all([register('r'), register('r'), register('r')]);
    const { server } = await createServer(owner);
    const invite = (await call(owner, 'POST', `/servers/${server.id}/invites`, { max_uses: 1 })).body;
    const results = await Promise.all(racers.map((u) => call(u, 'POST', `/invites/${invite.code}`)));
    expect(results.map((r) => r.status).sort()).toEqual([200, 404, 404]);
    expect((await call(owner, 'GET', `/servers/${server.id}/members`)).body).toHaveLength(2);
  });

  test('revoked and expired invites stop working', async () => {
    const owner = await register('own');
    const u = await register('u');
    const { server } = await createServer(owner);
    const a = (await call(owner, 'POST', `/servers/${server.id}/invites`, {})).body;
    const b = (await call(owner, 'POST', `/servers/${server.id}/invites`, { expires_in_hours: 1 })).body;
    expect((await call(owner, 'DELETE', `/servers/${server.id}/invites/${a.code}`)).status).toBe(204);
    await sql(`UPDATE server_invites SET expires_at = now() - interval '1 second' WHERE code = $1`, [b.code]);
    expect((await call(u, 'POST', `/invites/${a.code}`)).status).toBe(404);
    expect((await call(u, 'POST', `/invites/${b.code}`)).status).toBe(404);
  });
});

test.describe('membership', () => {
  async function setup() {
    const owner = await register('own');
    const [mod, amy] = await Promise.all([register('mod'), register('amy')]);
    const { server, channel } = await createServer(owner);
    await join(owner, server.id, mod, amy);
    await call(owner, 'PATCH', `/servers/${server.id}/members/${mod.user.id}/role`, { role: 'moderator' });
    return { owner, mod, amy, server, channel };
  }

  test('kick: removed at once, can rejoin', async () => {
    const { owner, mod, amy, server, channel } = await setup();
    const ws = await openSocket(amy);
    expect((await call(amy, 'DELETE', `/servers/${server.id}/members/${mod.user.id}`)).status).toBe(403); // member
    expect((await call(mod, 'DELETE', `/servers/${server.id}/members/${owner.user.id}`)).status).toBe(403); // higher rank
    expect((await call(mod, 'DELETE', `/servers/${server.id}/members/${amy.user.id}`)).status).toBe(204);

    const notice = await ws.waitFor((e) => e.type === 'removed_from_server');
    expect(notice.payload.reason).toBe('kicked');
    expect((await call(amy, 'GET', `/channels/${channel.id}/messages`)).status).toBe(403);
    await join(owner, server.id, amy);
    ws.close();
  });

  test('server ban: removed, can\'t rejoin until unbanned', async () => {
    const { owner, mod, amy, server } = await setup();
    expect((await call(mod, 'POST', `/servers/${server.id}/bans`, { user_id: amy.user.id, reason: 'spam' })).status).toBe(204);
    const invite = (await call(owner, 'POST', `/servers/${server.id}/invites`, {})).body;
    const rejoin = await call(amy, 'POST', `/invites/${invite.code}`);
    expect(rejoin.status).toBe(403);
    expect(rejoin.body.error).toContain('banned');

    const bans = (await call(mod, 'GET', `/servers/${server.id}/bans`)).body;
    expect(bans).toEqual([expect.objectContaining({ user_id: amy.user.id, reason: 'spam' })]);
    expect((await call(amy, 'GET', `/servers/${server.id}/bans`)).status).toBe(403);

    expect((await call(owner, 'DELETE', `/servers/${server.id}/bans/${amy.user.id}`)).status).toBe(204);
    expect((await call(amy, 'POST', `/invites/${invite.code}`)).status).toBe(200);
  });

  test('leaving: anyone but the owner', async () => {
    const { owner, amy, server } = await setup();
    expect((await call(owner, 'DELETE', `/servers/${server.id}/members/me`)).status).toBe(400);
    expect((await call(amy, 'DELETE', `/servers/${server.id}/members/me`)).status).toBe(204);
    expect((await call(amy, 'DELETE', `/servers/${server.id}/members/me`)).status).toBe(404);
  });

  test('roles follow the rank rules', async () => {
    const { owner, mod, amy, server } = await setup();
    const setRole = (actor: typeof owner, target: typeof owner, role: string) =>
      call(actor, 'PATCH', `/servers/${server.id}/members/${target.user.id}/role`, { role });
    const ws = await openSocket(amy);

    expect((await setRole(mod, amy, 'moderator')).status).toBe(403); // moderators can't change roles
    expect((await setRole(owner, mod, 'admin')).status).toBe(200);
    expect((await setRole(mod, amy, 'admin')).status).toBe(403); // admins can't make admins
    expect((await setRole(mod, amy, 'moderator')).status).toBe(200);
    expect((await setRole(mod, owner, 'member')).status).toBe(403);
    expect((await setRole(mod, mod, 'member')).status).toBe(400);
    expect((await setRole(owner, amy, 'king')).status).toBe(400);

    const event = await ws.waitFor((e) => e.type === 'member_updated' && e.payload.user_id === amy.user.id);
    expect(event.payload.role).toBe('moderator');
    ws.close();
  });

  test('ownership transfer needs the owner and their password', async () => {
    const { owner, mod, amy, server } = await setup();
    const transfer = (actor: typeof owner, to: typeof owner, current_password: string) =>
      call(actor, 'POST', `/servers/${server.id}/transfer`, { user_id: to.user.id, current_password });
    expect((await transfer(mod, mod, 'secret123')).status).toBe(403);
    expect((await transfer(owner, amy, 'wrong')).status).toBe(400);
    expect((await transfer(owner, amy, 'secret123')).status).toBe(204);

    const members = (await call(amy, 'GET', `/servers/${server.id}/members`)).body;
    expect(members.find((m: any) => m.id === amy.user.id)).toMatchObject({ is_owner: true, role: 'admin' });
    expect(members.find((m: any) => m.id === owner.user.id)).toMatchObject({ is_owner: false, role: 'admin' });
    expect((await call(owner, 'DELETE', `/servers/${server.id}/members/me`)).status).toBe(204);
  });

  test('deleting a server removes everything and tells everyone', async () => {
    const { owner, mod, amy, server, channel } = await setup();
    await postMessage(amy, channel.id, 'bye', { name: 'f.txt', type: 'text/plain', data: 'x' });
    const ws = await openSocket(amy);
    expect((await call(mod, 'DELETE', `/servers/${server.id}`, { current_password: 'secret123' })).status).toBe(403);
    expect((await call(owner, 'DELETE', `/servers/${server.id}`, { current_password: 'wrong' })).status).toBe(400);
    expect((await call(owner, 'DELETE', `/servers/${server.id}`, { current_password: 'secret123' })).status).toBe(204);

    expect((await ws.waitFor((e) => e.type === 'removed_from_server')).payload.reason).toBe('deleted');
    const [left] = await sql(
      `SELECT (SELECT count(*) FROM servers WHERE id = $1) + (SELECT count(*) FROM channels WHERE server_id = $1) +
              (SELECT count(*) FROM server_members WHERE server_id = $1) AS n`,
      [server.id],
    );
    expect(Number(left.n)).toBe(0);
    ws.close();
  });

  test('channels: members create, admins rename and delete, everyone sees it live', async () => {
    const { owner, mod, amy, server } = await setup();
    const ws = await openSocket(amy);
    const ch = (await call(amy, 'POST', `/servers/${server.id}/channels`, { name: 'random' })).body;
    await ws.waitFor((e) => e.type === 'channel_created' && e.payload.id === ch.id);

    expect((await call(mod, 'PATCH', `/channels/${ch.id}`, { name: 'x' })).status).toBe(403);
    expect((await call(owner, 'PATCH', `/channels/${ch.id}`, { name: 'off-topic' })).status).toBe(200);
    expect((await ws.waitFor((e) => e.type === 'channel_updated')).payload.name).toBe('off-topic');

    expect((await call(mod, 'DELETE', `/channels/${ch.id}`)).status).toBe(403);
    expect((await call(owner, 'DELETE', `/channels/${ch.id}`)).status).toBe(204);
    await ws.waitFor((e) => e.type === 'channel_deleted' && e.payload.id === ch.id);
    ws.close();
  });
});

test('a site owner outranks server owners but can\'t see servers they haven\'t joined', async () => {
  const name = uniq('Boss');
  expect(admin('create-user', name, `${name}@example.test`, '123456', '--site-owner')).toContain('site owner');
  const boss = { ...(await login(`${name}@example.test`, '123456')).body, ip: '10.9.9.9' };
  const owner = await register('own');
  const { server, channel } = await createServer(owner);

  expect((await call(boss, 'GET', `/channels/${channel.id}/messages`)).status).toBe(403);
  await join(owner, server.id, boss);
  expect((await call(boss, 'GET', `/servers/${server.id}/role`)).body).toMatchObject({ rank: 5, is_site_owner: true, is_owner: false });
  expect((await call(boss, 'PATCH', `/servers/${server.id}`, { description: 'managed' })).status).toBe(200);
  expect((await call(owner, 'DELETE', `/servers/${server.id}/members/${boss.user.id}`)).status).toBe(403);
  expect((await call(owner, 'POST', `/servers/${server.id}/bans`, { user_id: boss.user.id })).status).toBe(403);
  expect((await call(boss, 'DELETE', `/servers/${server.id}/members/me`)).status).toBe(204);
  expect(admin('remove-site-owner', name)).toContain('no longer');
});
