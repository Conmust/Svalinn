import { test, expect } from '@playwright/test';
import { call, createServer, join, login, openSocket, postMessage, register, sql } from '../../support/api';

test('history loads a page at a time back to the first message', async () => {
  const u = await register('hist');
  const { channel } = await createServer(u);
  await sql(
    `INSERT INTO messages (channel_id, user_id, content, created_at)
     SELECT $1, $2, 'msg ' || i, now() - interval '1 hour' + i * interval '1 second' FROM generate_series(1, 120) i`,
    [channel.id, u.user.id],
  );
  const page = async (before?: string) =>
    (await call(u, 'GET', `/channels/${channel.id}/messages${before ? `?before=${before}` : ''}`)).body.map((m: any) => m);

  const latest = await page();
  expect(latest).toHaveLength(50);
  expect([latest[0].content, latest.at(-1).content]).toEqual(['msg 71', 'msg 120']);
  const older = await page(latest[0].id);
  expect([older.length, older[0].content, older.at(-1).content]).toEqual([50, 'msg 21', 'msg 70']);
  const oldest = await page(older[0].id);
  expect([oldest.length, oldest[0].content]).toEqual([20, 'msg 1']);
  expect((await call(u, 'GET', `/channels/${channel.id}/messages?before=${channel.server_id}`)).status).toBe(404);
});

test('authors can edit their messages; everyone sees it live', async () => {
  const owner = await register('own');
  const member = await register('mem');
  const { server, channel } = await createServer(owner);
  await join(owner, server.id, member);
  const msg = (await postMessage(member, channel.id, 'typo')).body;
  const ws = await openSocket(owner);

  expect((await call(owner, 'PATCH', `/messages/${msg.id}`, { content: 'hijack' })).status).toBe(403);
  expect((await call(member, 'PATCH', `/messages/${msg.id}`, { content: '  ' })).status).toBe(400);
  expect((await call(member, 'PATCH', `/messages/${msg.id}`, { content: 'x'.repeat(4001) })).status).toBe(400);
  expect((await call(member, 'PATCH', `/messages/${msg.id}`, { content: 'fixed' })).status).toBe(200);

  const event = await ws.waitFor((e) => e.type === 'message_updated' && e.payload.id === msg.id);
  expect(event.payload).toMatchObject({ content: 'fixed', is_edited: true });
  ws.close();
});

test('pin, lock, hide, react and delete follow their rules', async () => {
  const owner = await register('own');
  const member = await register('mem');
  const { server, channel } = await createServer(owner);
  await join(owner, server.id, member);
  const msg = (await postMessage(member, channel.id, 'hello')).body;
  const M = `/messages/${msg.id}`;
  expect(msg).toMatchObject({ reactions: [], is_hidden: false });

  expect((await call(member, 'POST', `${M}/pin`)).status).toBe(403);
  expect((await call(owner, 'POST', `${M}/pin`)).status).toBe(200);
  expect((await call(owner, 'POST', `${M}/lock`)).status).toBe(200);

  // Locked messages can still get reactions, but nobody can delete them.
  expect((await call(member, 'POST', `${M}/reactions`, { emoji: '🔥' })).status).toBe(200);
  const both = await call(owner, 'POST', `${M}/reactions`, { emoji: '🔥' });
  expect(both.body.reactions).toEqual([{ emoji: '🔥', count: 2, user_ids: [member.user.id, owner.user.id] }]);
  expect((await call(member, 'DELETE', M)).status).toBe(403);
  expect((await call(owner, 'DELETE', M)).status).toBe(403);

  // Hiding only affects the person who hid it.
  await call(member, 'POST', `${M}/hide`);
  const view = async (u: typeof owner) => (await call(u, 'GET', `/channels/${channel.id}/messages`)).body[0];
  expect((await view(member)).is_hidden).toBe(true);
  expect((await view(owner)).is_hidden).toBe(false);
  expect(await view(member)).toMatchObject({ is_pinned: true, is_locked: true });

  expect((await call(member, 'DELETE', `${M}/reactions/${encodeURIComponent('🔥')}`)).body.reactions[0].count).toBe(1);
  expect((await call(owner, 'DELETE', `${M}/lock`)).status).toBe(200);
  expect((await call(member, 'DELETE', M)).status).toBe(200);
});

test('presence follows open connections and keeps a chosen status', async () => {
  const watcher = await register('watch');
  const bob = await register('bob');
  const { server } = await createServer(watcher);
  await join(watcher, server.id, bob);
  const status = async () =>
    (await call(watcher, 'GET', `/servers/${server.id}/members`)).body.find((m: any) => m.id === bob.user.id).status;
  const settle = () => new Promise((r) => setTimeout(r, 300));

  expect(await status()).toBe('offline');
  const w1 = await openSocket(bob);
  const w2 = await openSocket(bob);
  expect(await status()).toBe('online');
  w1.close(); await settle();
  expect(await status()).toBe('online'); // still open in another window
  w2.close(); await settle();
  expect(await status()).toBe('offline');

  const w3 = await openSocket(bob);
  await call(bob, 'PATCH', '/users/me/status', { status: 'busy' });
  w3.close(); await settle();
  const w4 = await openSocket(bob);
  expect(await status()).toBe('busy');
  w4.close();
});

test.describe('account settings', () => {
  test('change email needs the current password and a free, valid address', async () => {
    const u = await register('acct');
    const other = await register('acct');
    const change = (email: string, current_password: string) => call(u, 'PATCH', '/users/me/email', { email, current_password });
    expect((await change('new@example.test', 'wrong')).status).toBe(400);
    expect((await change('not-an-email', u.password)).status).toBe(400);
    expect((await change(other.email, u.password)).body.error).toContain('already in use');

    const fresh = `new.${u.email}`;
    expect((await change(fresh, u.password)).status).toBe(200);
    expect((await call(u, 'GET', '/users/me/account')).body.email).toBe(fresh);
    expect((await login(fresh, u.password)).status).toBe(200);
    expect((await login(u.email, u.password)).status).toBe(400);
  });

  test('change password logs out other devices only', async () => {
    const u = await register('acct');
    const other = { ...u, ...(await login(u.email, u.password)).body };
    const ws = await openSocket(other);

    expect((await call(u, 'PUT', '/users/me/password', { current_password: u.password, new_password: '123' })).status).toBe(400);
    const res = await call(u, 'PUT', '/users/me/password', { current_password: u.password, new_password: 'brand-new-1' });
    expect(res.body.other_sessions_ended).toBe(1);

    expect((await ws.waitClosed()).code).toBe(4001);
    expect((await call(other, 'GET', '/servers')).status).toBe(401);
    expect((await call(u, 'GET', '/servers')).status).toBe(200);
    expect((await login(u.email, u.password)).status).toBe(400);
    expect((await login(u.email, 'brand-new-1')).status).toBe(200);
  });

  test('wrong current passwords are rate limited', async () => {
    const u = await register('acct');
    const statuses = [];
    for (let i = 0; i < 6; i++) statuses.push((await call(u, 'PATCH', '/users/me/email', { email: 'z@example.test', current_password: 'bad' })).status);
    expect(statuses).toEqual([400, 400, 400, 400, 400, 429]);
  });
});
