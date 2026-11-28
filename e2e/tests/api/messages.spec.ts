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

// Channel messages are now mandatory end-to-end encrypted, and (same as
// DMs, which never supported editing at all) an encrypted message can't
// be edited -- re-encrypting it would mean re-deriving the recipient set,
// which risks handing a member who joined later the content of a message
// that predates them (see `messages.rs::edit_message`). Editing still
// works for legacy plaintext history (pre-dating server-level E2EE),
// which is exercised here against a directly-inserted plaintext row,
// mirroring the "history loads a page at a time" test above.
test('authors can edit a legacy plaintext message; everyone sees it live', async () => {
  const owner = await register('own');
  const member = await register('mem');
  const { server, channel } = await createServer(owner);
  await join(owner, server.id, member);
  const [{ id: msgId }] = await sql(
    `INSERT INTO messages (channel_id, user_id, content) VALUES ($1, $2, 'typo') RETURNING id`,
    [channel.id, member.user.id],
  );
  const ws = await openSocket(owner);

  expect((await call(owner, 'PATCH', `/messages/${msgId}`, { content: 'hijack' })).status).toBe(403);
  expect((await call(member, 'PATCH', `/messages/${msgId}`, { content: '  ' })).status).toBe(400);
  expect((await call(member, 'PATCH', `/messages/${msgId}`, { content: 'x'.repeat(4001) })).status).toBe(400);
  expect((await call(member, 'PATCH', `/messages/${msgId}`, { content: 'fixed' })).status).toBe(200);

  const event = await ws.waitFor((e) => e.type === 'message_updated' && e.payload.id === msgId);
  expect(event.payload).toMatchObject({ content: 'fixed', is_edited: true });
  ws.close();
});

test('editing a real (always-encrypted) channel message is rejected', async () => {
  const owner = await register('own');
  const { channel } = await createServer(owner);
  const msg = (await postMessage(owner, channel.id, 'typo')).body;
  expect((await call(owner, 'PATCH', `/messages/${msg.id}`, { content: 'fixed' })).status).toBe(400);
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

// Channel messages are per-device end-to-end encrypted with no history
// backfill (see `routes::messages::create_message`'s doc comment), so a
// member who joins after a message was sent never gets a decryption key
// for it -- including a pinned announcement or rule. This exercises the
// explicit, moderator-only escape hatch: revealing a pinned message's
// plaintext on the server so a later joiner can still read it, and the
// toggle/unpin rules around that reveal.
test('pinning with a reveal lets a member who joins later read it; unpinning clears it', async () => {
  const owner = await register('pinown');
  const { server, channel } = await createServer(owner);
  const msg = (await postMessage(owner, channel.id, 'Server rules: be kind.')).body;
  const M = `/messages/${msg.id}`;

  // A plain member can't reveal (or pin) at all.
  const member = await register('pinmem');
  await join(owner, server.id, member);
  expect((await call(member, 'PUT', `${M}/pin-visibility`, { plaintext_content: 'sneaky' })).status).toBe(403);

  // Revealing before pinning, or revealing a plaintext (unencrypted) row,
  // doesn't make sense and is rejected.
  expect((await call(owner, 'PUT', `${M}/pin-visibility`, { plaintext_content: 'too early' })).status).toBe(400);

  // Pin-and-reveal in one step.
  const pinned = await call(owner, 'POST', `${M}/pin`, { reveal_plaintext: 'Server rules: be kind.' });
  expect(pinned.status).toBe(200);
  expect(pinned.body.pin_plaintext_content).toBe('Server rules: be kind.');

  // A member who joins AFTER the send -- and so has no `message_recipients`
  // row for this message at all -- can still read it via the pinned list.
  const lateJoiner = await register('pinlate');
  await join(owner, server.id, lateJoiner);
  const list = (await call(lateJoiner, 'GET', `/channels/${channel.id}/pinned`)).body;
  expect(list).toHaveLength(1);
  expect(list[0]).toMatchObject({ id: msg.id, pin_plaintext_content: 'Server rules: be kind.' });
  expect(list[0].recipients ?? []).toEqual([]);

  // The reveal can be hidden again without unpinning...
  expect((await call(owner, 'PUT', `${M}/pin-visibility`, { plaintext_content: null })).status).toBe(200);
  const stillPinned = (await call(lateJoiner, 'GET', `/channels/${channel.id}/pinned`)).body;
  expect(stillPinned).toMatchObject([{ id: msg.id, pin_plaintext_content: null }]);

  // ...and re-revealed later via the same toggle.
  expect((await call(owner, 'PUT', `${M}/pin-visibility`, { plaintext_content: 'Server rules: be kind.' })).status).toBe(200);

  // Unpinning clears any revealed plaintext -- the reveal is scoped to
  // "while pinned", not a standing exception for this message.
  expect((await call(owner, 'DELETE', `${M}/pin`)).status).toBe(200);
  expect((await call(lateJoiner, 'GET', `/channels/${channel.id}/pinned`)).body).toEqual([]);
});

// @mentions: the server never sees channel message plaintext (it's
// per-device fan-out encrypted), so it can't detect a "@username" itself --
// the client resolves mentions from the plaintext before encrypting and
// sends the resulting user ids as explicit unencrypted metadata alongside
// the ciphertext. These tests exercise that metadata path end-to-end
// through the real HTTP API, mirroring the Rust unit tests in
// `routes/messages.rs` but confirming the whole stack is wired correctly.
test('a message can mention a current member, who sees it in the returned message and on fetch', async () => {
  const owner = await register('men');
  const member = await register('men');
  const { channel } = await createServer(owner);
  await join(owner, channel.server_id, member);

  const posted = (await postMessage(owner, channel.id, `hey @${member.user.username}`, undefined, [member.user.id])).body;
  expect(posted.mentioned_user_ids).toEqual([member.user.id]);

  const fetched = (await call(member, 'GET', `/channels/${channel.id}/messages`)).body;
  expect(fetched.find((m: any) => m.id === posted.id).mentioned_user_ids).toEqual([member.user.id]);
});

test('mentioning someone who cannot view the channel is rejected', async () => {
  const owner = await register('men');
  const outsider = await register('men');
  const { channel } = await createServer(owner);

  const res = await postMessage(owner, channel.id, 'hey @stranger', undefined, [outsider.user.id]);
  expect(res.status).toBe(400);
});

test('duplicate mentions in the same message are deduped', async () => {
  const owner = await register('men');
  const member = await register('men');
  const { channel } = await createServer(owner);
  await join(owner, channel.server_id, member);

  const posted = (await postMessage(owner, channel.id, `@${member.user.username} @${member.user.username}`, undefined, [member.user.id, member.user.id])).body;
  expect(posted.mentioned_user_ids).toEqual([member.user.id]);
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
