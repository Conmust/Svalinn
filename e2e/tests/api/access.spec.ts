import { test, expect } from '@playwright/test';
import { API_URL } from '../../support/config';
import {
  admin, call, callForm, createServer, join, jwtPayload, login, nowSeconds, openSocket, post, postMessage,
  register, signFileLink, sql,
} from '../../support/api';

const PNG = Uint8Array.from(Buffer.from('89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c489', 'hex'));
const fetchFile = (link: string, headers: Record<string, string> = {}) => fetch(API_URL + link, { headers });

test('outsiders can do nothing in a server', async () => {
  const owner = await register('own');
  const outsider = await register('out');
  const { server, channel } = await createServer(owner);

  expect((await call(outsider, 'GET', `/servers/${server.id}/channels`)).status).toBe(403);
  expect((await call(outsider, 'POST', `/servers/${server.id}/channels`, { name: 'x' })).status).toBe(403);
  expect((await call(outsider, 'GET', `/channels/${channel.id}/messages`)).status).toBe(403);
  expect((await postMessage(outsider, channel.id, 'spam')).status).toBe(403);
  expect((await call(outsider, 'GET', `/servers/${server.id}/members`)).status).toBe(403);
  expect((await call(outsider, 'PATCH', `/servers/${server.id}`, { name: 'pwned' })).status).toBe(403);
  expect((await call(outsider, 'GET', `/servers/${server.id}/invites`)).status).toBe(403);
});

test('outsiders get no live events from a server', async () => {
  const owner = await register('own');
  const member = await register('mem');
  const outsider = await register('out');
  const { server, channel } = await createServer(owner);
  await join(owner, server.id, member);

  const [memberWs, outsiderWs] = await Promise.all([openSocket(member), openSocket(outsider)]);
  await postMessage(owner, channel.id, 'secret plans');
  const event = await memberWs.waitFor((e) => e.type === 'new_message');
  expect(event.payload.content).toBe('secret plans');
  await new Promise((r) => setTimeout(r, 300));
  expect(outsiderWs.events.filter((e) => e.type === 'new_message')).toHaveLength(0);
  memberWs.close();
  outsiderWs.close();
});

test.describe('uploads', () => {
  test('accepts large attachments and rejects oversized emojis clearly', async () => {
    const owner = await register('own');
    const { server, channel } = await createServer(owner);

    const big = await postMessage(owner, channel.id, 'big', { name: 'big.bin', type: 'application/octet-stream', data: new Uint8Array(5_000_000) });
    expect(big.status).toBe(200); // over axum's default 2 MB

    const form = new FormData();
    form.append('name', 'huge');
    form.append('file', new Blob([new Uint8Array(3 * 1024 * 1024)], { type: 'image/png' }), 'huge.png');
    const emoji = await callForm(owner, 'POST', `/servers/${server.id}/emojis`, form);
    expect(emoji.status).toBe(413);
    expect(emoji.body.error).toContain('2 MB');
  });

  test('crafted file names stay inside the uploads folder', async () => {
    const owner = await register('own');
    const { channel } = await createServer(owner);
    const res = await postMessage(owner, channel.id, 'x', { name: 'x./../../evil', type: 'text/plain', data: 'x' });
    const stored = (await sql(`SELECT attachment_url FROM messages WHERE id = $1`, [res.body.id]))[0].attachment_url;
    expect(stored).toMatch(/^\/uploads\/msg_[0-9a-f-]+_[0-9a-f-]+\.bin$/);
  });
});

test.describe('file links', () => {
  async function setup() {
    const owner = await register('own');
    const member = await register('mem');
    const outsider = await register('out');
    const { server, channel } = await createServer(owner);
    await join(owner, server.id, member);
    const msg = (await postMessage(owner, channel.id, 'pic', { name: 'pic.png', type: 'image/png', data: PNG })).body;
    const stored: string = (await sql(`SELECT attachment_url FROM messages WHERE id = $1`, [msg.id]))[0].attachment_url;
    const memberLink = (await call(member, 'GET', `/channels/${channel.id}/messages`)).body.find((m: any) => m.id === msg.id).attachment_url;
    return { owner, member, outsider, server, channel, msg, stored, name: stored.replace('/uploads/', ''), memberLink };
  }

  test('members get signed, per-person links with safe headers', async () => {
    const { msg, stored, memberLink, member } = await setup();
    expect(msg.attachment_url).toMatch(/^\/api\/v1\/files\//);
    expect(memberLink).toContain(`u=${member.user.id}`);
    expect(memberLink).not.toBe(msg.attachment_url);

    const res = await fetchFile(memberLink);
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toBe('image/png');
    expect(res.headers.get('x-content-type-options')).toBe('nosniff');
    expect(res.headers.get('content-security-policy')).toBe('sandbox');
    expect(res.headers.get('cache-control')).toMatch(/^private/);

    expect((await fetchFile(stored)).status).toBe(404); // no public /uploads route
  });

  test('tampered, expired and borrowed links are refused', async () => {
    const { memberLink, member, outsider, name } = await setup();
    const tampered = memberLink.replace(/sig=(.)/, (_: string, c: string) => `sig=${c === 'a' ? 'b' : 'a'}`);
    expect((await fetchFile(tampered)).status).toBe(403);
    expect((await fetchFile(memberLink.replace(member.user.id, outsider.user.id))).status).toBe(403);

    const sid = jwtPayload(member.token).sid;
    expect((await fetchFile(signFileLink(name, member.user.id, sid, nowSeconds() - 5))).status).toBe(403);

    // Even a validly signed link doesn't help someone outside the server.
    const outsiderLink = signFileLink(name, outsider.user.id, jwtPayload(outsider.token).sid, nowSeconds() + 600);
    expect((await fetchFile(outsiderLink)).status).toBe(404);
    expect((await fetchFile(signFileLink('..%2F.env', member.user.id, sid, nowSeconds() + 600))).status).toBe(404);
  });

  test('saved links stop working on ban, logout or leaving', async () => {
    const { owner, member, server, channel, msg, memberLink } = await setup();
    expect((await fetchFile(memberLink)).status).toBe(200);
    await post('/auth/logout', { refresh_token: member.refresh_token });
    expect((await fetchFile(memberLink)).status).toBe(403);

    const again = (await login(member.email, member.password)).body;
    const fresh = (await call({ ...member, ...again }, 'GET', `/channels/${channel.id}/messages`)).body.find((m: any) => m.id === msg.id).attachment_url;
    expect((await fetchFile(fresh)).status).toBe(200);
    await call(owner, 'DELETE', `/servers/${server.id}/members/${member.user.id}`);
    expect((await fetchFile(fresh)).status).toBe(404);

    const third = await register('mem');
    await join(owner, server.id, third);
    const link = (await call(third, 'GET', `/channels/${channel.id}/messages`)).body.find((m: any) => m.id === msg.id).attachment_url;
    expect(admin('ban', third.user.username, 'test')).toContain('Banned');
    expect((await fetchFile(link)).status).toBe(403);
    admin('unban', third.user.username);
  });

  test('uploaded web pages download instead of running; video supports seeking', async () => {
    const owner = await register('own');
    const { channel } = await createServer(owner);
    await postMessage(owner, channel.id, 'page', { name: 'x.html', type: 'text/html', data: '<script>alert(1)</script>' });
    await postMessage(owner, channel.id, 'clip', { name: 'clip.mp4', type: 'video/mp4', data: new Uint8Array(100_000) });
    const msgs = (await call(owner, 'GET', `/channels/${channel.id}/messages`)).body;

    const html = await fetchFile(msgs.find((m: any) => m.content === 'page').attachment_url);
    expect(html.headers.get('content-disposition')).toBe('attachment');
    expect(html.headers.get('content-security-policy')).toBe('sandbox');

    const video = await fetchFile(msgs.find((m: any) => m.content === 'clip').attachment_url, { Range: 'bytes=0-999' });
    expect(video.status).toBe(206);
    expect(video.headers.get('content-range')).toBe('bytes 0-999/100000');
  });

  test('live events carry links signed for each recipient', async () => {
    const owner = await register('own');
    const member = await register('mem');
    const { server, channel } = await createServer(owner);
    await join(owner, server.id, member);
    const ws = await openSocket(member);
    await postMessage(owner, channel.id, 'live pic', { name: 'p.png', type: 'image/png', data: PNG });
    const event = await ws.waitFor((e) => e.type === 'new_message');
    expect(event.payload.attachment_url).toContain(`u=${member.user.id}`);
    expect((await fetchFile(event.payload.attachment_url)).status).toBe(200);
    ws.close();
  });
});
