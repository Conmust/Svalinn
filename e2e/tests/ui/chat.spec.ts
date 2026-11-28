import { test, expect } from '@playwright/test';
import path from 'node:path';
import os from 'node:os';
import fs from 'node:fs';
import zlib from 'node:zlib';
import { createServer, join, postMessage, register, sql } from '../../support/api';
import { messageRow, openAs, openChannel, pageErrors, sendMessage } from '../../support/ui';

async function twoMembers(browser: import('@playwright/test').Browser) {
  const owner = await register('own');
  const member = await register('mem');
  const { server, channel } = await createServer(owner);
  await join(owner, server.id, member);
  const ownerPage = await openAs(browser, owner);
  const memberPage = await openAs(browser, member);
  await openChannel(ownerPage, server.name);
  await openChannel(memberPage, server.name);
  return { owner, member, server, channel, ownerPage, memberPage };
}

/** A small valid PNG, written to a temp file for the file picker. */
function pngFile(): string {
  const chunk = (type: string, data: Buffer) => {
    const len = Buffer.alloc(4); len.writeUInt32BE(data.length);
    const crc = Buffer.alloc(4); crc.writeUInt32BE(zlib.crc32(Buffer.concat([Buffer.from(type), data])) >>> 0);
    return Buffer.concat([len, Buffer.from(type), data, crc]);
  };
  const ihdr = Buffer.alloc(13); ihdr.writeUInt32BE(8, 0); ihdr.writeUInt32BE(8, 4); ihdr[8] = 8; ihdr[9] = 2;
  const raw = Buffer.concat(Array.from({ length: 8 }, () => Buffer.concat([Buffer.from([0]), Buffer.alloc(24, 0x80)])));
  const file = path.join(os.tmpdir(), `e2e-${process.pid}-green.png`);
  fs.writeFileSync(file, Buffer.concat([Buffer.from('89504e470d0a1a0a', 'hex'), chunk('IHDR', ihdr), chunk('IDAT', zlib.deflateSync(raw)), chunk('IEND', Buffer.alloc(0))]));
  return file;
}

test('messages arrive live for others, once for the sender', async ({ browser }) => {
  const { ownerPage, memberPage } = await twoMembers(browser);
  await sendMessage(ownerPage, 'hello there');
  await expect(memberPage.getByText('hello there')).toBeVisible();
  await ownerPage.waitForTimeout(500);
  await expect(ownerPage.getByText('hello there')).toHaveCount(1);
  expect(pageErrors(ownerPage)).toEqual([]);
  expect(pageErrors(memberPage)).toEqual([]);
});

test('image attachments display for everyone', async ({ browser }) => {
  const { ownerPage, memberPage } = await twoMembers(browser);
  await ownerPage.locator('input[type=file]').setInputFiles(pngFile());
  await sendMessage(ownerPage, 'a picture');
  for (const page of [ownerPage, memberPage]) {
    const img = page.locator('img[alt$="green.png"]');
    await expect(img).toBeVisible();
    await expect.poll(() => img.evaluate((i: HTMLImageElement) => i.naturalWidth)).toBeGreaterThan(0);
    // Channel attachments are mandatory end-to-end encrypted now: the
    // server only ever serves the ciphertext blob, so what's rendered is
    // a `blob:` URL built from the bytes decrypted client-side (see
    // `ensureAttachmentDecrypted` in `ChatArea.svelte`), not the signed
    // `/api/v1/files/...` server link directly.
    expect(await img.getAttribute('src')).toContain('blob:');
  }
});

test('the emoji button inserts at the cursor', async ({ browser }) => {
  const { ownerPage: page } = await twoMembers(browser);
  const input = page.getByPlaceholder('Type a message...');
  await input.fill('hello world');
  await input.evaluate((el: HTMLInputElement) => el.setSelectionRange(5, 5));
  await page.getByTitle('Insert emoji').click();
  await page.getByRole('button', { name: '🚀' }).click();
  await expect(input).toHaveValue('hello🚀 world');
  await expect(page.getByText('Insert Emoji')).toHaveCount(0);
});

// Channel messages are mandatory end-to-end encrypted now, and (same as
// DMs, which never supported editing) an encrypted message can't be
// edited, since re-encrypting it for the current member set on edit would
// risk handing a later-joining member content from before they joined.
// The app hides the Edit button entirely for an encrypted message --
// delete and resend is the supported path instead.
test('a sent (always-encrypted) message has no edit option', async ({ browser }) => {
  const { memberPage } = await twoMembers(browser);
  await sendMessage(memberPage, 'second line');
  const row = messageRow(memberPage, 'second line');
  await row.hover();
  await expect(row.getByRole('button', { name: 'Edit', exact: true })).toHaveCount(0);
});

test('reactions, pins and locks from the message toolbar', async ({ browser }) => {
  const { ownerPage, memberPage } = await twoMembers(browser);
  await sendMessage(memberPage, 'react to me');

  // Members don't get moderator tools.
  const memberRow = messageRow(memberPage, 'react to me');
  await memberRow.hover();
  await expect(memberRow.getByRole('button', { name: 'Pin', exact: true })).toHaveCount(0);
  await memberRow.getByTitle('Add reaction').click();
  await memberPage.getByRole('button', { name: '🔥', exact: true }).click();

  const ownerRow = messageRow(ownerPage, 'react to me');
  await expect(ownerRow.getByRole('button', { name: /🔥\s*1/ })).toBeVisible();
  await ownerRow.getByRole('button', { name: /🔥\s*1/ }).click();
  await expect(memberRow.getByRole('button', { name: /🔥\s*2/ })).toBeVisible();

  await ownerRow.hover();
  await ownerRow.getByRole('button', { name: 'Pin', exact: true }).click();
  await ownerRow.hover();
  await ownerRow.getByRole('button', { name: 'Lock', exact: true }).click();
  await expect(memberRow.getByText('📌 Pinned')).toBeVisible();
  await expect(memberRow.getByText('🔒 Locked')).toBeVisible();
  await memberRow.hover();
  await expect(memberRow.getByRole('button', { name: 'Delete', exact: true })).toBeDisabled();
});

// Channel messages are per-device end-to-end encrypted with no history
// backfill, so a member who joins after a message was sent has no key for
// it -- including a pinned rule or announcement. This drives the whole
// reveal/hide flow through the real UI: pinning, revealing (with its
// confirmation dialog), a late joiner reading the revealed copy instead of
// the usual "wasn't there yet" placeholder, and hiding the reveal again.
test('revealing a pinned message lets a member who joins later read it; hiding it reverts that', async ({ browser }) => {
  const owner = await register('pinown');
  const { server } = await createServer(owner);
  const ownerPage = await openAs(browser, owner);
  await openChannel(ownerPage, server.name);
  await sendMessage(ownerPage, 'Server rules: be kind.');

  const ownerRow = messageRow(ownerPage, 'Server rules: be kind.');
  await ownerRow.hover();
  await ownerRow.getByRole('button', { name: 'Pin', exact: true }).click();
  await ownerRow.hover();
  await ownerRow.getByRole('button', { name: 'Reveal', exact: true }).click();
  await ownerPage.getByRole('button', { name: /Reveal it/ }).click();
  await expect(ownerRow.getByText('Revealed by a moderator')).toBeVisible();

  // Joins the server only now -- after the message was sent and pinned --
  // so this device never received a `message_recipients` entry for it.
  const lateJoiner = await register('pinlate');
  await join(owner, server.id, lateJoiner);
  const latePage = await openAs(browser, lateJoiner);
  await openChannel(latePage, server.name);

  // Found by the sender's name, not the message content -- the content
  // itself is exactly what's about to change below.
  const lateRow = messageRow(latePage, owner.user.username);
  await expect(lateRow).toContainText('Server rules: be kind.');
  await expect(lateRow.getByText('Revealed by a moderator')).toBeVisible();
  // No "Reveal"/"Unreveal" toggle for a plain member -- only a moderator sees it.
  await lateRow.hover();
  await expect(lateRow.getByRole('button', { name: 'Unreveal', exact: true })).toHaveCount(0);

  // Unrevealing it reverts the late joiner to the usual placeholder, live
  // over the websocket -- no reload needed.
  await ownerRow.hover();
  await ownerRow.getByRole('button', { name: 'Unreveal', exact: true }).click();
  await expect(lateRow).toContainText("Sent before this device was added");
  await expect(lateRow.getByText('Revealed by a moderator')).toHaveCount(0);

  expect(pageErrors(ownerPage)).toEqual([]);
  expect(pageErrors(latePage)).toEqual([]);
});

test('older messages load when scrolling up, keeping your place', async ({ browser }) => {
  const owner = await register('hist');
  const { server, channel } = await createServer(owner);
  await sql(
    `INSERT INTO messages (channel_id, user_id, content, created_at)
     SELECT $1, $2, 'history ' || i, now() - interval '1 hour' + i * interval '1 second' FROM generate_series(1, 120) i`,
    [channel.id, owner.user.id],
  );
  const page = await openAs(browser, owner);
  await openChannel(page, server.name);
  const shown = page.locator('.messages-container').getByText(/^history \d+$/);
  await expect(page.getByText('history 120', { exact: true })).toBeVisible();
  await expect(shown).toHaveCount(50);

  const box = page.locator('.messages-container');
  await expect.poll(() => box.evaluate((el) => el.scrollTop)).toBeGreaterThan(0); // jumped to the newest
  await box.evaluate((el) => el.scrollTo(0, 0));
  await expect(shown).toHaveCount(100);
  await expect(page.getByText('history 71', { exact: true })).toBeInViewport(); // place kept

  // A new message arriving while reading history doesn't pull the view down.
  await postMessage(owner, channel.id, 'brand new message');
  await expect(page.getByText('brand new message')).toBeAttached();
  await page.waitForTimeout(400);
  await expect(page.getByText('history 71', { exact: true })).toBeInViewport();
  await box.evaluate((el) => el.scrollTo(0, 0));
  await expect(shown).toHaveCount(120);
  await expect(page.getByText('This is the beginning of the channel')).toBeVisible();
});
