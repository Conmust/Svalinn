import { test, expect, type Browser, type Page } from '@playwright/test';
import path from 'node:path';
import os from 'node:os';
import fs from 'node:fs';
import zlib from 'node:zlib';
import { call, createServer, join, register, sql, type User } from '../../support/api';
import { openAs, pageErrors, openChannel } from '../../support/ui';

// Adversarial / stress coverage for the ratchet-first attachment-key-wrap
// feature (migration 0044, `wrapAttachmentKeyForDevice` in both chat
// components) and the stale-device-list retry fix that shipped alongside
// it. Independent of `chat.spec.ts`'s one happy-path attachment test --
// this targets exactly the race class and the single-use-key subtlety
// that motivated those two changes, to see if they actually hold up.

const DECRYPT_FAILED_PLACEHOLDER = '[Unable to decrypt this message]';

/** A small valid PNG, written to a temp file for the file picker. Each
 * call makes a uniquely-named file so parallel/sequential sends in one
 * test don't collide on the same path (and so assertions on the filename
 * can tell attachments apart). */
function pngFile(tag: string): string {
  const chunk = (type: string, data: Buffer) => {
    const len = Buffer.alloc(4); len.writeUInt32BE(data.length);
    const crc = Buffer.alloc(4); crc.writeUInt32BE(zlib.crc32(Buffer.concat([Buffer.from(type), data])) >>> 0);
    return Buffer.concat([len, Buffer.from(type), data, crc]);
  };
  const ihdr = Buffer.alloc(13); ihdr.writeUInt32BE(8, 0); ihdr.writeUInt32BE(8, 4); ihdr[8] = 8; ihdr[9] = 2;
  const raw = Buffer.concat(Array.from({ length: 8 }, () => Buffer.concat([Buffer.from([0]), Buffer.alloc(24, 0x80)])));
  const file = path.join(os.tmpdir(), `e2e-stress-${process.pid}-${tag}-green.png`);
  fs.writeFileSync(file, Buffer.concat([Buffer.from('89504e470d0a1a0a', 'hex'), chunk('IHDR', ihdr), chunk('IDAT', zlib.deflateSync(raw)), chunk('IEND', Buffer.alloc(0))]));
  return file;
}

async function deviceCount(userId: string): Promise<number> {
  const rows = await sql<{ count: string }>('SELECT COUNT(*) FROM device_keys WHERE user_id = $1', [userId]);
  return Number(rows[0].count);
}

async function waitForDeviceCount(userId: string, expected: number, timeoutMs = 15_000) {
  const start = Date.now();
  for (;;) {
    if ((await deviceCount(userId)) >= expected) return;
    if (Date.now() - start > timeoutMs) throw new Error(`user ${userId} never reached ${expected} registered devices`);
    await new Promise((r) => setTimeout(r, 100));
  }
}

async function openDmPair(browser: Browser): Promise<{ a: User; b: User; aPage: Page; bPage: Page }> {
  const a = await register('ksa');
  const b = await register('ksb');
  const created = await call(a, 'POST', '/conversations', { participant_id: b.user.id });
  if (created.status !== 200) throw new Error(`failed to create conversation: ${created.status} ${JSON.stringify(created.body)}`);

  const aPage = await openAs(browser, a);
  const bPage = await openAs(browser, b);
  await Promise.all([waitForDeviceCount(a.user.id, 1), waitForDeviceCount(b.user.id, 1)]);

  for (const page of [aPage, bPage]) await page.getByTitle('Direct Messages').click();
  await aPage.getByText(b.user.username, { exact: false }).first().click();
  await bPage.getByText(a.user.username, { exact: false }).first().click();
  await expect(aPage.getByPlaceholder('Type a message...')).toBeEnabled({ timeout: 15_000 });
  await expect(bPage.getByPlaceholder('Type a message...')).toBeEnabled({ timeout: 15_000 });

  return { a, b, aPage, bPage };
}

test.describe('ratchet attachment-key-wrap stress tests', () => {
  // Directly reproduces the race that caused the flaky CI failure this
  // feature's own PR surfaced (see `isStaleDeviceListError`'s fix): a new
  // device for the OTHER participant registers in the gap between loading
  // `participantDevices` and the attachment send's fan-out actually
  // completing, so the server rejects the send as missing coverage for
  // the brand new device. Before the fix this fell straight to the
  // generic "Network error" alert with the attachment never sent; after
  // it, the client should silently reload the device list and resend.
  test('a device registers mid-flight during an attachment send (DM): the send recovers via the stale-device-list retry, not a hard failure', async ({ browser }) => {
    const { a, b, aPage, bPage } = await openDmPair(browser);

    // Hold up A's fan-out POST just long enough for B to finish
    // registering a second device in the meantime.
    let released: () => void;
    const gate = new Promise<void>((r) => (released = r));
    await aPage.route('**/api/v1/conversations/*/messages', async (route) => {
      if (route.request().method() === 'POST') await gate;
      await route.continue();
    });

    await aPage.locator('input[type=file]').setInputFiles(pngFile('dm-race'));
    await aPage.getByPlaceholder('Type a message...').fill('racing attachment');
    const sendClick = aPage.getByRole('button', { name: 'Send' }).click();

    // While A's send sits parked at the network gate, register B's
    // second device ("phone") for real.
    const bPhone = await openAs(browser, b);
    await bPhone.getByTitle('Direct Messages').click();
    await bPhone.getByText(a.user.username, { exact: false }).first().click();
    await expect(bPhone.getByPlaceholder('Type a message...')).toBeEnabled({ timeout: 15_000 });
    await waitForDeviceCount(b.user.id, 2);

    // Now let A's held request through. It will be rejected (missing
    // coverage for B's new device) -- the retry path must catch it.
    released!();
    await sendClick;

    // The attachment must have actually gone through on retry: visible
    // (decrypted, `blob:` src) on A's own page, on B's original page, AND
    // on B's new phone (which only exists because of the race, so it has
    // no stale participantDevices of its own to worry about).
    for (const page of [aPage, bPage, bPhone]) {
      const img = page.locator('img[alt$="green.png"]');
      await expect(img).toBeVisible({ timeout: 15_000 });
      await expect.poll(() => img.evaluate((i: HTMLImageElement) => i.naturalWidth)).toBeGreaterThan(0);
    }
    await expect(aPage.getByText('racing attachment', { exact: true })).toBeVisible();
    await expect(aPage.getByText(DECRYPT_FAILED_PLACEHOLDER)).toHaveCount(0);
    await expect(bPhone.getByText(DECRYPT_FAILED_PLACEHOLDER)).toHaveCount(0);

    expect(pageErrors(aPage), 'no uncaught page error / stray alert on the sender').toEqual([]);
    expect(pageErrors(bPhone)).toEqual([]);
  });

  // Same race, but in a channel (ChatArea.svelte's independent copy of
  // the same retry logic/fix) and with a THIRD member joining mid-flight
  // instead of a second device -- the other half of what
  // `isStaleDeviceListError`'s fix needed to cover ("missing" a whole new
  // member's device, not just a new device of an existing member).
  test('a new member joins mid-flight during a channel attachment send: the send recovers via the stale-device-list retry', async ({ browser }) => {
    const owner = await register('ksco');
    const early = await register('ksce');
    const late = await register('kscl');
    const { server } = await createServer(owner);
    await join(owner, server.id, early);

    const ownerPage = await openAs(browser, owner);
    const earlyPage = await openAs(browser, early);
    await openChannel(ownerPage, server.name);
    await openChannel(earlyPage, server.name);
    await ownerPage.waitForTimeout(500);

    let released: () => void;
    const gate = new Promise<void>((r) => (released = r));
    await ownerPage.route('**/api/v1/channels/*/messages', async (route) => {
      if (route.request().method() === 'POST') await gate;
      await route.continue();
    });

    await ownerPage.locator('input[type=file]').setInputFiles(pngFile('channel-race'));
    await ownerPage.getByPlaceholder('Type a message...').fill('late joiner race');
    const sendClick = ownerPage.getByRole('button', { name: 'Send' }).click();

    // While the owner's send is parked, a brand new member joins and
    // opens the channel (registering their device) for real.
    await join(owner, server.id, late);
    const latePage = await openAs(browser, late);
    await openChannel(latePage, server.name);
    await expect(latePage.getByPlaceholder('Type a message...')).toBeEnabled({ timeout: 15_000 });
    await waitForDeviceCount(late.user.id, 1);

    released!();
    await sendClick;

    for (const page of [ownerPage, earlyPage, latePage]) {
      const img = page.locator('img[alt$="green.png"]');
      await expect(img).toBeVisible({ timeout: 15_000 });
      await expect.poll(() => img.evaluate((i: HTMLImageElement) => i.naturalWidth)).toBeGreaterThan(0);
    }
    expect(pageErrors(ownerPage)).toEqual([]);
    expect(pageErrors(latePage)).toEqual([]);
  });

  // The subtlety the design explicitly called out: ratchet message keys
  // are single-use and deleted the instant they're consumed, so a SECOND
  // decrypt of the same attachment key (re-viewing it) must come from the
  // local cache, never a second ratchet-decrypt attempt -- which would
  // fail outright since that key no longer exists. Forces this by
  // reloading the page (clearing in-memory `attachmentState`, but not
  // IndexedDB) and re-opening the same channel, which re-triggers
  // `ensureAttachmentDecrypted` for a message it's never seen in THIS
  // page instance before.
  test('viewing a ratchet-wrapped attachment twice (including across a full page reload) does not fail the second time', async ({ browser }) => {
    const owner = await register('ksvo');
    const member = await register('ksvm');
    const { server } = await createServer(owner);
    await join(owner, server.id, member);

    const ownerPage = await openAs(browser, owner);
    const memberPage = await openAs(browser, member);
    await openChannel(ownerPage, server.name);
    await openChannel(memberPage, server.name);
    await ownerPage.waitForTimeout(500);

    await ownerPage.locator('input[type=file]').setInputFiles(pngFile('review'));
    await ownerPage.getByPlaceholder('Type a message...').fill('view me twice');
    await ownerPage.getByRole('button', { name: 'Send' }).click();

    const memberImg = memberPage.locator('img[alt$="green.png"]');
    await expect(memberImg).toBeVisible({ timeout: 15_000 });
    await expect.poll(() => memberImg.evaluate((i: HTMLImageElement) => i.naturalWidth)).toBeGreaterThan(0);

    // First reload: IndexedDB cache should short-circuit a second ratchet
    // decrypt of the now-consumed message key.
    await memberPage.reload();
    await memberPage.getByTitle(server.name, { exact: true }).click();
    await memberPage.getByText('# general', { exact: true }).click();
    const memberImgAfterReload = memberPage.locator('img[alt$="green.png"]');
    await expect(memberImgAfterReload).toBeVisible({ timeout: 15_000 });
    await expect.poll(() => memberImgAfterReload.evaluate((i: HTMLImageElement) => i.naturalWidth)).toBeGreaterThan(0);
    expect(await memberImgAfterReload.getAttribute('src')).toContain('blob:');
    await expect(memberPage.getByText(DECRYPT_FAILED_PLACEHOLDER)).toHaveCount(0);

    // Second reload, for good measure -- the cache path must be stable,
    // not a one-shot fluke.
    await memberPage.reload();
    await memberPage.getByTitle(server.name, { exact: true }).click();
    await memberPage.getByText('# general', { exact: true }).click();
    const memberImgAfterReload2 = memberPage.locator('img[alt$="green.png"]');
    await expect(memberImgAfterReload2).toBeVisible({ timeout: 15_000 });
    await expect(memberPage.getByText(DECRYPT_FAILED_PLACEHOLDER)).toHaveCount(0);

    expect(pageErrors(memberPage)).toEqual([]);
  });

  // Mixed-recipient fan-out: the sender's own device (always static,
  // never ratcheted -- by design), plus a peer device that HAS done a
  // ratchet handshake (gets the new ratchet-wrapped key), sent in the
  // same single attachment message. Confirms the per-recipient
  // discriminator (`attachment_key_ratchet_header_json` present or not)
  // is read correctly for both rows of the SAME message, not just
  // whichever one happens to be checked first.
  test('one send with mixed ratchet/static recipients: both the ratcheted peer and the static sender decrypt their own copy correctly', async ({ browser }) => {
    const { aPage, bPage } = await openDmPair(browser);

    // Exchange one text message first so a ratchet session is firmly
    // established between A and B's devices before the attachment goes
    // out (A's own device copy of the row is always static regardless).
    await aPage.getByPlaceholder('Type a message...').fill('warm up the ratchet');
    await aPage.getByRole('button', { name: 'Send' }).click();
    await expect(bPage.getByText('warm up the ratchet', { exact: true })).toBeVisible({ timeout: 10_000 });

    await aPage.locator('input[type=file]').setInputFiles(pngFile('mixed'));
    await aPage.getByPlaceholder('Type a message...').fill('mixed recipients');
    await aPage.getByRole('button', { name: 'Send' }).click();

    for (const page of [aPage, bPage]) {
      const img = page.locator('img[alt$="green.png"]');
      await expect(img).toBeVisible({ timeout: 15_000 });
      await expect.poll(() => img.evaluate((i: HTMLImageElement) => i.naturalWidth)).toBeGreaterThan(0);
    }
    expect(pageErrors(aPage)).toEqual([]);
    expect(pageErrors(bPage)).toEqual([]);
  });
});
