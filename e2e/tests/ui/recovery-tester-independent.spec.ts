import { test, expect, type Browser, type BrowserContext, type Page } from '@playwright/test';
import { call, register, sql, type User } from '../../support/api';

/**
 * Independent final-gate verification of the passphrase key-recovery-backup
 * feature, written fresh by an independent tester rather than re-running
 * the feature authors' own `recovery.spec.ts`. Deliberately varies the
 * scenario: uses a different passphrase/users, and -- unlike the existing
 * suite -- explicitly proves that OLD DM history sent before "losing" a
 * device is actually decryptable after recovery, that the manual
 * "Recover from backup" escape hatch's new sends really use the recovered
 * key server-side, that "Change passphrase" really invalidates the old
 * passphrase, and that "Remove backup" really deletes server-side.
 */

const DECRYPT_FAILED_PLACEHOLDER = '[Unable to decrypt this message]';

interface Device {
  context: BrowserContext;
  page: Page;
  errors: string[];
}

async function openDevice(browser: Browser, user: User): Promise<Device> {
  const context = await browser.newContext();
  await context.addInitScript(
    (u) => {
      localStorage.setItem('token', u.token);
      localStorage.setItem('refresh_token', u.refresh_token);
      localStorage.setItem('user', JSON.stringify(u.user));
    },
    { token: user.token, refresh_token: user.refresh_token, user: user.user }
  );
  const page = await context.newPage();
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(e.message));
  page.on('dialog', (d) => void d.accept());
  await page.goto('/');
  return { context, page, errors };
}

async function waitForLocalKeypair(page: Page): Promise<void> {
  await expect
    .poll(() => page.evaluate(() => localStorage.getItem('svalinn_e2ee_device_id')))
    .not.toBeNull();
}

async function waitForOwnDevice(userId: string, timeoutMs = 15_000) {
  const start = Date.now();
  for (;;) {
    const rows = await sql<{ count: string }>('SELECT COUNT(*) FROM device_keys WHERE user_id = $1', [userId]);
    if (Number(rows[0].count) > 0) return;
    if (Date.now() - start > timeoutMs) throw new Error(`device for user ${userId} never registered`);
    await new Promise((r) => setTimeout(r, 100));
  }
}

test.describe('independent tester: full real recovery cycle with old-history decryption', () => {
  test('backup, lose device, recover, decrypt OLD history, and send/receive NEW messages', async ({ browser }) => {
    const alice = await register('indep_a');
    const bob = await register('indep_b');
    const passphrase = 'xkcd-936-style-four-random-words-9981';

    const created = await call(alice, 'POST', '/conversations', { participant_id: bob.user.id });
    expect(created.status).toBe(200);

    const aliceDev1 = await openDevice(browser, alice);
    const bobDev = await openDevice(browser, bob);
    await aliceDev1.page.getByTitle('Account settings').waitFor();
    await bobDev.page.getByTitle('Account settings').waitFor();
    await waitForLocalKeypair(aliceDev1.page);
    await waitForLocalKeypair(bobDev.page);
    await Promise.all([waitForOwnDevice(alice.user.id), waitForOwnDevice(bob.user.id)]);

    // --- Set up recovery backup on Alice's first device ---
    await aliceDev1.page.getByTitle('Account settings').click();
    await expect(aliceDev1.page.getByText(alice.email)).toBeVisible();
    await aliceDev1.page.getByRole('button', { name: 'Set up a recovery passphrase' }).click();
    await aliceDev1.page.getByLabel('Recovery passphrase').fill(passphrase);
    await aliceDev1.page.getByLabel('Confirm passphrase').fill(passphrase);
    await aliceDev1.page.getByRole('button', { name: 'Save recovery backup' }).click();
    await expect(aliceDev1.page.getByText('Recovery backup saved.')).toBeVisible();
    await aliceDev1.page.keyboard.press('Escape');

    // --- Send a real encrypted DM from Alice's device BEFORE losing it ---
    const oldMessageText = `pre-loss-history-${Date.now()}`;
    for (const page of [aliceDev1.page, bobDev.page]) {
      await page.getByTitle('Direct Messages').click();
    }
    await aliceDev1.page.getByText(bob.user.username, { exact: false }).first().click();
    await bobDev.page.getByText(alice.user.username, { exact: false }).first().click();
    await expect(aliceDev1.page.getByPlaceholder('Type a message...')).toBeEnabled({ timeout: 15_000 });
    await aliceDev1.page.getByPlaceholder('Type a message...').fill(oldMessageText);
    await aliceDev1.page.getByRole('button', { name: 'Send' }).click();
    await expect(aliceDev1.page.getByText(oldMessageText, { exact: true })).toBeVisible();
    await expect(bobDev.page.getByText(oldMessageText, { exact: true })).toBeVisible();

    const beforeDeviceRows = await sql<{ id: string; public_key: string }>(
      'SELECT id, public_key FROM device_keys WHERE user_id = $1',
      [alice.user.id]
    );
    expect(beforeDeviceRows).toHaveLength(1);

    // --- Simulate total device loss: close Alice's device 1 entirely ---
    await aliceDev1.context.close();

    // --- Fresh browser context, same account: RecoveryChoice should appear ---
    const aliceDev2 = await openDevice(browser, alice);
    await expect(aliceDev2.page.getByText(/This account has a recovery backup set up/)).toBeVisible();
    await aliceDev2.page.getByRole('button', { name: 'I have my recovery passphrase' }).click();

    // Wrong passphrase: clean error, no crash, choice still available.
    await aliceDev2.page.getByLabel('Recovery passphrase').fill('definitely the wrong words');
    await aliceDev2.page.getByRole('button', { name: 'Recover my key' }).click();
    await expect(aliceDev2.page.getByText(/Incorrect passphrase/)).toBeVisible();
    expect(aliceDev2.errors, 'a wrong passphrase must not throw an uncaught error').toEqual([]);

    // Correct passphrase.
    await aliceDev2.page.getByLabel('Recovery passphrase').fill(passphrase);
    await aliceDev2.page.getByRole('button', { name: 'Recover my key' }).click();
    await aliceDev2.page.getByTitle('Account settings').waitFor();
    await waitForLocalKeypair(aliceDev2.page);
    expect(aliceDev2.errors, 'recovering with the right passphrase must not throw').toEqual([]);

    const afterDeviceRows = await sql<{ id: string; public_key: string }>(
      'SELECT id, public_key FROM device_keys WHERE user_id = $1',
      [alice.user.id]
    );
    expect(afterDeviceRows).toHaveLength(1);
    expect(afterDeviceRows[0].id).toBe(beforeDeviceRows[0].id);

    // --- THE actual point of the feature: can the recovered device decrypt
    // the OLD DM sent before the device was "lost"? ---
    await aliceDev2.page.getByTitle('Direct Messages').click();
    await aliceDev2.page.getByText(bob.user.username, { exact: false }).first().click();
    await expect(aliceDev2.page.getByText(oldMessageText, { exact: true })).toBeVisible({ timeout: 15_000 });
    await expect(aliceDev2.page.getByText(DECRYPT_FAILED_PLACEHOLDER)).toHaveCount(0);

    // --- Recovered device can also send/receive NEW messages normally ---
    const newMessageText = `post-recovery-new-${Date.now()}`;
    await expect(aliceDev2.page.getByPlaceholder('Type a message...')).toBeEnabled({ timeout: 15_000 });
    await aliceDev2.page.getByPlaceholder('Type a message...').fill(newMessageText);
    await aliceDev2.page.getByRole('button', { name: 'Send' }).click();
    await expect(aliceDev2.page.getByText(newMessageText, { exact: true })).toBeVisible();
    await expect(bobDev.page.getByText(newMessageText, { exact: true })).toBeVisible({ timeout: 15_000 });

    expect(aliceDev2.errors).toEqual([]);

    await aliceDev2.context.close();
    await bobDev.context.close();
  });

  test('manual "Recover from backup" escape hatch: new sends after recovery use the RECOVERED key server-side', async ({ browser }) => {
    const carol = await register('indep_c');
    const dave = await register('indep_d');
    const passphrase = 'another-wholly-independent-passphrase-77';

    const created = await call(carol, 'POST', '/conversations', { participant_id: dave.user.id });
    expect(created.status).toBe(200);

    // Device A: Carol's original device, backs itself up.
    const a = await openDevice(browser, carol);
    await a.page.getByTitle('Account settings').waitFor();
    await waitForLocalKeypair(a.page);
    const deviceAId = await a.page.evaluate(() => localStorage.getItem('svalinn_e2ee_device_id'));
    const deviceAPublicKey = await a.page.evaluate(() => localStorage.getItem('svalinn_e2ee_public_key'));

    await a.page.getByTitle('Account settings').click();
    await a.page.getByRole('button', { name: 'Set up a recovery passphrase' }).click();
    await a.page.getByLabel('Recovery passphrase').fill(passphrase);
    await a.page.getByLabel('Confirm passphrase').fill(passphrase);
    await a.page.getByRole('button', { name: 'Save recovery backup' }).click();
    await expect(a.page.getByText('Recovery backup saved.')).toBeVisible();
    await a.context.close();

    // Device B: Carol's second device, starts fresh with ITS OWN key
    // (simulating a device that already has a key of its own).
    const b = await openDevice(browser, carol);
    await expect(b.page.getByText(/This account has a recovery backup set up/)).toBeVisible();
    await b.page.getByRole('button', { name: "I don't have it -- start fresh" }).click();
    await b.page.getByTitle('Account settings').waitFor();
    await waitForLocalKeypair(b.page);
    const deviceBId = await b.page.evaluate(() => localStorage.getItem('svalinn_e2ee_device_id'));
    const deviceBPublicKey = await b.page.evaluate(() => localStorage.getItem('svalinn_e2ee_public_key'));
    expect(deviceBId).not.toBe(deviceAId);

    await b.page.getByTitle('Account settings').click();

    // Cancel the manual recover once, via the browser confirm() dialog, and
    // verify nothing changed.
    await b.page.getByRole('button', { name: 'Recover from backup' }).click();
    await b.page.getByLabel('Recovery passphrase').fill(passphrase);
    // Swap the default auto-accept dialog handler for a one-shot dismiss,
    // then restore the default so later confirm()s in this test still work.
    let dialogSeen = false;
    b.page.removeAllListeners('dialog');
    b.page.once('dialog', (d) => {
      dialogSeen = true;
      void d.dismiss();
      b.page.on('dialog', (d2) => void d2.accept());
    });
    await b.page.getByRole('button', { name: 'Recover my key' }).click();
    await expect.poll(() => dialogSeen).toBe(true);
    // Cancelling the confirm() must leave device B's key untouched.
    const stillDeviceBId = await b.page.evaluate(() => localStorage.getItem('svalinn_e2ee_device_id'));
    expect(stillDeviceBId).toBe(deviceBId);
    await expect(b.page.getByText(/Key recovered from backup/)).toHaveCount(0);

    // Now actually confirm it (dialogs auto-accept per openDevice's default
    // handler since the `once` listener above already consumed the dismiss).
    await b.page.getByRole('button', { name: 'Recover my key' }).click();
    await expect(b.page.getByText(/Key recovered from backup/)).toBeVisible();
    expect(b.errors).toEqual([]);

    const recoveredDeviceId = await b.page.evaluate(() => localStorage.getItem('svalinn_e2ee_device_id'));
    const recoveredPublicKey = await b.page.evaluate(() => localStorage.getItem('svalinn_e2ee_public_key'));
    expect(recoveredDeviceId).toBe(deviceAId);
    expect(recoveredPublicKey).toBe(deviceAPublicKey);
    await b.page.keyboard.press('Escape');

    // --- Send a NEW message from the recovered device and confirm,
    // server-side, that message_recipients rows for it use the RECOVERED
    // device's public key, not device B's original one. ---
    const dDev = await openDevice(browser, dave);
    await dDev.page.getByTitle('Account settings').waitFor();
    await waitForLocalKeypair(dDev.page);
    await Promise.all([waitForOwnDevice(carol.user.id), waitForOwnDevice(dave.user.id)]);

    for (const page of [b.page, dDev.page]) {
      await page.getByTitle('Direct Messages').click();
    }
    await b.page.getByText(dave.user.username, { exact: false }).first().click();
    await dDev.page.getByText(carol.user.username, { exact: false }).first().click();
    await expect(b.page.getByPlaceholder('Type a message...')).toBeEnabled({ timeout: 15_000 });

    const sentText = `after-manual-recovery-${Date.now()}`;
    await b.page.getByPlaceholder('Type a message...').fill(sentText);
    await b.page.getByRole('button', { name: 'Send' }).click();
    await expect(b.page.getByText(sentText, { exact: true })).toBeVisible();
    await expect(dDev.page.getByText(sentText, { exact: true })).toBeVisible({ timeout: 15_000 });

    const daveDeviceRows = await sql<{ id: string }>('SELECT id FROM device_keys WHERE user_id = $1', [dave.user.id]);
    expect(daveDeviceRows).toHaveLength(1);
    const rows = await sql<{ sender_public_key: string }>(
      `SELECT mr.sender_public_key FROM message_recipients mr
       JOIN messages m ON m.id = mr.message_id
       WHERE m.content IS NULL AND m.conversation_id = $1 AND mr.device_id = $2
       ORDER BY mr.created_at DESC LIMIT 5`,
      [created.body.id, daveDeviceRows[0].id]
    );
    expect(rows.length).toBeGreaterThan(0);
    // Every fan-out row for this NEW message, addressed to Dave's device,
    // must carry the RECOVERED key's public key (device A's), not device
    // B's original (now-abandoned) one.
    expect(rows.every((r) => r.sender_public_key === deviceAPublicKey)).toBe(true);
    expect(rows.some((r) => r.sender_public_key === deviceBPublicKey)).toBe(false);

    await b.context.close();
    await dDev.context.close();
  });

  test('"Change passphrase" re-encrypts under a NEW passphrase; the OLD one stops working', async ({ browser }) => {
    const erin = await register('indep_e');
    const oldPass = 'the-original-passphrase-111';
    const newPass = 'a-completely-different-passphrase-222';

    const dev1 = await openDevice(browser, erin);
    await dev1.page.getByTitle('Account settings').waitFor();
    await waitForLocalKeypair(dev1.page);

    await dev1.page.getByTitle('Account settings').click();
    await dev1.page.getByRole('button', { name: 'Set up a recovery passphrase' }).click();
    await dev1.page.getByLabel('Recovery passphrase').fill(oldPass);
    await dev1.page.getByLabel('Confirm passphrase').fill(oldPass);
    await dev1.page.getByRole('button', { name: 'Save recovery backup' }).click();
    await expect(dev1.page.getByText('Recovery backup saved.')).toBeVisible();

    // Change the passphrase.
    await dev1.page.getByRole('button', { name: 'Change passphrase' }).click();
    await dev1.page.getByLabel('Recovery passphrase').fill(newPass);
    await dev1.page.getByLabel('Confirm passphrase').fill(newPass);
    await dev1.page.getByRole('button', { name: 'Save recovery backup' }).click();
    await expect(dev1.page.getByText('Recovery backup saved.')).toBeVisible();
    await dev1.context.close();

    // Fresh device: old passphrase must now fail, new one must work.
    const dev2 = await openDevice(browser, erin);
    await expect(dev2.page.getByText(/This account has a recovery backup set up/)).toBeVisible();
    await dev2.page.getByRole('button', { name: 'I have my recovery passphrase' }).click();

    await dev2.page.getByLabel('Recovery passphrase').fill(oldPass);
    await dev2.page.getByRole('button', { name: 'Recover my key' }).click();
    await expect(dev2.page.getByText(/Incorrect passphrase/)).toBeVisible();

    await dev2.page.getByLabel('Recovery passphrase').fill(newPass);
    await dev2.page.getByRole('button', { name: 'Recover my key' }).click();
    await dev2.page.getByTitle('Account settings').waitFor();
    await waitForLocalKeypair(dev2.page);
    expect(dev2.errors).toEqual([]);

    await dev2.context.close();
  });

  test('"Remove backup" deletes server-side; RecoveryChoice no longer appears on a fresh device', async ({ browser }) => {
    const frank = await register('indep_f');
    const passphrase = 'yet-another-passphrase-333';

    const dev1 = await openDevice(browser, frank);
    await dev1.page.getByTitle('Account settings').waitFor();
    await waitForLocalKeypair(dev1.page);

    await dev1.page.getByTitle('Account settings').click();
    await dev1.page.getByRole('button', { name: 'Set up a recovery passphrase' }).click();
    await dev1.page.getByLabel('Recovery passphrase').fill(passphrase);
    await dev1.page.getByLabel('Confirm passphrase').fill(passphrase);
    await dev1.page.getByRole('button', { name: 'Save recovery backup' }).click();
    await expect(dev1.page.getByText('Recovery backup saved.')).toBeVisible();

    // Verify via direct API GET that the backup exists server-side first.
    const beforeRemove = await call(frank, 'GET', '/users/me/key-backup');
    expect(beforeRemove.status).toBe(200);

    const recoverySection = dev1.page.locator('section', { hasText: 'Account recovery' });
    await recoverySection.getByRole('button', { name: 'Remove' }).click();
    await expect(dev1.page.getByText('Recovery backup removed.')).toBeVisible();
    await dev1.context.close();

    // Confirmed server-side via a subsequent GET -- must now be gone.
    const afterRemove = await call(frank, 'GET', '/users/me/key-backup');
    expect(afterRemove.status).toBe(404);

    // Fresh device, same account: RecoveryChoice must NOT appear anymore --
    // it should just generate a fresh key with no prompt, same as an
    // account that never set up a backup.
    const dev2 = await openDevice(browser, frank);
    await expect(dev2.page.getByText(/This account has a recovery backup set up/)).toHaveCount(0);
    await dev2.page.getByTitle('Account settings').waitFor();
    await waitForLocalKeypair(dev2.page);
    expect(dev2.errors).toEqual([]);

    await dev2.context.close();
  });
});
