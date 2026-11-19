import { test, expect, type Browser, type BrowserContext, type Page } from '@playwright/test';
import { register, sql, type User } from '../../support/api';

/**
 * Real, through-the-UI exercise of the passphrase key-recovery-backup
 * feature -- registering, actually clicking "Save recovery backup" with a
 * real passphrase, actually clicking "Recover my key" with it on a
 * simulated new device, etc.
 *
 * This is the test that was missing and let a critical bug ship: the only
 * prior recovery test (`recovery-gate-race.spec.ts`) seeded the backup
 * directly via the API with a synthetic blob and only ever exercised the
 * "start fresh" path. No test ever drove the real encrypt/decrypt path
 * through the browser, so `recovery.ts` calling `sodium.crypto_pwhash` --
 * a function that doesn't exist in the `libsodium-wrappers` MINIMAL build
 * this app depended on -- went completely unnoticed: every real "Save
 * recovery backup" click threw immediately.
 */

interface Device {
  context: BrowserContext;
  page: Page;
  errors: string[];
}

/** Opens a fresh browser context already logged in as `user` (tokens seeded
 * into localStorage, same as `support/ui.ts`'s `openAs`), but WITHOUT that
 * helper's dialog-dismissing error tracking -- this feature's UI relies on
 * real `confirm()` dialogs (passphrase-loss warnings), so dialogs here are
 * accepted instead of treated as test failures. */
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

/** Waits until this device has settled on a local keypair -- either
 * generated automatically (no backup exists) or via the recovery-choice
 * modal -- so DB/localStorage assertions don't race the async device setup
 * that runs after the "Account settings" title first becomes clickable. */
async function waitForLocalKeypair(page: Page): Promise<void> {
  await expect
    .poll(() => page.evaluate(() => localStorage.getItem('svalinn_e2ee_device_id')))
    .not.toBeNull();
}

async function deviceRows(userId: string) {
  return sql<{ id: string; public_key: string }>('SELECT id, public_key FROM device_keys WHERE user_id = $1', [userId]);
}

test.describe('passphrase key-recovery backup, exercised through the real UI', () => {
  test('save a backup with a real passphrase, lose the device, and recover the same key', async ({ browser }) => {
    const user = await register('recov');
    const passphrase = 'correct horse battery staple 42';

    // Device 1: first-ever login, no backup exists yet, so it just gets its
    // own key automatically (no recovery choice offered).
    const d1 = await openDevice(browser, user);
    await d1.page.getByTitle('Account settings').waitFor();
    await waitForLocalKeypair(d1.page);

    const before = await deviceRows(user.user.id);
    expect(before).toHaveLength(1);

    await d1.page.getByTitle('Account settings').click();
    await expect(d1.page.getByText(user.email)).toBeVisible();
    await d1.page.getByRole('button', { name: 'Set up a recovery passphrase' }).click();
    await d1.page.getByLabel('Recovery passphrase').fill(passphrase);
    await d1.page.getByLabel('Confirm passphrase').fill(passphrase);

    // This is the exact click that was completely broken: before the fix,
    // `deriveKey()` threw synchronously (`crypto_pwhash` didn't exist on the
    // minimal-build `sodium` import), so this button never got past "Saving...".
    await d1.page.getByRole('button', { name: 'Save recovery backup' }).click();
    await expect(d1.page.getByText('Recovery backup saved.')).toBeVisible();
    expect(d1.errors, 'saving a real recovery backup must not throw').toEqual([]);

    await d1.context.close();

    // Device 2: simulate losing device 1 entirely -- a fresh browser
    // context (empty localStorage) logging into the SAME account.
    const d2 = await openDevice(browser, user);
    await expect(d2.page.getByText(/This account has a recovery backup set up/)).toBeVisible();
    await d2.page.getByRole('button', { name: 'I have my recovery passphrase' }).click();

    // Wrong passphrase first: must fail cleanly, not crash, and must not
    // have burned the choice -- retry has to still be possible.
    await d2.page.getByLabel('Recovery passphrase').fill('a passphrase that is definitely wrong');
    await d2.page.getByRole('button', { name: 'Recover my key' }).click();
    await expect(d2.page.getByText(/Incorrect passphrase/)).toBeVisible();

    // Retry with the correct passphrase.
    await d2.page.getByLabel('Recovery passphrase').fill(passphrase);
    await d2.page.getByRole('button', { name: 'Recover my key' }).click();
    await expect(d2.page.getByText(/This account has a recovery backup set up/)).toHaveCount(0);
    await d2.page.getByTitle('Account settings').waitFor();
    await waitForLocalKeypair(d2.page);
    expect(d2.errors, 'recovering with the real passphrase must not throw').toEqual([]);

    // The SAME device_id/keypair was restored -- no second device row.
    const after = await deviceRows(user.user.id);
    expect(after).toHaveLength(1);
    expect(after[0].id).toBe(before[0].id);
    expect(after[0].public_key).toBe(before[0].public_key);

    const localDeviceId = await d2.page.evaluate(() => localStorage.getItem('svalinn_e2ee_device_id'));
    const localPublicKey = await d2.page.evaluate(() => localStorage.getItem('svalinn_e2ee_public_key'));
    expect(localDeviceId).toBe(before[0].id);
    expect(localPublicKey).toBe(before[0].public_key);

    await d2.context.close();
  });

  test('manual "Recover from backup" lets a device with its own key adopt a different backed-up key', async ({ browser }) => {
    const user = await register('recov2');
    const passphrase = 'a second, equally real passphrase';

    // Device A: backs up ITS OWN key under a passphrase.
    const a = await openDevice(browser, user);
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

    // Device B: a different, brand-new device on the SAME account that
    // explicitly chooses to start fresh instead of recovering -- it ends up
    // with its own key, distinct from the one backed up above. This is the
    // scenario Bug 2 described: once this device has ANY local keypair,
    // `needsRecoveryChoice()` can never offer the choice again, even though
    // a real backup still exists server-side.
    const b = await openDevice(browser, user);
    await expect(b.page.getByText(/This account has a recovery backup set up/)).toBeVisible();
    await b.page.getByRole('button', { name: "I don't have it -- start fresh" }).click();
    await b.page.getByTitle('Account settings').waitFor();
    await waitForLocalKeypair(b.page);
    const deviceBId = await b.page.evaluate(() => localStorage.getItem('svalinn_e2ee_device_id'));
    expect(deviceBId).not.toBe(deviceAId);

    // The manual escape hatch: even though device B already has its own
    // key, "Recover from backup" in Account Settings can still pull in
    // device A's backed-up key and replace B's local key with it.
    await b.page.getByTitle('Account settings').click();
    await b.page.getByRole('button', { name: 'Recover from backup' }).click();
    await b.page.getByLabel('Recovery passphrase').fill(passphrase);
    await b.page.getByRole('button', { name: 'Recover my key' }).click();
    await expect(b.page.getByText(/Key recovered from backup/)).toBeVisible();
    expect(b.errors, 'the manual recover-from-backup action must not throw').toEqual([]);

    const recoveredDeviceId = await b.page.evaluate(() => localStorage.getItem('svalinn_e2ee_device_id'));
    const recoveredPublicKey = await b.page.evaluate(() => localStorage.getItem('svalinn_e2ee_public_key'));
    expect(recoveredDeviceId).toBe(deviceAId);
    expect(recoveredPublicKey).toBe(deviceAPublicKey);

    await b.context.close();
  });
});
