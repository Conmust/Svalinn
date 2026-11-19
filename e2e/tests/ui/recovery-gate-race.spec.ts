import { test, expect } from '@playwright/test';
import { call, register, sql, type User } from '../../support/api';

/**
 * Regression test for the fix to the race between `App.svelte`'s
 * `setupDeviceEncryption()` (now `deviceEncryptionReady()` in
 * `lib/recovery.ts`) and `DMChatArea.svelte` opening a conversation before
 * that check resolves.
 *
 * Before the fix, `DMChatArea.svelte` called `ensureDeviceKeypair()`
 * directly at component init, completely bypassing the recovery-backup
 * check. Opening a DM while that check (a network call,
 * `GET /users/me/key-backup`) was still in flight -- e.g. right after
 * login -- let `DMChatArea` race ahead and generate+register a brand new
 * throwaway device key before the user was ever asked whether they wanted
 * to recover their real backed-up key. Once that happened,
 * `hasLocalKeypair()` became true, so the recovery choice could never be
 * offered again on that device.
 *
 * The fix makes `deviceEncryptionReady()` (in `lib/recovery.ts`) the ONE
 * path to this device's first-ever keypair; every consumer (`App.svelte`,
 * `DMChatArea.svelte`, `AccountSettings.svelte`) awaits the exact same
 * promise, so a DM opened mid-check waits on that same check instead of
 * racing ahead.
 */

async function deviceCount(userId: string): Promise<number> {
  const rows = await sql<{ count: string }>('SELECT COUNT(*) FROM device_keys WHERE user_id = $1', [userId]);
  return Number(rows[0].count);
}

/** Seeds an account-level recovery backup directly via the API -- all that
 * matters for this test is that the ACCOUNT has a backup (so a brand new
 * device logging in is supposed to be asked to choose), not that the blob
 * is a real decryptable one. The test only ever exercises the "start
 * fresh" path, never "recover", so the blob's content is irrelevant. */
async function seedKeyBackup(user: User) {
  const res = await call(user, 'PUT', '/users/me/key-backup', {
    encrypted_blob: 'deadbeef'.repeat(8),
    salt: 'c2FsdC1iYXNlNjQtZW5jb2RlZA==',
    kdf_params: { algorithm: 'argon2id13', opslimit: 3, memlimit: 268435456, version: 1 },
  });
  if (res.status !== 200) {
    throw new Error(`failed to seed key backup: ${res.status} ${JSON.stringify(res.body)}`);
  }
}

test.describe('recovery-choice gate cannot be bypassed by racing a DM open', () => {
  test('opening a DM immediately after login, before the backup check resolves, still shows the recovery choice and creates no throwaway device', async ({ browser }) => {
    const ATTEMPTS = 10;
    let clean = 0;

    for (let i = 0; i < ATTEMPTS; i++) {
      const a = await register('racea');
      const b = await register('raceb');
      await seedKeyBackup(a);

      const created = await call(a, 'POST', '/conversations', { participant_id: b.user.id });
      if (created.status !== 200) {
        throw new Error(`failed to create conversation: ${created.status} ${JSON.stringify(created.body)}`);
      }

      // Log in as `a` on a brand-new "device" -- a fresh browser context,
      // so `localStorage` starts empty and `hasLocalKeypair()` is false --
      // with the backup-existence check (`GET /users/me/key-backup`)
      // artificially delayed so it's still in flight when the DM is
      // opened, mirroring the original race window right after login.
      const context = await browser.newContext();
      await context.addInitScript((u) => {
        localStorage.setItem('token', u.token);
        localStorage.setItem('refresh_token', u.refresh_token);
        localStorage.setItem('user', JSON.stringify(u.user));
      }, { token: a.token, refresh_token: a.refresh_token, user: a.user });
      const page = await context.newPage();

      await page.route('**/api/v1/users/me/key-backup', async (route) => {
        if (route.request().method() === 'GET') {
          await new Promise((r) => setTimeout(r, 1000));
        }
        await route.continue();
      });

      await page.goto('/');
      await page.getByTitle('Account settings').waitFor();

      // Race ahead: open the DM with `b` as fast as possible, well before
      // the 1s-delayed `GET` resolves.
      await page.getByTitle('Direct Messages').click();
      await page.getByText(b.user.username, { exact: false }).first().click();

      // The unskippable recovery-choice modal must still appear -- it must
      // NOT have been bypassed by `DMChatArea` generating its own
      // throwaway key in the meantime.
      await expect(page.getByText(/This account has a recovery backup set up/)).toBeVisible({ timeout: 5000 });

      // No device should have been registered for this account yet. The
      // bug this guards against burned a device slot on a throwaway key
      // before the modal ever had a chance to show -- so under the bug
      // this would already be 1 by the time the (equally-delayed) modal
      // appears.
      expect(await deviceCount(a.user.id), 'a throwaway device was registered before the recovery choice was made').toBe(0);

      // Resolve the choice ("start fresh", since no real passphrase was
      // set up for this seeded backup) and confirm exactly one device
      // gets registered -- never two.
      // `b` never opened the app in this test, so `b` has no device of
      // their own and sending stays disabled ("Encrypted messaging
      // unavailable") regardless -- that's an unrelated, pre-existing
      // behavior. What matters here is that `a`'s own setup completed with
      // exactly one device.
      await page.getByRole('button', { name: /start fresh/i }).click();
      await expect(page.getByText(/This account has a recovery backup set up/)).toHaveCount(0);
      await expect
        .poll(() => deviceCount(a.user.id), { timeout: 10_000 })
        .toBe(1);

      await context.close();
      clean++;
    }

    expect(clean).toBe(ATTEMPTS);
  });
});
