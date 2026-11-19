import { test, expect } from '@playwright/test';
import { call, register, sql, type User } from '../../support/api';

/**
 * Regression test for the BLOCKING bug found in this round's security
 * review: `recovery.ts`'s backup-existence check (`needsRecoveryChoice()`,
 * via `fetchKeyBackup()`) now has a network timeout. Before the fix, that
 * timeout was only 10s, but `runDeviceEncryptionSetup()`'s retry loop
 * treated ANY failure of that check -- including a timeout caused by a
 * merely SLOW (not actually broken) connection -- as a transient error,
 * retried it twice more, and then silently fell back to generating a
 * brand-new, unrelated keypair via `ensureDeviceKeypair()` -- WITHOUT ever
 * showing the explicit recover-or-start-fresh `RecoveryChoice.svelte`
 * modal. An account whose check consistently took just over 10s (slow
 * network, loaded server -- not hung) would permanently and silently lose
 * the normal path back to its real backed-up key.
 *
 * This simulates exactly that: the server takes ~13s to respond to
 * `GET /users/me/key-backup` -- longer than the OLD 10s timeout, but well
 * within the new, more generous `BACKUP_EXISTENCE_CHECK_TIMEOUT_MS` (20s)
 * -- and confirms the user still gets the real `RecoveryChoice` modal
 * (an explicit choice), never a silent fresh-key fallback.
 */

async function deviceCount(userId: string): Promise<number> {
  const rows = await sql<{ count: string }>('SELECT COUNT(*) FROM device_keys WHERE user_id = $1', [userId]);
  return Number(rows[0].count);
}

/** Seeds an account-level recovery backup directly via the API -- all that
 * matters for this test is that the ACCOUNT has a backup (so a brand new
 * device logging in is supposed to be asked to choose), not that the blob
 * is a real decryptable one. This test only exercises the "the modal
 * appears at all, despite a slow check" path, never actual decryption. */
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

test.describe('a merely-slow (not broken) backup-existence check still gets an explicit recovery choice', () => {
  test('a ~13s-delayed key-backup check surfaces RecoveryChoice, not a silent fresh-key fallback', async ({ browser }) => {
    const user = await register('slowchk');
    await seedKeyBackup(user);

    // Log in on a brand-new "device" -- a fresh browser context, so
    // `localStorage` starts empty and `hasLocalKeypair()` is false.
    const context = await browser.newContext();
    await context.addInitScript((u) => {
      localStorage.setItem('token', u.token);
      localStorage.setItem('refresh_token', u.refresh_token);
      localStorage.setItem('user', JSON.stringify(u.user));
    }, { token: user.token, refresh_token: user.refresh_token, user: user.user });
    const page = await context.newPage();
    const errors: string[] = [];
    page.on('pageerror', (e) => errors.push(e.message));

    // Delay the key-backup GET by ~13s -- longer than the old 10s timeout
    // (which would have wrongly treated this as a hang), shorter than the
    // new, generous `BACKUP_EXISTENCE_CHECK_TIMEOUT_MS` (20s) -- this
    // request must still succeed, not time out.
    let sawDelayedRequest = false;
    await page.route('**/api/v1/users/me/key-backup', async (route) => {
      if (route.request().method() === 'GET') {
        sawDelayedRequest = true;
        await new Promise((r) => setTimeout(r, 13_000));
      }
      await route.continue();
    });

    await page.goto('/');
    await page.getByTitle('Account settings').waitFor();

    // The explicit recovery-choice modal must appear -- NOT get silently
    // bypassed by a throwaway fresh key generated while the (slow, but
    // working) check was still thought of as "failed".
    await expect(page.getByText(/This account has a recovery backup set up/)).toBeVisible({ timeout: 20_000 });
    expect(sawDelayedRequest).toBe(true);

    // Critically: no device should have been silently registered for this
    // account before the modal appeared -- that's exactly what the old,
    // silent `ensureDeviceKeypair()` fallback would have done.
    expect(
      await deviceCount(user.user.id),
      'a throwaway device was registered instead of showing the recovery choice'
    ).toBe(0);

    // Resolving the choice (start fresh, since this seeded blob isn't a
    // real decryptable backup) still works normally afterward.
    await page.getByRole('button', { name: /start fresh/i }).click();
    await expect(page.getByText(/This account has a recovery backup set up/)).toHaveCount(0);
    await expect.poll(() => deviceCount(user.user.id), { timeout: 10_000 }).toBe(1);

    expect(errors).toEqual([]);
    await context.close();
  });
});
