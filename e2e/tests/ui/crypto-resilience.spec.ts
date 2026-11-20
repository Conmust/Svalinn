import { test, expect, type Page } from '@playwright/test';
import { call, createServer, join, register, sql } from '../../support/api';
import { openChannel, pageErrors } from '../../support/ui';

/**
 * Forcibly breaks this device's E2EE setup for `page`, the same way a
 * broken device-registration call would in production: every
 * `POST /users/me/devices` the page makes is aborted, so
 * `ensureDeviceKeypair()` (see `lib/crypto.ts`) can never succeed and
 * `deviceEncryptionReady()` (see `lib/recovery.ts`) is guaranteed to
 * eventually reject with a `DeviceSetupError`. Registered before the page
 * navigates, so it's in effect from the very first login-triggered setup
 * attempt in `App.svelte`.
 */
async function breakDeviceRegistration(page: Page) {
  await page.route('**/api/v1/users/me/devices', async (route) => {
    if (route.request().method() === 'POST') {
      await route.abort('failed');
      return;
    }
    await route.continue();
  });
}

test.describe('the app stays usable when the E2EE subsystem is broken', () => {
  // Channel messages are now mandatory end-to-end encrypted too (not just
  // DMs), so a broken device-registration setup hard-blocks sending in
  // BOTH the channel panel and the DM panel -- there's no "non-E2EE
  // messaging" fallback left to exercise. What still has to survive is
  // navigation and the rest of the UI around the broken panels: no crash,
  // and both panels degrade to a clear, specific error rather than
  // silently sending plaintext.
  test('both channel and DM panels degrade to a clear error, and sending stays hard-blocked everywhere', async ({ browser }) => {
    const a = await register('cra');
    const b = await register('crb');
    const { server } = await createServer(a);
    await join(a, server.id, b);

    const created = await call(a, 'POST', '/conversations', { participant_id: b.user.id });
    expect(created.status).toBe(200);
    const conversationId = created.body.id as string;

    const context = await browser.newContext();
    await context.addInitScript((u) => {
      if (!sessionStorage.getItem('e2e-seeded')) {
        localStorage.setItem('token', u.token);
        localStorage.setItem('refresh_token', u.refresh_token);
        localStorage.setItem('user', JSON.stringify(u.user));
        sessionStorage.setItem('e2e-seeded', '1');
      }
    }, { token: a.token, refresh_token: a.refresh_token, user: a.user });
    const aPage = await context.newPage();
    const errors: string[] = [];
    aPage.on('pageerror', (e) => errors.push(e.message));
    aPage.on('dialog', (d) => {
      errors.push(`unexpected dialog: ${d.message()}`);
      d.dismiss().catch(() => {});
    });

    // Break this device's E2EE setup BEFORE the app ever loads, so the
    // very first `deviceEncryptionReady()` attempt (kicked off by
    // `App.svelte` right after login) fails and never recovers.
    await breakDeviceRegistration(aPage);

    await aPage.goto('/');
    await aPage.getByTitle('Account settings').waitFor();

    // --- (a) The channel panel shows a clear, specific error -- no crash,
    // and sending there is hard-blocked too -----------------------------
    await openChannel(aPage, server.name);
    const channelPanel = aPage.locator('.messages-container');
    await expect(channelPanel.getByRole('alert')).toBeVisible({ timeout: 20_000 });
    await expect(channelPanel.getByRole('alert')).toContainText('Encrypted messaging is currently unavailable');
    await expect(channelPanel.getByRole('alert')).toContainText(/failed to register this device/i);
    await expect(aPage.getByPlaceholder('Encrypted messaging unavailable')).toBeDisabled();
    await expect(aPage.getByRole('button', { name: 'Send' })).toBeDisabled();

    // Navigating away from and back to a server still works normally --
    // this is a panel-local failure, not a whole-app crash.
    await aPage.getByTitle('Direct Messages').click();
    await openChannel(aPage, server.name);
    await expect(aPage.getByText('# general', { exact: true })).toBeVisible();

    // --- (b) The DM panel shows the same clear, specific error ---------
    await aPage.getByTitle('Direct Messages').click();
    await aPage.getByText(b.user.username, { exact: false }).first().click();

    const dmPanel = aPage.locator('.messages-container');
    await expect(dmPanel.getByRole('alert')).toBeVisible({ timeout: 20_000 });
    await expect(dmPanel.getByRole('alert')).toContainText('Encrypted messaging is currently unavailable');
    // Specific about the actual cause (device registration failing),
    // not a generic catch-all.
    await expect(dmPanel.getByRole('alert')).toContainText(/failed to register this device/i);

    // The rest of the window (server rail, DM list) is still there and
    // usable -- this is a panel-local failure, not a whole-app crash.
    await expect(aPage.getByTitle('Account settings')).toBeVisible();
    await expect(aPage.getByText(b.user.username, { exact: false }).first()).toBeVisible();

    // --- (c) Sending stays hard-blocked, with no silent plaintext send --
    const input = aPage.getByPlaceholder('Encrypted messaging unavailable');
    await expect(input).toBeDisabled();
    const sendButton = aPage.getByRole('button', { name: 'Send' });
    await expect(sendButton).toBeDisabled();

    // No uncaught exception reached the page -- the failure was fully
    // handled in-place.
    expect(errors).toEqual([]);

    // Confirm, server-side, that nothing was ever sent to this
    // conversation -- not even as a fallback plaintext message.
    const rows = await sql('SELECT COUNT(*) AS count FROM messages WHERE conversation_id = $1', [conversationId]);
    expect(Number(rows[0].count)).toBe(0);

    expect(pageErrors(aPage)).toEqual([]);
  });
});
