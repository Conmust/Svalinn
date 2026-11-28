import { test, expect } from '@playwright/test';
import { login } from '../../support/api';
import { newUserPage, pageErrors } from '../../support/ui';
import { totpCode } from '../../support/totp';

// The TOTP endpoints get full API coverage in tests/api/totp.spec.ts; this
// file covers the two things that need a real browser: the Account
// Settings setup/disable UI, and the login screen's 2FA code-entry step.

test('enabling 2FA in Account Settings, then logging back in with a code, then disabling it', async ({ browser }) => {
  const { user, page } = await newUserPage(browser, 'totpui');

  await page.getByTitle('Account settings').click();
  await expect(page.getByText('> Account Settings')).toBeVisible();
  await expect(page.getByText('Two-factor authentication is on.')).toHaveCount(0);

  await page.getByRole('button', { name: 'Enable two-factor authentication' }).click();
  await expect(page.getByText('Scan this with an authenticator app')).toBeVisible();

  // Read the manual-entry secret straight out of the page rather than
  // hard-coding a QR decode -- this is exactly what someone who can't scan
  // the code would type in by hand.
  const secret = (await page.locator('code.select-all').first().textContent())!.trim();

  // Nothing's been verified against this secret yet, so the current step's
  // code (no replay concern yet) confirms it. Note the moment, so the
  // later login step can target the *next* step explicitly rather than
  // guessing from wall-clock time elapsed since.
  const enabledAtSeconds = Math.floor(Date.now() / 1000);
  await page.getByLabel('6-digit code').fill(totpCode(secret, enabledAtSeconds));
  await page.getByRole('button', { name: 'Confirm and enable' }).click();

  await expect(page.getByText("Save these backup codes somewhere safe")).toBeVisible();
  const backupCodes = await page.locator('.grid.grid-cols-2 code.select-all').allTextContents();
  expect(backupCodes).toHaveLength(8);

  await page.getByRole('button', { name: "I've saved these" }).click();
  await expect(page.getByText('Two-factor authentication is on.')).toBeVisible();
  await page.getByLabel('Close account settings').click();

  // Log out and back in: this time the password alone isn't enough.
  // `handleLogout` revokes the session server-side but doesn't itself drop
  // the client's open websocket -- that happens when the server notices
  // and closes the socket, which fires an `endSession()` reload of its own
  // at some later, unpredictable moment (a pre-existing quirk, not a 2FA
  // one). Racing a manual `page.goto` against that reload just trades one
  // race for another (the navigations can collide); giving it a moment to
  // happen on its own first avoids it landing mid-way through the next
  // login attempt instead.
  await page.getByTitle('Logout').click();
  await page.waitForTimeout(2000);
  await expect(page.getByText('Access the network')).toBeVisible();

  await page.getByLabel('Email').fill(user.email);
  await page.getByLabel('Password').fill(user.password);
  await page.getByRole('button', { name: 'Login' }).click();
  await expect(page.getByText('> Two-factor check')).toBeVisible();

  // A wrong code is rejected without leaving the screen.
  await page.getByLabel('Code').fill('000000');
  await page.getByRole('button', { name: 'Verify' }).click();
  await expect(page.getByText('That code is incorrect')).toBeVisible();

  // The step right after the one `enabledAtSeconds` consumed -- guaranteed
  // different from that one (so replay protection doesn't reject it) no
  // matter how little real time the test took to get here, and still well
  // inside the server's +-1-step verification window as long as the whole
  // flow above took under a minute or so.
  await page.getByLabel('Code').fill(totpCode(secret, enabledAtSeconds + 30));
  await page.getByRole('button', { name: 'Verify' }).click();
  await page.getByTitle('Account settings').waitFor();

  // Disabling needs the password.
  await page.getByTitle('Account settings').click();
  await expect(page.getByText('Two-factor authentication is on.')).toBeVisible();
  await page.locator('#account-totp-disable-password').fill(user.password);
  await page.getByRole('button', { name: 'Disable two-factor authentication' }).click();
  await expect(page.getByText('Enable two-factor authentication')).toBeVisible();

  // A plain login works again with no code screen.
  expect((await login(user.email, user.password)).body.requires_2fa).toBeFalsy();

  expect(pageErrors(page)).toEqual([]);
});

test('a backup code also gets past the login-screen 2FA step', async ({ browser }) => {
  const { user, page } = await newUserPage(browser, 'totpbkup');

  await page.getByTitle('Account settings').click();
  await page.getByRole('button', { name: 'Enable two-factor authentication' }).click();
  const secret = (await page.locator('code.select-all').first().textContent())!.trim();
  await page.getByLabel('6-digit code').fill(totpCode(secret));
  await page.getByRole('button', { name: 'Confirm and enable' }).click();
  const backupCode = (await page.locator('.grid.grid-cols-2 code.select-all').first().textContent())!.trim();
  await page.getByRole('button', { name: "I've saved these" }).click();
  await page.getByLabel('Close account settings').click();

  await page.getByTitle('Logout').click();
  await page.waitForTimeout(2000);
  await page.getByLabel('Email').fill(user.email);
  await page.getByLabel('Password').fill(user.password);
  await page.getByRole('button', { name: 'Login' }).click();
  await expect(page.getByText('> Two-factor check')).toBeVisible();

  await page.getByLabel('Code').fill(backupCode);
  await page.getByRole('button', { name: 'Verify' }).click();
  await page.getByTitle('Account settings').waitFor();

  expect(pageErrors(page)).toEqual([]);
});
