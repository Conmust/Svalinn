import crypto from 'node:crypto';
import { test, expect } from '@playwright/test';
import { API, login, register, sql, uniq } from '../../support/api';
import { pageErrors } from '../../support/ui';

// The login screen's "Forgot password?" flow. The actual password-reset
// endpoints get their own direct API coverage in tests/api/auth.spec.ts;
// this file covers the two things that need a real browser: the login
// screen's own form, and the standalone reset-password-page actually
// working when visited the way a real email link would be.

test('forgot-password shows the same message whether or not the account exists', async ({ page }) => {
  const u = await register('fpui');

  await page.goto('/');
  await page.getByRole('button', { name: 'Forgot password?' }).click();
  await expect(page.getByText('> Reset your password')).toBeVisible();

  await page.getByLabel('Email').fill(u.email);
  await page.getByRole('button', { name: 'Send reset link' }).click();
  await expect(page.getByText('If an account exists for that email, a password reset link has been sent.')).toBeVisible();

  // Same message again for an email nobody registered -- nothing in the UI
  // distinguishes the two cases, which is the whole point (see
  // `routes::auth::forgot_password`'s doc comment on the server).
  await page.getByLabel('Email').fill(`${uniq('nobody')}@example.test`);
  await page.getByRole('button', { name: 'Send reset link' }).click();
  await expect(page.getByText('If an account exists for that email, a password reset link has been sent.')).toBeVisible();

  // The suite runs the server with APP_ENV=test (see support/config.ts), so
  // there's no dev_reset_link here either -- same as real production, with
  // no real email provider wired up. Nothing dev-only should render.
  await expect(page.getByText('[dev] Open reset link')).toHaveCount(0);

  await page.getByRole('button', { name: 'Back to login' }).click();
  await expect(page.getByText('Access the network')).toBeVisible();

  expect(pageErrors(page)).toEqual([]);
});

test('the emailed reset-password-page actually resets the password, end to end, in a real browser', async ({ page }) => {
  const u = await register('fpreset');

  // No real email provider is wired up (and the suite's APP_ENV=test means
  // even the dev-link convenience is off -- see support/config.ts), so
  // there's no inbox to click a link from. Simulate "the user clicked the
  // emailed link" the same way this suite already does for email
  // verification: insert the token Svalinn would have minted and mailed,
  // using the exact hash it stores server-side (SHA-256 hex of the raw
  // token -- see `routes::auth::hash_token`).
  const token = crypto.randomBytes(32).toString('hex');
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  await sql(
    "INSERT INTO password_reset_tokens (token_hash, user_id, expires_at) VALUES ($1, $2, NOW() + interval '1 hour')",
    [tokenHash, u.user.id],
  );

  // This page is served by the API, not the app -- it's a standalone page
  // so the link works for anyone with a browser, no desktop app required
  // (see `routes::auth::reset_password_page`'s doc comment).
  await page.goto(`${API}/auth/reset-password-page?token=${token}`);
  await expect(page.locator('h1')).toHaveText('Reset your password');

  await page.locator('#p1').fill('a-brand-new-password');
  await page.locator('#p2').fill('a-brand-new-password');
  await page.getByRole('button', { name: 'Reset password' }).click();
  await expect(page.getByText('Password reset. You can close this page and log in with your new password.')).toBeVisible();

  expect((await login(u.email, u.password)).status).toBe(400); // old password
  expect((await login(u.email, 'a-brand-new-password')).status).toBe(200); // new one

  expect(pageErrors(page)).toEqual([]);
});

test('the reset-password-page rejects mismatched passwords before ever calling the server', async ({ page }) => {
  // A syntactically-plausible but unissued token is enough -- this test
  // never gets past the client-side mismatch check to reach the server.
  const token = crypto.randomBytes(32).toString('hex');

  await page.goto(`${API}/auth/reset-password-page?token=${token}`);
  await page.locator('#p1').fill('one-password-here');
  await page.locator('#p2').fill('a-different-password');
  await page.getByRole('button', { name: 'Reset password' }).click();
  await expect(page.getByText('Passwords do not match.')).toBeVisible();

  expect(pageErrors(page)).toEqual([]);
});
