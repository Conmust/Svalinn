import { test, expect } from '@playwright/test';
import { call, createServer, post, randomIp, register, sql, uniq, type User } from '../../support/api';
import { openAs, pageErrors } from '../../support/ui';

/**
 * Registers a user WITHOUT the SQL escape hatch `support/api.ts`'s own
 * `register()` uses to mark every test user pre-verified -- this is the
 * one test in the suite that actually exercises the verification gate
 * itself (resend link, the account-settings UI, and `accept_invite`'s
 * enforcement), rather than everything that merely sits behind it.
 */
async function registerUnverified(prefix: string): Promise<User> {
  const username = uniq(prefix);
  const email = `${username}@example.test`;
  const password = 'secret123';
  const ip = randomIp();
  const res = await post<any>('/auth/register', { username, email, password }, ip);
  if (res.status !== 200) throw new Error(`register failed: ${res.status} ${JSON.stringify(res.body)}`);
  return { ...res.body, email, password, ip };
}

// End-to-end coverage for the gap this feature closes: previously, an
// account whose verification link never arrived or expired (there's no
// real email provider wired up yet -- see `routes::auth::send_verification_email`)
// had no way back in, since `accept_invite` requires a verified email.
test('an unverified account is blocked from joining, can resend from account settings, then joins', async ({ browser }) => {
  const owner = await register('verifowner');
  const { server } = await createServer(owner);
  const invite = (await call(owner, 'POST', `/servers/${server.id}/invites`, {})).body;

  const member = await registerUnverified('verifmem');
  const page = await openAs(browser, member);

  // Trying to join while unverified surfaces the server's own message, plus
  // a shortcut straight to where it can be fixed.
  await page.getByTitle('Create or join a server').click();
  await page.getByRole('tab', { name: 'Join' }).click();
  await page.getByLabel('Invite code or link').fill(invite.code);
  await page.getByRole('button', { name: 'Look up' }).click();
  await expect(page.getByText(server.name)).toBeVisible(); // the preview itself doesn't check verification
  await page.getByRole('button', { name: 'Join', exact: true }).click();
  await expect(page.getByText('Verify your email before joining servers', { exact: false })).toBeVisible();

  await page.getByRole('button', { name: 'Go to account settings to resend it' }).click();
  await expect(page.getByText('Email not verified')).toBeVisible();

  await page.getByRole('button', { name: 'Resend verification email' }).click();
  // The suite runs the server with APP_ENV=test (see `support/config.ts`),
  // not `development`, so `dev_verification_link` is deliberately absent
  // here too (same as real production) -- the resend genuinely has nowhere
  // to go without a real email provider wired up, so this is the honest
  // "check your inbox" message, not the dev auto-verify convenience.
  await expect(page.getByText('Verification email sent. Check your inbox.')).toBeVisible();

  // No real inbox to click a link from, so simulate it the same way
  // `register()`'s own test helper does -- this test's job is the gate and
  // the resend endpoint, not standing up a real mail transport.
  await sql('UPDATE users SET email_verified_at = NOW() WHERE id = $1', [member.user.id]);

  await page.getByLabel('Close account settings').click();
  await page.getByTitle('Account settings').click();
  await expect(page.getByText('Email not verified')).toHaveCount(0);
  await page.getByLabel('Close account settings').click();

  await page.getByTitle('Create or join a server').click();
  await page.getByRole('tab', { name: 'Join' }).click();
  await page.getByLabel('Invite code or link').fill(invite.code);
  await page.getByRole('button', { name: 'Look up' }).click();
  await expect(page.getByText(server.name)).toBeVisible();
  await page.getByRole('button', { name: 'Join', exact: true }).click();
  await expect(page.getByTitle(server.name, { exact: true })).toBeVisible();

  expect(pageErrors(page)).toEqual([]);
});
