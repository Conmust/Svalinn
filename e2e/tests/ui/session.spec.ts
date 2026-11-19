import { test, expect } from '@playwright/test';
import { admin, createServer, join, register, uniq } from '../../support/api';
import { API_URL } from '../../support/config';
import { openAs, openChannel, pageErrors, sendMessage, trackErrors } from '../../support/ui';

test('register from the login screen, with server address checks', async ({ page }) => {
  trackErrors(page);
  await page.goto('/');
  await expect(page.getByText(`Server: ${API_URL}`)).toBeVisible();

  await page.getByRole('button', { name: 'change' }).click();
  await page.locator('#auth-server').evaluate((el: HTMLInputElement) => (el.type = 'text')); // let the app's own check run
  await page.locator('#auth-server').fill('not a url');
  await page.getByLabel('Email').fill('x@example.test');
  await page.getByLabel('Password').fill('whatever');
  await page.getByRole('button', { name: 'Login' }).click();
  await expect(page.getByText('Enter a full address')).toBeVisible();

  await page.locator('#auth-server').fill(`${API_URL}/some/path`);
  await page.getByText("Don't have an account? Register").click();
  const name = uniq('newbie');
  await page.getByLabel('Username').fill(name);
  await page.getByLabel('Email').fill(`${name}@example.test`);
  await page.getByLabel('Password').fill('secret123');
  await page.getByRole('button', { name: 'Register' }).click();
  await expect(page.getByText('Select a conversation to start chatting')).toBeVisible();
  expect(await page.evaluate(() => localStorage.getItem('refresh_token'))).toMatch(/^[0-9a-f]{64}$/);
});

test('an expired access token is refreshed without the user noticing', async ({ browser }) => {
  const owner = await register('tok');
  const { server } = await createServer(owner);
  const page = await openAs(browser, owner);
  await openChannel(page, server.name);
  const refreshBefore = await page.evaluate(() => localStorage.getItem('refresh_token'));

  // Replace the access token with one that expired a minute ago.
  await page.evaluate(() => {
    const b64 = (o: object) => btoa(JSON.stringify(o)).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
    localStorage.setItem('token', `${b64({ alg: 'HS256' })}.${b64({ exp: Math.floor(Date.now() / 1000) - 60 })}.x`);
  });
  await sendMessage(page, 'sent after expiry');
  await expect(page.getByText('sent after expiry')).toBeVisible();
  expect(await page.evaluate(() => localStorage.getItem('refresh_token'))).not.toBe(refreshBefore);
  expect(pageErrors(page)).toEqual([]);
});

test('a ban sends the user to the login screen with the reason', async ({ browser }) => {
  const u = await register('banme');
  const { server } = await createServer(u);
  const page = await openAs(browser, u);
  await openChannel(page, server.name);

  admin('ban', u.user.username, 'harassment');
  await expect(page.getByText('This account has been banned: harassment')).toBeVisible();
  expect(await page.evaluate(() => localStorage.getItem('refresh_token'))).toBeNull();

  await page.getByLabel('Email').fill(u.email);
  await page.getByLabel('Password').fill(u.password);
  await page.getByRole('button', { name: 'Login' }).click();
  await expect(page.getByText('This account has been banned: harassment')).toBeVisible();
  admin('unban', u.user.username);
});

test('account settings: change email and password', async ({ browser }) => {
  const u = await register('acct');
  const page = await openAs(browser, u);
  await page.getByTitle('Account settings').click();
  await expect(page.getByText(u.email)).toBeVisible();

  await page.getByLabel('New email').fill(`new.${u.email}`);
  await page.locator('#account-email-password').fill('wrong');
  await page.getByRole('button', { name: 'Change email' }).click();
  await expect(page.getByText('Your current password is incorrect')).toBeVisible();
  await page.locator('#account-email-password').fill(u.password);
  await page.getByRole('button', { name: 'Change email' }).click();
  await expect(page.getByText('Email updated')).toBeVisible();

  // Uses PUT: this caught a CORS policy that didn't allow it.
  await page.locator('#account-current-password').fill(u.password);
  await page.getByLabel('New password', { exact: true }).fill('better-pass-1');
  await page.getByLabel('Confirm new password').fill('better-pass-2');
  await page.getByRole('button', { name: 'Change password' }).click();
  await expect(page.getByText("The new passwords don't match")).toBeVisible();
  await page.getByLabel('Confirm new password').fill('better-pass-1');
  await page.getByRole('button', { name: 'Change password' }).click();
  await expect(page.getByText('Password changed')).toBeVisible();
  expect(pageErrors(page)).toEqual([]);
});

test('the member list shows people coming online live', async ({ browser }) => {
  const owner = await register('own');
  const member = await register('mem');
  const { server } = await createServer(owner);
  await join(owner, server.id, member);
  const page = await openAs(browser, owner);
  await openChannel(page, server.name);
  await page.getByRole('button', { name: 'Members' }).click();
  const roster = page.locator('aside').last();
  await expect(roster).toContainText(/Offline — 1/i);

  const memberPage = await openAs(browser, member);
  await expect(roster).toContainText(/Online — 2/i);
  await memberPage.context().close();
  await expect(roster).toContainText(/Offline — 1/i);
});
