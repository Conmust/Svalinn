// Helpers for browser tests.
import type { Browser, Page } from '@playwright/test';
import { register, type User } from './api';

/**
 * Opens the app already logged in as `user`, by putting their tokens in
 * storage first. Most tests do this instead of typing into the login form,
 * which keeps them fast and clear of the login rate limit.
 */
export async function openAs(browser: Browser, user: User): Promise<Page> {
  const context = await browser.newContext();
  await context.addInitScript((u) => {
    if (!sessionStorage.getItem('e2e-seeded')) {
      localStorage.setItem('token', u.token);
      localStorage.setItem('refresh_token', u.refresh_token);
      localStorage.setItem('user', JSON.stringify(u.user));
      sessionStorage.setItem('e2e-seeded', '1');
    }
  }, { token: user.token, refresh_token: user.refresh_token, user: user.user });
  const page = await context.newPage();
  trackErrors(page);
  await page.goto('/');
  // Logged in. (The app opens the user's first server, if any, straight away.)
  await page.getByTitle('Account settings').waitFor();
  return page;
}

export async function newUserPage(browser: Browser, prefix = 'ui'): Promise<{ user: User; page: Page }> {
  const user = await register(prefix);
  return { user, page: await openAs(browser, user) };
}

/** Fails the test on uncaught page errors or unexpected alert/confirm dialogs. */
export function trackErrors(page: Page) {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(e.message));
  page.on('dialog', (d) => {
    errors.push(`unexpected dialog: ${d.message()}`);
    d.dismiss().catch(() => {});
  });
  (page as any).__errors = errors;
}

export function pageErrors(page: Page): string[] {
  return (page as any).__errors ?? [];
}

export async function openChannel(page: Page, serverName: string, channel = 'general') {
  await page.getByTitle(serverName, { exact: true }).click();
  // Channel messages are mandatory end-to-end encrypted, so opening a
  // channel always kicks off a member-devices fetch (to know who to
  // encrypt a send "for"); sending can only use it once it lands, but
  // nothing in the UI itself waits for that -- a message typed right
  // after this call can race it and the send gets silently dropped.
  // Waiting for it here, rather than leaving every caller to discover
  // the race on its own, is what made that flake show up consistently
  // across unrelated tests that otherwise never touched this file.
  const deviceListLoaded = page.waitForResponse((r) => r.url().includes('/member-devices'), { timeout: 10_000 }).catch(() => {});
  await page.getByText(`# ${channel}`, { exact: true }).click();
  await deviceListLoaded;
}

export async function sendMessage(page: Page, text: string) {
  await page.getByPlaceholder('Type a message...').fill(text);
  await page.getByRole('button', { name: 'Send' }).click();
}

/** The message row (hover target) containing `text`. */
export const messageRow = (page: Page, text: string) =>
  page.locator('.messages-container div.group', { hasText: text }).last();
