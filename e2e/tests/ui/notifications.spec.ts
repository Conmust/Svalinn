import { test, expect, type Browser } from '@playwright/test';
import { createServer, join, register, type User } from '../../support/api';
import { openChannel } from '../../support/ui';

/**
 * Opens the app logged in as `user`, like `support/ui.ts`'s `openAs`, but
 * also stubs `window.Notification` before any app code runs so
 * `lib/notifications.ts` sees a working, always-granted Notification API
 * without needing a real OS/browser permission prompt (which headless
 * Chromium has no user present to answer). Every call the app makes is
 * recorded on `window.__notifications` for the test to assert against.
 *
 * Duplicated from `openAs` rather than extending it, matching the existing
 * precedent in `typing-dm.spec.ts` (a locally-copied `waitForOwnDevice`)
 * for a one-off variant that only one test file needs.
 */
async function openAsWithNotificationStub(browser: Browser, user: User) {
  const context = await browser.newContext();
  await context.addInitScript((u) => {
    if (!sessionStorage.getItem('e2e-seeded')) {
      localStorage.setItem('token', u.token);
      localStorage.setItem('refresh_token', u.refresh_token);
      localStorage.setItem('user', JSON.stringify(u.user));
      sessionStorage.setItem('e2e-seeded', '1');
    }
  }, { token: user.token, refresh_token: user.refresh_token, user: user.user });
  await context.addInitScript(() => {
    (window as any).__notifications = [];
    class FakeNotification {
      static permission = 'granted';
      static requestPermission = async () => 'granted';
      constructor(title: string, options?: { body?: string }) {
        (window as any).__notifications.push({ title, body: options?.body });
      }
    }
    (window as any).Notification = FakeNotification;
  });
  const page = await context.newPage();
  await page.goto('/');
  await page.getByTitle('Account settings').waitFor();
  return page;
}

/** Forces `document.hidden`/`document.hasFocus()` to report a backgrounded
 * window -- Playwright's separate browser contexts don't reliably simulate
 * real OS/browser focus loss, so this overrides what `shouldNotify()` in
 * `lib/notifications.ts` actually reads, deterministically. */
async function setBackgrounded(page: import('@playwright/test').Page, backgrounded: boolean) {
  await page.evaluate((bg) => {
    Object.defineProperty(document, 'hidden', { get: () => bg, configurable: true });
    document.hasFocus = () => !bg;
  }, backgrounded);
}

// See `lib/notifications.ts` for the design: fires only when the user isn't
// looking at the app (backgrounded/unfocused) and permission is granted.
// This is a desktop OS notification, not a remote push service -- nothing
// is sent anywhere else to make it happen, and the content shown is
// already-decrypted plaintext already on screen in the chat.
test('a desktop notification fires for a new channel message only while backgrounded', async ({ browser }) => {
  const owner = await register('notifyown');
  const member = await register('notifymem');
  const { server } = await createServer(owner);
  await join(owner, server.id, member);

  const ownerPage = await openAsWithNotificationStub(browser, owner);
  const memberPage = await openAsWithNotificationStub(browser, member);
  await openChannel(ownerPage, server.name);
  await openChannel(memberPage, server.name);

  // Focused: no notification, even though the message still arrives live.
  await setBackgrounded(memberPage, false);
  await ownerPage.getByPlaceholder('Type a message...').fill('first message');
  await ownerPage.getByRole('button', { name: 'Send' }).click();
  await expect(memberPage.getByText('first message')).toBeVisible();
  expect(await memberPage.evaluate(() => (window as any).__notifications)).toEqual([]);

  // Backgrounded: the next message does notify, with the sender's name and
  // the (already-decrypted) message content.
  await setBackgrounded(memberPage, true);
  await ownerPage.getByPlaceholder('Type a message...').fill('second message');
  await ownerPage.getByRole('button', { name: 'Send' }).click();
  await expect(memberPage.getByText('second message')).toBeVisible();
  await expect.poll(() => memberPage.evaluate(() => (window as any).__notifications.length)).toBe(1);
  const notifications = await memberPage.evaluate(() => (window as any).__notifications);
  expect(notifications[0].title).toBe(owner.user.username);
  expect(notifications[0].body).toBe('second message');

  // The sender never gets notified about their own message.
  expect(await ownerPage.evaluate(() => (window as any).__notifications)).toEqual([]);
});
