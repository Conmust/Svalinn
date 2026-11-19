import { test, expect, type Browser, type Page } from '@playwright/test';
import { call, register, sql, type User } from '../../support/api';
import { openAs, pageErrors } from '../../support/ui';

const SENT_BEFORE_DEVICE_ADDED_PLACEHOLDER = '[Sent before this device was added]';

/**
 * `participantDevices` is fetched exactly once per conversation selection
 * (see the `conversationId` watcher in DMChatArea.svelte) with no retry, so
 * if the other participant's device registration (generated/uploaded
 * asynchronously right after login -- see App.svelte) hasn't landed yet at
 * that moment, sending stays blocked for the rest of the test. Waiting for
 * both users' `device_keys` rows to exist before selecting the conversation
 * avoids that unrelated race entirely.
 */
async function waitForOwnDevice(userId: string, timeoutMs = 15_000) {
  const start = Date.now();
  for (;;) {
    const rows = await sql<{ count: string }>('SELECT COUNT(*) FROM device_keys WHERE user_id = $1', [userId]);
    if (Number(rows[0].count) > 0) return;
    if (Date.now() - start > timeoutMs) throw new Error(`device for user ${userId} never registered`);
    await new Promise((r) => setTimeout(r, 100));
  }
}

/**
 * Two registered users with an existing conversation between them, both
 * logged in and with that conversation open in the DM view, ready to send.
 */
async function openDmPair(browser: Browser): Promise<{ a: User; b: User; aPage: Page; bPage: Page }> {
  const a = await register('dmra');
  const b = await register('dmrb');

  const created = await call(a, 'POST', '/conversations', { participant_id: b.user.id });
  if (created.status !== 200) throw new Error(`failed to create conversation: ${created.status} ${JSON.stringify(created.body)}`);

  const aPage = await openAs(browser, a);
  const bPage = await openAs(browser, b);

  // Wait for both devices to finish registering BEFORE selecting the
  // conversation -- see `waitForOwnDevice`.
  await Promise.all([waitForOwnDevice(a.user.id), waitForOwnDevice(b.user.id)]);

  for (const page of [aPage, bPage]) {
    await page.getByTitle('Direct Messages').click();
  }
  await aPage.getByText(b.user.username, { exact: false }).first().click();
  await bPage.getByText(a.user.username, { exact: false }).first().click();

  // The Send button is also disabled whenever the input is empty
  // (`disabled={sending || !canSend || !newMessage.trim()}`), so check the
  // input itself -- its `disabled` only reflects `sending || !canSend`.
  await expect(aPage.getByPlaceholder('Type a message...')).toBeEnabled({ timeout: 15_000 });
  await expect(bPage.getByPlaceholder('Type a message...')).toBeEnabled({ timeout: 15_000 });

  return { a, b, aPage, bPage };
}

async function sendAndCheckOwnDisplay(aPage: Page, bPage: Page, text: string) {
  await aPage.getByPlaceholder('Type a message...').fill(text);
  await aPage.getByRole('button', { name: 'Send' }).click();

  // (a) The sending device must show the real content, never the
  // "sent before this device was added" placeholder, under any arrival
  // ordering of the WebSocket push vs. the HTTP response.
  await expect(aPage.getByText(text, { exact: true })).toBeVisible();
  await expect(aPage.getByText(SENT_BEFORE_DEVICE_ADDED_PLACEHOLDER)).toHaveCount(0);
  // (c) No duplicate rendering of the same message on the sender's device.
  await expect(aPage.getByText(text, { exact: true })).toHaveCount(1);

  // (b) The other participant's device still gets the live WebSocket push
  // with the correct content, same as before.
  await expect(bPage.getByText(text, { exact: true })).toBeVisible();
  await expect(bPage.getByText(text, { exact: true })).toHaveCount(1);
}

test('sending device never shows a wrong placeholder for its own message -- WS push forced to arrive first', async ({ browser }) => {
  const { aPage, bPage } = await openDmPair(browser);

  // The server broadcasts over the websocket before it returns the HTTP
  // response (see `send_conversation_message`), so on a fast loopback
  // connection the WS push already tends to win; delaying the POST
  // response here makes that ordering deterministic for this test.
  await aPage.route('**/api/v1/conversations/*/messages', async (route) => {
    if (route.request().method() === 'POST') {
      await new Promise((r) => setTimeout(r, 250));
    }
    await route.continue();
  });

  const ATTEMPTS = 10;
  let clean = 0;
  for (let i = 0; i < ATTEMPTS; i++) {
    const text = `ws-first-${i}-${Date.now()}`;
    await sendAndCheckOwnDisplay(aPage, bPage, text);
    clean++;
  }

  expect(clean).toBe(ATTEMPTS);
  expect(pageErrors(aPage)).toEqual([]);
  expect(pageErrors(bPage)).toEqual([]);
});

test('sending device never shows a wrong placeholder for its own message -- natural (unthrottled) timing', async ({ browser }) => {
  const { aPage, bPage } = await openDmPair(browser);

  const ATTEMPTS = 10;
  let clean = 0;
  for (let i = 0; i < ATTEMPTS; i++) {
    const text = `natural-${i}-${Date.now()}`;
    await sendAndCheckOwnDisplay(aPage, bPage, text);
    clean++;
  }

  expect(clean).toBe(ATTEMPTS);
  expect(pageErrors(aPage)).toEqual([]);
  expect(pageErrors(bPage)).toEqual([]);
});
