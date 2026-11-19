import { test, expect, type Browser, type Page } from '@playwright/test';
import { call, register, sql, type User } from '../../support/api';
import { openAs, pageErrors } from '../../support/ui';

const SENT_BEFORE_DEVICE_ADDED_PLACEHOLDER = '[Sent before this device was added]';
const DECRYPT_FAILED_PLACEHOLDER = '[Unable to decrypt this message]';

async function waitForOwnDevice(userId: string, timeoutMs = 15_000) {
  const start = Date.now();
  for (;;) {
    const rows = await sql<{ count: string }>('SELECT COUNT(*) FROM device_keys WHERE user_id = $1', [userId]);
    if (Number(rows[0].count) > 0) return;
    if (Date.now() - start > timeoutMs) throw new Error(`device for user ${userId} never registered`);
    await new Promise((r) => setTimeout(r, 100));
  }
}

async function openDmPair(browser: Browser): Promise<{ a: User; b: User; aPage: Page; bPage: Page }> {
  const a = await register('rtra');
  const b = await register('rtrb');

  const created = await call(a, 'POST', '/conversations', { participant_id: b.user.id });
  if (created.status !== 200) throw new Error(`failed to create conversation: ${created.status} ${JSON.stringify(created.body)}`);

  const aPage = await openAs(browser, a);
  const bPage = await openAs(browser, b);

  await Promise.all([waitForOwnDevice(a.user.id), waitForOwnDevice(b.user.id)]);

  for (const page of [aPage, bPage]) {
    await page.getByTitle('Direct Messages').click();
  }
  await aPage.getByText(b.user.username, { exact: false }).first().click();
  await bPage.getByText(a.user.username, { exact: false }).first().click();

  await expect(aPage.getByPlaceholder('Type a message...')).toBeEnabled({ timeout: 15_000 });
  await expect(bPage.getByPlaceholder('Type a message...')).toBeEnabled({ timeout: 15_000 });

  return { a, b, aPage, bPage };
}

async function deviceCount(userId: string): Promise<number> {
  const rows = await sql<{ count: string }>('SELECT COUNT(*) FROM device_keys WHERE user_id = $1', [userId]);
  return Number(rows[0].count);
}

async function waitForDeviceCount(userId: string, expected: number, timeoutMs = 15_000) {
  const start = Date.now();
  for (;;) {
    if ((await deviceCount(userId)) >= expected) return;
    if (Date.now() - start > timeoutMs) throw new Error(`user ${userId} never reached ${expected} registered devices`);
    await new Promise((r) => setTimeout(r, 100));
  }
}

/**
 * Opens a second device (e.g. "phone") for an already-registered user who
 * already has one device open elsewhere, and selects the same DM. Waits for
 * the new device to finish registering (`device_keys`) BEFORE returning, and
 * then has `refreshPage` re-select the DM so its cached `participantDevices`
 * picks up the new device -- otherwise any send from `refreshPage` would
 * legitimately (and correctly) exclude the brand new device, which is a
 * separate, pre-existing "stale device list" behavior, not the thing under
 * test here.
 */
async function openSecondDevice(browser: Browser, user: User, otherUsername: string, refreshPage: Page): Promise<Page> {
  const before = await deviceCount(user.user.id);
  const page = await openAs(browser, user);
  await page.getByTitle('Direct Messages').click();
  await page.getByText(otherUsername, { exact: false }).first().click();
  await expect(page.getByPlaceholder('Type a message...')).toBeEnabled({ timeout: 15_000 });
  await waitForDeviceCount(user.user.id, before + 1);

  // Force `refreshPage` to refetch `participantDevices` for this
  // conversation now that the new device is registered.
  await refreshPage.reload();
  await refreshPage.getByTitle('Direct Messages').click();
  await refreshPage.getByText(otherUsername, { exact: false }).first().click();
  await expect(refreshPage.getByPlaceholder('Type a message...')).toBeEnabled({ timeout: 15_000 });

  return page;
}

test.describe('independent retest of the self-echo race fix', () => {
  test('1. 20 rapid sequential sends from one device: own bubble always shows real text, never a placeholder or stale content', async ({ browser }) => {
    const { aPage, bPage } = await openDmPair(browser);

    const N = 20;
    const texts: string[] = [];
    for (let i = 0; i < N; i++) {
      const text = `seq-${i}-${Date.now()}`;
      texts.push(text);
      await aPage.getByPlaceholder('Type a message...').fill(text);
      await aPage.getByRole('button', { name: 'Send' }).click();
      // Check immediately after each send, not batched at the end.
      await expect(aPage.getByText(text, { exact: true })).toBeVisible({ timeout: 10_000 });
      await expect(aPage.getByText(SENT_BEFORE_DEVICE_ADDED_PLACEHOLDER)).toHaveCount(0);
      await expect(aPage.getByText(DECRYPT_FAILED_PLACEHOLDER)).toHaveCount(0);
      // Also check on the other participant's side live.
      await expect(bPage.getByText(text, { exact: true })).toBeVisible({ timeout: 10_000 });
    }

    // Final sanity: every one of the 20 texts is present exactly once on
    // both sides, nothing dropped, nothing duplicated.
    for (const text of texts) {
      await expect(aPage.getByText(text, { exact: true })).toHaveCount(1);
      await expect(bPage.getByText(text, { exact: true })).toHaveCount(1);
    }
    expect(pageErrors(aPage)).toEqual([]);
    expect(pageErrors(bPage)).toEqual([]);
  });

  test('2. two devices of the SAME sender open at once: sending from device A still live-pushes correctly to device B, and vice versa', async ({ browser }) => {
    const { a, b, aPage, bPage } = await openDmPair(browser);
    // a second device ("phone") for user A.
    const aPhone = await openSecondDevice(browser, a, b.user.username, aPage);

    const t1 = `laptop-send-${Date.now()}`;
    await aPage.getByPlaceholder('Type a message...').fill(t1);
    await aPage.getByRole('button', { name: 'Send' }).click();
    await expect(aPage.getByText(t1, { exact: true })).toBeVisible();
    await expect(aPage.getByText(SENT_BEFORE_DEVICE_ADDED_PLACEHOLDER)).toHaveCount(0);
    // phone (other device, same user) should live-receive it correctly.
    await expect(aPhone.getByText(t1, { exact: true })).toBeVisible({ timeout: 10_000 });
    await expect(aPhone.getByText(SENT_BEFORE_DEVICE_ADDED_PLACEHOLDER)).toHaveCount(0);
    await expect(aPhone.getByText(DECRYPT_FAILED_PLACEHOLDER)).toHaveCount(0);
    // b should get it too.
    await expect(bPage.getByText(t1, { exact: true })).toBeVisible({ timeout: 10_000 });

    const t2 = `phone-send-${Date.now()}`;
    await aPhone.getByPlaceholder('Type a message...').fill(t2);
    await aPhone.getByRole('button', { name: 'Send' }).click();
    await expect(aPhone.getByText(t2, { exact: true })).toBeVisible();
    await expect(aPhone.getByText(SENT_BEFORE_DEVICE_ADDED_PLACEHOLDER)).toHaveCount(0);
    await expect(aPage.getByText(t2, { exact: true })).toBeVisible({ timeout: 10_000 });
    await expect(bPage.getByText(t2, { exact: true })).toBeVisible({ timeout: 10_000 });

    expect(pageErrors(aPage)).toEqual([]);
    expect(pageErrors(aPhone)).toEqual([]);
    expect(pageErrors(bPage)).toEqual([]);
  });

  test('3. CONCURRENT sends from two devices of the SAME sender, overlapping in-flight windows: neither message is lost or swapped', async ({ browser }) => {
    const { a, b, aPage, bPage } = await openDmPair(browser);
    const aPhone = await openSecondDevice(browser, a, b.user.username, aPage);

    // Slow down the POST response on BOTH of user A's devices so their
    // sends are in flight at the same time, and the WS echo of each
    // reaches the OTHER of A's devices while that other device's own send
    // is also in flight -- the exact scenario the fix's single-slot
    // `pendingSelfEcho` does not appear to account for.
    for (const page of [aPage, aPhone]) {
      await page.route('**/api/v1/conversations/*/messages', async (route) => {
        if (route.request().method() === 'POST') {
          await new Promise((r) => setTimeout(r, 500));
        }
        await route.continue();
      });
    }

    const tLaptop = `concurrent-laptop-${Date.now()}`;
    const tPhone = `concurrent-phone-${Date.now()}`;

    await aPage.getByPlaceholder('Type a message...').fill(tLaptop);
    await aPhone.getByPlaceholder('Type a message...').fill(tPhone);

    // Fire both sends essentially simultaneously.
    await Promise.all([
      aPage.getByRole('button', { name: 'Send' }).click(),
      aPhone.getByRole('button', { name: 'Send' }).click(),
    ]);

    // Give both requests + broadcasts time to land.
    await aPage.waitForTimeout(2000);

    // Both messages must show up, un-corrupted, on BOTH of A's devices and
    // on B's device. This is the assertion most likely to fail: the
    // single-slot `pendingSelfEcho` buffer on each of A's devices can be
    // overwritten/discarded by the OTHER device's broadcast.
    for (const page of [aPage, aPhone, bPage]) {
      await expect(page.getByText(tLaptop, { exact: true })).toBeVisible({ timeout: 10_000 });
      await expect(page.getByText(tPhone, { exact: true })).toBeVisible({ timeout: 10_000 });
      await expect(page.getByText(SENT_BEFORE_DEVICE_ADDED_PLACEHOLDER)).toHaveCount(0);
    }
  });

  test('4. HTTP response never arrives after the message was actually persisted: own device must still show real content, not the placeholder', async ({ browser }) => {
    const { aPage, bPage } = await openDmPair(browser);

    // Simulate a network drop on the way back: let the POST request reach
    // the server (so it persists + broadcasts) but abort the response
    // before the client sees it.
    await aPage.route('**/api/v1/conversations/*/messages', async (route) => {
      if (route.request().method() === 'POST') {
        // Let it actually hit the server first (fire and forget), wait for
        // the broadcast to likely have arrived, THEN abort the response.
        const req = route.request();
        fetch(req.url(), { method: 'POST', headers: req.headers(), body: req.postData() ?? undefined }).catch(() => {});
        await new Promise((r) => setTimeout(r, 400));
        await route.abort('failed');
        return;
      }
      await route.continue();
    });

    const text = `dropped-response-${Date.now()}`;
    await aPage.getByPlaceholder('Type a message...').fill(text);
    await aPage.getByRole('button', { name: 'Send' }).click();

    // Let things settle: the fetch should fail client-side, the finally
    // block should flush pendingSelfEcho if it arrived.
    await aPage.waitForTimeout(1500);

    // The message DID get persisted and broadcast server-side (we fired it
    // directly above). The sending device should ideally show the real
    // text -- not the "sent before this device was added" placeholder,
    // and not nothing at all.
    const placeholderCount = await aPage.getByText(SENT_BEFORE_DEVICE_ADDED_PLACEHOLDER).count();
    const realTextCount = await aPage.getByText(text, { exact: true }).count();
    console.log(`[retest] after dropped HTTP response: placeholderCount=${placeholderCount}, realTextCount=${realTextCount}`);
    expect(placeholderCount, 'own device showed the wrong placeholder for a message it actually sent successfully').toBe(0);
    expect(realTextCount, 'own device should still show its own real sent text after a dropped HTTP response').toBeGreaterThan(0);
  });

  test('5. rapid double-click on Send does not duplicate, corrupt, or swap message content', async ({ browser }) => {
    const { aPage, bPage } = await openDmPair(browser);

    const text = `doubleclick-${Date.now()}`;
    await aPage.getByPlaceholder('Type a message...').fill(text);
    const sendBtn = aPage.getByRole('button', { name: 'Send' });
    // Fire two clicks back to back without waiting for actionability (the
    // button disables almost immediately, which is itself one of the
    // things under test -- does it disable fast enough to block a second
    // real send, or can a user get a click in before the DOM updates?).
    // Use JS-level dispatch so both land synchronously, bypassing
    // Playwright's actionability wait that would otherwise just wait for
    // the (now-disabled) button and time out.
    await Promise.all([
      sendBtn.dispatchEvent('click'),
      sendBtn.dispatchEvent('click').catch(() => {}),
    ]);
    await aPage.waitForTimeout(1500);

    await expect(aPage.getByText(text, { exact: true })).toHaveCount(1);
    await expect(bPage.getByText(text, { exact: true })).toHaveCount(1);
    expect(pageErrors(aPage)).toEqual([]);
  });
});
