import { test, expect } from '@playwright/test';
import { call, register, sql } from '../../support/api';
import { openAs } from '../../support/ui';

/**
 * Waits for a user's device registration to land before opening a DM, the
 * same race `dm-race.spec.ts`'s `waitForOwnDevice` guards against: the
 * participant-devices fetch that gates sending runs exactly once per
 * conversation selection, with no retry.
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

// DM counterpart of the channel typing-indicator test in `chat.spec.ts` --
// see `routes/ws.rs::handle_typing` and `lib/typing.ts` for the design
// (not E2EE, no message content, no explicit "stopped" event).
test('a DM typing indicator shows the other participant\'s name and clears on send', async ({ browser }) => {
  const a = await register('typa');
  const b = await register('typb');
  const created = await call(a, 'POST', '/conversations', { participant_id: b.user.id });
  if (created.status !== 200) throw new Error(`failed to create conversation: ${created.status}`);

  const aPage = await openAs(browser, a);
  const bPage = await openAs(browser, b);
  await Promise.all([waitForOwnDevice(a.user.id), waitForOwnDevice(b.user.id)]);

  for (const page of [aPage, bPage]) await page.getByTitle('Direct Messages').click();
  await aPage.getByText(b.user.username, { exact: false }).first().click();
  await bPage.getByText(a.user.username, { exact: false }).first().click();
  await expect(aPage.getByPlaceholder('Type a message...')).toBeEnabled({ timeout: 15_000 });
  await expect(bPage.getByPlaceholder('Type a message...')).toBeEnabled({ timeout: 15_000 });

  await aPage.getByPlaceholder('Type a message...').fill('hey, one sec');
  await expect(bPage.getByText(`${a.user.username} is typing...`)).toBeVisible();
  await expect(aPage.getByText('is typing...')).toHaveCount(0);

  await aPage.getByRole('button', { name: 'Send' }).click();
  await expect(bPage.getByText('hey, one sec')).toBeVisible();
  await expect(bPage.getByText('is typing...')).toHaveCount(0);
});
