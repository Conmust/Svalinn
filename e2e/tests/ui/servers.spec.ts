import { test, expect, type Page } from '@playwright/test';
import { createServer, join, register, uniq } from '../../support/api';
import { openAs, openChannel, pageErrors } from '../../support/ui';

const memberRow = (page: Page, username: string) => page.locator('aside div.group', { hasText: username });

async function manage(page: Page, username: string) {
  const row = memberRow(page, username);
  await row.hover();
  await row.getByRole('button', { name: `Manage ${username}` }).click();
}

test('invite, join, kick, ban and unban through the app', async ({ browser }) => {
  const owner = await register('own');
  const name = uniq('Guild');
  const { server } = await createServer(owner, name);
  const ownerPage = await openAs(browser, owner);
  await openChannel(ownerPage, name);

  // Owner creates an invite
  await ownerPage.getByTitle('Server Settings').click();
  await ownerPage.getByRole('button', { name: 'Invites' }).click();
  await ownerPage.getByLabel('Max uses').selectOption('5');
  await ownerPage.getByRole('button', { name: 'Create invite' }).click();
  const code = (await ownerPage.locator('li code').first().innerText()).trim();
  await ownerPage.getByLabel('Close settings').click();
  await ownerPage.getByRole('button', { name: 'Members' }).click();
  await expect(ownerPage.getByText('Members — 1')).toBeVisible();

  // Member joins with a pasted link
  const member = await register('mem');
  const memberPage = await openAs(browser, member);
  const joinWith = async () => {
    await memberPage.getByTitle('Create or join a server').click();
    await memberPage.getByRole('tab', { name: 'Join' }).click();
    await memberPage.getByLabel('Invite code or link').fill(`https://example.test/invite/${code}`);
    await memberPage.getByRole('button', { name: 'Look up' }).click();
    await expect(memberPage.getByText(name, { exact: true })).toBeVisible();
    await memberPage.getByRole('button', { name: 'Join', exact: true }).click();
  };
  await joinWith();
  await expect(memberPage.getByText('# general')).toBeVisible();
  await expect(ownerPage.getByText('Members — 2')).toBeVisible(); // live

  // Kick
  await manage(ownerPage, member.user.username);
  await ownerPage.getByRole('dialog').getByRole('button', { name: 'Kick' }).click();
  await ownerPage.getByRole('dialog').getByRole('button', { name: 'Kick' }).click();
  await expect(memberPage.getByText(`You were removed from ${name}.`)).toBeVisible();
  await expect(memberPage.getByTitle(name, { exact: true })).toHaveCount(0);

  // Rejoin, then ban with a reason
  await joinWith();
  await expect(ownerPage.getByText('Members — 2')).toBeVisible();
  await manage(ownerPage, member.user.username);
  await ownerPage.getByRole('dialog').getByRole('button', { name: 'Ban' }).click();
  await ownerPage.getByLabel('Reason (optional)').fill('spamming links');
  await ownerPage.getByRole('dialog').getByRole('button', { name: 'Ban' }).click();
  await expect(memberPage.getByText(`You were banned from ${name}.`)).toBeVisible();

  await memberPage.getByTitle('Create or join a server').click();
  await memberPage.getByRole('tab', { name: 'Join' }).click();
  await memberPage.getByLabel('Invite code or link').fill(code);
  await memberPage.getByRole('button', { name: 'Look up' }).click();
  await memberPage.getByRole('button', { name: 'Join', exact: true }).click();
  await expect(memberPage.getByText('You are banned from this server.')).toBeVisible();

  // Lift the ban
  await ownerPage.getByTitle('Server Settings').click();
  await ownerPage.getByRole('button', { name: 'Bans' }).click();
  await expect(ownerPage.getByText('spamming links')).toBeVisible();
  await ownerPage.getByRole('button', { name: 'Unban' }).click();
  await expect(ownerPage.getByText('Nobody is banned')).toBeVisible();
  expect(pageErrors(ownerPage)).toEqual([]);
  void server;
});

test('promotions and channel changes show up live', async ({ browser }) => {
  const owner = await register('own');
  const member = await register('mem');
  const { server } = await createServer(owner);
  await join(owner, server.id, member);
  const ownerPage = await openAs(browser, owner);
  const memberPage = await openAs(browser, member);
  await openChannel(ownerPage, server.name);
  await openChannel(memberPage, server.name);

  // Promote to moderator: the member gets Pin without reloading
  await memberPage.getByPlaceholder('Type a message...').fill('my message');
  await memberPage.getByRole('button', { name: 'Send' }).click();
  await ownerPage.getByRole('button', { name: 'Members' }).click();
  await manage(ownerPage, member.user.username);
  await expect(ownerPage.getByLabel('Role').locator('option')).toHaveText(['Member', 'Moderator', 'Admin']);
  await ownerPage.getByLabel('Role').selectOption('moderator');
  await ownerPage.getByRole('button', { name: 'Save role' }).click();
  const row = memberPage.locator('.messages-container div.group', { hasText: 'my message' }).last();
  await expect(async () => {
    await row.hover();
    await expect(row.getByRole('button', { name: 'Pin', exact: true })).toBeVisible({ timeout: 500 });
  }).toPass();

  // New channel, renamed, deleted: the member follows along live
  await ownerPage.getByTitle('Create Channel').click();
  await ownerPage.getByLabel('Channel Name').fill('news');
  await ownerPage.locator('form').getByRole('button', { name: 'Create' }).click();
  await expect(memberPage.getByText('# news')).toBeVisible();

  const news = ownerPage.locator('div.relative.group', { hasText: '# news' });
  await news.hover();
  await news.getByRole('button', { name: 'Rename news' }).click();
  await ownerPage.getByLabel('Channel name').fill('announcements');
  await ownerPage.getByRole('button', { name: 'Rename', exact: true }).click();
  await expect(memberPage.getByText('# announcements')).toBeVisible();
  await expect(memberPage.getByRole('button', { name: 'Rename announcements' })).toHaveCount(0); // moderators can't

  await memberPage.getByText('# announcements').click();
  const ann = ownerPage.locator('div.relative.group', { hasText: '# announcements' });
  await ann.hover();
  await ann.getByRole('button', { name: 'Delete announcements' }).click();
  await ownerPage.getByRole('button', { name: 'Delete channel' }).click();
  await expect(memberPage.getByText('Select a channel to start chatting')).toBeVisible();
  await expect(memberPage.getByText('# announcements')).toHaveCount(0);
});

test('transfer ownership, then delete the server', async ({ browser }) => {
  const owner = await register('own');
  const member = await register('mem');
  const { server } = await createServer(owner);
  await join(owner, server.id, member);
  const ownerPage = await openAs(browser, owner);
  const memberPage = await openAs(browser, member);
  await openChannel(ownerPage, server.name);
  await openChannel(memberPage, server.name);

  await ownerPage.getByRole('button', { name: 'Members' }).click();
  await manage(ownerPage, member.user.username);
  await ownerPage.getByRole('button', { name: `Transfer ownership to ${member.user.username}` }).click();
  await ownerPage.getByLabel('Your password').fill('wrong');
  await ownerPage.getByRole('button', { name: 'Transfer', exact: true }).click();
  await expect(ownerPage.getByText('Your current password is incorrect')).toBeVisible();
  await ownerPage.getByLabel('Your password').fill('secret123');
  await ownerPage.getByRole('button', { name: 'Transfer', exact: true }).click();
  await expect(ownerPage.getByRole('dialog')).toHaveCount(0);

  await memberPage.getByTitle('Server Settings').click();
  await memberPage.getByRole('button', { name: 'Delete server' }).click();
  await memberPage.getByLabel('Type the server name to confirm').fill(server.name);
  await memberPage.getByLabel('Your password').fill('secret123');
  await memberPage.locator('form').getByRole('button', { name: 'Delete server' }).click();

  await expect(ownerPage.getByText(`${server.name} was deleted.`)).toBeVisible();
  await expect(ownerPage.getByTitle(server.name, { exact: true })).toHaveCount(0);
});
