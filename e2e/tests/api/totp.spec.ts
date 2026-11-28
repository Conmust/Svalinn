import { test, expect } from '@playwright/test';
import { call, login, register } from '../../support/api';
import { nextTotpCode, totpCode } from '../../support/totp';

/** Walks a registered user through setup -> enable, returning the decoded
 * secret and the backup codes issued on enable. */
async function enableTotp(user: Awaited<ReturnType<typeof register>>) {
  const setup = await call(user, 'POST', '/users/me/2fa/setup');
  expect(setup.status).toBe(200);
  expect(setup.body.secret).toMatch(/^[A-Z2-7]+$/);
  expect(setup.body.otpauth_url).toContain(setup.body.secret);

  const enabled = await call(user, 'POST', '/users/me/2fa/enable', { code: totpCode(setup.body.secret) });
  expect(enabled.status).toBe(200);
  expect(enabled.body.backup_codes).toHaveLength(8);

  return { secret: setup.body.secret as string, backupCodes: enabled.body.backup_codes as string[] };
}

test.describe('TOTP two-factor authentication', () => {
  test('setup does not turn 2FA on until a real code confirms it', async () => {
    const u = await register('totp');
    const setup = await call(u, 'POST', '/users/me/2fa/setup');
    expect(setup.status).toBe(200);

    expect((await call(u, 'GET', '/users/me/account')).body.totp_enabled).toBe(false);

    // A wrong code doesn't enable it either.
    const wrong = await call(u, 'POST', '/users/me/2fa/enable', { code: '000000' });
    expect(wrong.status).toBe(400);
    expect((await call(u, 'GET', '/users/me/account')).body.totp_enabled).toBe(false);

    // The real code does.
    const enabled = await call(u, 'POST', '/users/me/2fa/enable', { code: totpCode(setup.body.secret) });
    expect(enabled.status).toBe(200);
    expect((await call(u, 'GET', '/users/me/account')).body.totp_enabled).toBe(true);
  });

  test('login on a 2FA account stops at a pending token until a code confirms it', async () => {
    const u = await register('totp');
    const { secret } = await enableTotp(u);

    const firstFactor = await login(u.email, u.password, u.ip);
    expect(firstFactor.status).toBe(200);
    expect(firstFactor.body.requires_2fa).toBe(true);
    expect(firstFactor.body.pending_token).toBeTruthy();
    expect(firstFactor.body.token).toBeUndefined();

    // Wrong code: the pending token survives so the person can retry.
    const wrong = await call(null, 'POST', '/auth/2fa/login', {
      pending_token: firstFactor.body.pending_token,
      code: '000000',
    });
    expect(wrong.status).toBe(400);

    // Right code, one step past the one `enableTotp` already consumed.
    const ok = await call(null, 'POST', '/auth/2fa/login', {
      pending_token: firstFactor.body.pending_token,
      code: nextTotpCode(secret),
    });
    expect(ok.status).toBe(200);
    expect(ok.body.token).toBeTruthy();
    expect(ok.body.user.id).toBe(u.user.id);

    // The pending token is single-use -- it's gone even though it hasn't expired.
    const reused = await call(null, 'POST', '/auth/2fa/login', {
      pending_token: firstFactor.body.pending_token,
      code: nextTotpCode(secret, Math.floor(Date.now() / 1000) + 30),
    });
    expect(reused.status).toBe(400);
  });

  test('the same code cannot be used twice', async () => {
    const u = await register('totp');
    const { secret } = await enableTotp(u);
    const code = nextTotpCode(secret);

    const first = await login(u.email, u.password, u.ip);
    const firstVerify = await call(null, 'POST', '/auth/2fa/login', { pending_token: first.body.pending_token, code });
    expect(firstVerify.status).toBe(200);

    const second = await login(u.email, u.password, u.ip);
    const secondVerify = await call(null, 'POST', '/auth/2fa/login', { pending_token: second.body.pending_token, code });
    expect(secondVerify.status).toBe(400);
  });

  test('a backup code logs in once and then stops working', async () => {
    const u = await register('totp');
    const { backupCodes } = await enableTotp(u);
    const code = backupCodes[0];

    const first = await login(u.email, u.password, u.ip);
    const firstVerify = await call(null, 'POST', '/auth/2fa/login', { pending_token: first.body.pending_token, code });
    expect(firstVerify.status).toBe(200);

    const second = await login(u.email, u.password, u.ip);
    const secondVerify = await call(null, 'POST', '/auth/2fa/login', { pending_token: second.body.pending_token, code });
    expect(secondVerify.status).toBe(400);

    // Formatting (case, dashes, spaces) shouldn't matter on entry.
    const third = await login(u.email, u.password, u.ip);
    const messyCode = ` ${backupCodes[1].toLowerCase().replace('-', ' ')} `;
    const thirdVerify = await call(null, 'POST', '/auth/2fa/login', { pending_token: third.body.pending_token, code: messyCode });
    expect(thirdVerify.status).toBe(200);
  });

  test('disable requires the current password and actually turns 2FA off', async () => {
    const u = await register('totp');
    await enableTotp(u);

    const wrongPassword = await call(u, 'POST', '/users/me/2fa/disable', { current_password: 'not-the-password' });
    expect(wrongPassword.status).toBe(400);
    expect((await call(u, 'GET', '/users/me/account')).body.totp_enabled).toBe(true);

    const disabled = await call(u, 'POST', '/users/me/2fa/disable', { current_password: u.password });
    expect(disabled.status).toBe(200);
    expect((await call(u, 'GET', '/users/me/account')).body.totp_enabled).toBe(false);

    // A plain login works again with no 2FA step.
    const loggedIn = await login(u.email, u.password, u.ip);
    expect(loggedIn.status).toBe(200);
    expect(loggedIn.body.requires_2fa).toBeFalsy();
    expect(loggedIn.body.token).toBeTruthy();
  });

  test('regenerating backup codes invalidates the old set', async () => {
    const u = await register('totp');
    const { backupCodes } = await enableTotp(u);

    const regenerated = await call(u, 'POST', '/users/me/2fa/backup-codes/regenerate', { current_password: u.password });
    expect(regenerated.status).toBe(200);
    expect(regenerated.body.backup_codes).toHaveLength(8);
    expect(regenerated.body.backup_codes).not.toEqual(backupCodes);

    // An old code no longer works...
    const oldAttempt = await login(u.email, u.password, u.ip);
    const oldVerify = await call(null, 'POST', '/auth/2fa/login', {
      pending_token: oldAttempt.body.pending_token,
      code: backupCodes[0],
    });
    expect(oldVerify.status).toBe(400);

    // ...but a new one does.
    const newAttempt = await login(u.email, u.password, u.ip);
    const newVerify = await call(null, 'POST', '/auth/2fa/login', {
      pending_token: newAttempt.body.pending_token,
      code: regenerated.body.backup_codes[0],
    });
    expect(newVerify.status).toBe(200);
  });
});
