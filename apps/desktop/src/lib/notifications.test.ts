import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const isPermissionGranted = vi.fn();
const requestPermission = vi.fn();
const sendNotification = vi.fn();

vi.mock('@tauri-apps/plugin-notification', () => ({
  isPermissionGranted: (...args: unknown[]) => isPermissionGranted(...args),
  requestPermission: (...args: unknown[]) => requestPermission(...args),
  sendNotification: (...args: unknown[]) => sendNotification(...args),
}));

/** Sets up the global `document`/`Notification` shape `notifications.ts`
 * reads, same approach `message-history.test.ts` uses for `indexedDB` --
 * this module's tests run with no real DOM, so these are provided
 * per-test rather than assumed to exist. */
function setGlobals(opts: { hidden: boolean; focused: boolean; notificationCtor: boolean }) {
  (globalThis as any).document = { hidden: opts.hidden };
  (globalThis as any).window = { hasFocus: () => opts.focused };
  // `document.hasFocus()` is actually a method on `window`/`document` in a
  // real browser (both exist and proxy to the same thing) -- this module
  // calls it as `document.hasFocus()`, so attach it there directly.
  (globalThis as any).document.hasFocus = () => opts.focused;
  if (opts.notificationCtor) {
    (globalThis as any).Notification = function Notification() {};
  } else {
    delete (globalThis as any).Notification;
  }
}

describe('notificationsSupported', () => {
  afterEach(() => {
    delete (globalThis as any).Notification;
  });

  it('is true when the Notification constructor exists', async () => {
    (globalThis as any).Notification = function Notification() {};
    const { notificationsSupported } = await import('./notifications');
    expect(notificationsSupported()).toBe(true);
  });

  it('is false when there is no Notification constructor', async () => {
    delete (globalThis as any).Notification;
    vi.resetModules();
    const { notificationsSupported } = await import('./notifications');
    expect(notificationsSupported()).toBe(false);
  });
});

describe('hasNotificationPermission / requestNotificationPermission', () => {
  beforeEach(() => {
    vi.resetModules();
    isPermissionGranted.mockReset();
    requestPermission.mockReset();
    setGlobals({ hidden: true, focused: false, notificationCtor: true });
  });

  it('reports false when unsupported, without calling the plugin', async () => {
    setGlobals({ hidden: true, focused: false, notificationCtor: false });
    const { hasNotificationPermission } = await import('./notifications');
    expect(await hasNotificationPermission()).toBe(false);
    expect(isPermissionGranted).not.toHaveBeenCalled();
  });

  it('reflects the plugin\'s answer when supported', async () => {
    isPermissionGranted.mockResolvedValue(true);
    const { hasNotificationPermission } = await import('./notifications');
    expect(await hasNotificationPermission()).toBe(true);
  });

  it('treats a rejected permission check as not granted, not a thrown error', async () => {
    isPermissionGranted.mockRejectedValue(new Error('boom'));
    const { hasNotificationPermission } = await import('./notifications');
    await expect(hasNotificationPermission()).resolves.toBe(false);
  });

  it('requestNotificationPermission short-circuits if already granted', async () => {
    isPermissionGranted.mockResolvedValue(true);
    const { requestNotificationPermission } = await import('./notifications');
    expect(await requestNotificationPermission()).toBe(true);
    expect(requestPermission).not.toHaveBeenCalled();
  });

  it('requestNotificationPermission prompts when not yet granted', async () => {
    isPermissionGranted.mockResolvedValue(false);
    requestPermission.mockResolvedValue('granted');
    const { requestNotificationPermission } = await import('./notifications');
    expect(await requestNotificationPermission()).toBe(true);
    expect(requestPermission).toHaveBeenCalledOnce();
  });

  it('requestNotificationPermission reports false on denial', async () => {
    isPermissionGranted.mockResolvedValue(false);
    requestPermission.mockResolvedValue('denied');
    const { requestNotificationPermission } = await import('./notifications');
    expect(await requestNotificationPermission()).toBe(false);
  });
});

describe('notifyNewMessage', () => {
  beforeEach(() => {
    vi.resetModules();
    isPermissionGranted.mockReset();
    sendNotification.mockReset();
  });

  it('sends a notification when backgrounded and permitted', async () => {
    setGlobals({ hidden: true, focused: false, notificationCtor: true });
    isPermissionGranted.mockResolvedValue(true);
    const { notifyNewMessage } = await import('./notifications');
    await notifyNewMessage('Alice', 'hey there');
    expect(sendNotification).toHaveBeenCalledWith({ title: 'Alice', body: 'hey there' });
  });

  it('sends when visible but not focused', async () => {
    setGlobals({ hidden: false, focused: false, notificationCtor: true });
    isPermissionGranted.mockResolvedValue(true);
    const { notifyNewMessage } = await import('./notifications');
    await notifyNewMessage('Alice', 'hey there');
    expect(sendNotification).toHaveBeenCalledOnce();
  });

  it('does not send while the app is focused and visible', async () => {
    setGlobals({ hidden: false, focused: true, notificationCtor: true });
    isPermissionGranted.mockResolvedValue(true);
    const { notifyNewMessage } = await import('./notifications');
    await notifyNewMessage('Alice', 'hey there');
    expect(sendNotification).not.toHaveBeenCalled();
  });

  it('does not send without permission', async () => {
    setGlobals({ hidden: true, focused: false, notificationCtor: true });
    isPermissionGranted.mockResolvedValue(false);
    const { notifyNewMessage } = await import('./notifications');
    await notifyNewMessage('Alice', 'hey there');
    expect(sendNotification).not.toHaveBeenCalled();
  });

  it('never throws even if sendNotification itself throws', async () => {
    setGlobals({ hidden: true, focused: false, notificationCtor: true });
    isPermissionGranted.mockResolvedValue(true);
    sendNotification.mockImplementation(() => {
      throw new Error('platform notification failure');
    });
    const { notifyNewMessage } = await import('./notifications');
    await expect(notifyNewMessage('Alice', 'hey there')).resolves.toBeUndefined();
  });
});
