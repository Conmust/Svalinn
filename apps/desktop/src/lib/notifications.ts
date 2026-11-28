// Native OS notifications for a new message, shown when the user isn't
// actively looking at the app -- e.g. another window has focus, or the app
// is minimized/backgrounded.
//
// This uses `@tauri-apps/plugin-notification` rather than the bare Web
// Notification API directly, so the SAME code path works both in the
// compiled Tauri desktop/mobile app (where the plugin bridges to real OS
// notification permissions and, on mobile, native delivery) and in a plain
// browser (this app's own e2e tests run the Svelte build directly in
// Chromium, with no Tauri runtime at all) -- the plugin's own
// `sendNotification` falls back to the standard `window.Notification`
// constructor whenever it isn't running inside Tauri, which every
// evergreen browser already implements. See `src-tauri/Cargo.toml` and
// `src-tauri/src/lib.rs` for the plugin's registration, and
// `src-tauri/capabilities/default.json` for the permission that lets the
// webview actually call it.
//
// Privacy note: this is NOT a remote "push" service -- nothing is
// registered with any third-party push provider, and no message content
// ever leaves this device to make a notification happen. The content
// shown here is already decrypted and already on screen in the chat UI by
// the time a notification fires; this just also surfaces it as a native OS
// notification when the user isn't currently looking at the window.
import { isPermissionGranted, requestPermission, sendNotification } from '@tauri-apps/plugin-notification';

/** Whether this runtime can show notifications at all (every evergreen
 * browser does; this is just a defensive check for anything exotic). */
export function notificationsSupported(): boolean {
  return typeof Notification !== 'undefined';
}

export async function hasNotificationPermission(): Promise<boolean> {
  if (!notificationsSupported()) return false;
  try {
    return await isPermissionGranted();
  } catch {
    return false;
  }
}

/** Prompts the user, if needed. Returns whether permission ended up
 * granted. Must be called from a user gesture (e.g. a settings toggle
 * click) -- browsers ignore a permission prompt triggered any other way,
 * which is also why this app never calls this on its own on startup. */
export async function requestNotificationPermission(): Promise<boolean> {
  if (!notificationsSupported()) return false;
  try {
    if (await isPermissionGranted()) return true;
    const result = await requestPermission();
    return result === 'granted';
  } catch {
    return false;
  }
}

/** Whether a notification should fire right now: permission is granted,
 * and the user isn't already looking at the app. `document.hidden` covers
 * a backgrounded/minimized tab or window; `!document.hasFocus()` also
 * covers a visible-but-not-focused window (e.g. on top of another app in a
 * tiling layout) -- either way, a notification just duplicates what's
 * already on screen. */
export async function shouldNotify(): Promise<boolean> {
  if (typeof document === 'undefined') return false;
  if (document.hidden || !document.hasFocus()) {
    return await hasNotificationPermission();
  }
  return false;
}

/** Shows a notification if (and only if) the user isn't currently looking
 * at the app and has granted permission. Safe to call unconditionally from
 * a message handler -- the gating is internal, so callers never need to
 * check `shouldNotify` themselves first. Never throws: a failure here
 * (permission revoked mid-session, an unsupported runtime) just means the
 * one notification is silently skipped, which is strictly better than an
 * uncaught error interrupting message handling. */
export async function notifyNewMessage(title: string, body: string): Promise<void> {
  try {
    if (!(await shouldNotify())) return;
    sendNotification({ title, body });
  } catch (err) {
    console.warn('Failed to show a new-message notification:', err);
  }
}
