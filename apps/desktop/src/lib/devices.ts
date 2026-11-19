// Per-device key management: registering this device, listing/renaming/
// removing a user's own devices, and discovering a conversation's
// participant devices before composing a fan-out send. Pairs with
// `lib/crypto.ts`, which owns the actual keypair generation/storage.
import { getAuthHeaders, apiFetch, apiBase } from './api';
import { withTimeout } from './timeout';

/** Every network call below feeds either the "can this device send
 * encrypted DMs at all" gate or the devices settings UI -- neither should
 * be able to hang forever on a dead connection. This bounds each one so a
 * stuck request surfaces as a clear failure instead of an indefinite
 * spinner (callers already treat any rejection here as "assume the worst,
 * block sending" -- see `DMChatArea.svelte`'s `canSend`). */
const DEVICE_NETWORK_TIMEOUT_MS = 10_000;

/** One of the current user's own registered devices, as shown in the
 * devices settings UI. Never carries a public key -- the owning client
 * already has it locally. */
export interface MyDevice {
  id: string;
  device_label: string;
  created_at: string;
}

/** One device belonging to either participant of a conversation, as
 * needed to encrypt a send. */
export interface ParticipantDevice {
  device_id: string;
  user_id: string;
  public_key: string;
  device_label: string;
  /** True for one of the CURRENT user's own devices (which may or may not
   * be the device making the request -- see `encryptForConversation`). */
  is_me: boolean;
}

/** Registers this device with the server and returns its new `device_id`.
 * Called once per device by `ensureDeviceKeypair` -- not meant to be
 * called directly elsewhere. */
export async function registerDevice(publicKeyBase64: string, deviceLabel: string): Promise<string> {
  const response = await withTimeout(
    apiFetch(`${apiBase()}/api/v1/users/me/devices`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
      body: JSON.stringify({ public_key: publicKeyBase64, device_label: deviceLabel }),
    }),
    DEVICE_NETWORK_TIMEOUT_MS,
    'Timed out registering this device.'
  );
  if (!response.ok) {
    throw new Error('Failed to register device');
  }
  const { id } = await response.json();
  return id;
}

/** Lists the current user's own registered devices, for the devices
 * settings UI. */
export async function fetchMyDevices(): Promise<MyDevice[]> {
  const response = await withTimeout(
    apiFetch(`${apiBase()}/api/v1/users/me/devices`, {
      headers: getAuthHeaders(),
    }),
    DEVICE_NETWORK_TIMEOUT_MS,
    'Timed out fetching your devices.'
  );
  if (!response.ok) {
    throw new Error('Failed to fetch devices');
  }
  return response.json();
}

/** Renames one of the current user's own devices (including, potentially,
 * this one). */
export async function renameDevice(deviceId: string, deviceLabel: string): Promise<MyDevice> {
  const response = await apiFetch(`${apiBase()}/api/v1/users/me/devices/${deviceId}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
    body: JSON.stringify({ device_label: deviceLabel }),
  });
  if (!response.ok) {
    throw new Error('Failed to rename device');
  }
  return response.json();
}

/** Removes one of the current user's own devices. Any messages already
 * addressed to it become permanently undecryptable on it -- there's no
 * way to retroactively hand it the keys it needed, by design. */
export async function removeDevice(deviceId: string): Promise<void> {
  const response = await apiFetch(`${apiBase()}/api/v1/users/me/devices/${deviceId}`, {
    method: 'DELETE',
    headers: getAuthHeaders(),
  });
  if (!response.ok) {
    throw new Error('Failed to remove device');
  }
}

/** Lists every registered device of BOTH participants in a conversation --
 * what a client needs before composing a fan-out send: encrypt once per
 * device in this list (besides the sending device itself, which already
 * has the plaintext). Empty for the other participant means they haven't
 * set up encrypted messaging on any device yet -- sending must be blocked
 * client-side rather than falling back to plaintext. */
export async function fetchParticipantDevices(conversationId: string): Promise<ParticipantDevice[]> {
  const response = await withTimeout(
    apiFetch(`${apiBase()}/api/v1/conversations/${conversationId}/participant-devices`, {
      headers: getAuthHeaders(),
    }),
    DEVICE_NETWORK_TIMEOUT_MS,
    'Timed out fetching the other participant\'s devices.'
  );
  if (!response.ok) {
    throw new Error('Failed to fetch participant devices');
  }
  return response.json();
}
