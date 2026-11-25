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

// --- Double Ratchet prekey bundles & session sync (migration 0038/0039) ---
//
// Additive alongside everything above: `ratchet.ts` is the only caller of
// these. None of this is used by the stateless per-device `crypto.ts` path.

/** Sets (or replaces) this device's Ed25519 signing public key -- see
 * migration 0039. Called once by `ratchet.ts`'s identity setup, the first
 * time it runs on a device that was already registered (the common case:
 * `ensureDeviceKeypair` in `crypto.ts` usually ran long before ratchet
 * support existed on this device). */
export async function setSigningKey(deviceId: string, signingPublicKeyBase64: string): Promise<void> {
  const response = await apiFetch(`${apiBase()}/api/v1/users/me/devices/${deviceId}/signing-key`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
    body: JSON.stringify({ signing_public_key: signingPublicKeyBase64 }),
  });
  if (!response.ok) {
    throw new Error('Failed to set this device\'s signing key');
  }
}

/** One prekey to upload: either `{ keyType: "signed", publicKey, signature
 * }` (replaces this device's previous active signed prekey) or `{ keyType:
 * "one_time", publicKey }` (always additive). */
export interface PrekeyUpload {
  keyType: 'signed' | 'one_time';
  publicKey: string;
  signature?: string;
}

/** Uploads one or more prekeys for this device. */
export async function uploadPrekeys(deviceId: string, prekeys: PrekeyUpload[]): Promise<void> {
  const response = await apiFetch(`${apiBase()}/api/v1/users/me/devices/${deviceId}/prekeys`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
    body: JSON.stringify({
      prekeys: prekeys.map((p) => ({ key_type: p.keyType, public_key: p.publicKey, signature: p.signature })),
    }),
  });
  if (!response.ok) {
    throw new Error('Failed to upload prekeys');
  }
}

/** This device's own remaining one-time-prekey count, for the
 * replenishment check in `ratchet.ts`. */
export interface PrekeyCounts {
  unconsumedOneTimePrekeys: number;
  hasSignedPrekey: boolean;
}

export async function fetchPrekeyCounts(deviceId: string): Promise<PrekeyCounts> {
  const response = await apiFetch(`${apiBase()}/api/v1/users/me/devices/${deviceId}/prekeys/count`, {
    headers: getAuthHeaders(),
  });
  if (!response.ok) {
    throw new Error('Failed to fetch this device\'s prekey counts');
  }
  const body = await response.json();
  return { unconsumedOneTimePrekeys: body.unconsumed_one_time_prekeys, hasSignedPrekey: body.has_signed_prekey };
}

/** A device's identity + one-time-use bundle, as needed to bootstrap a
 * brand-new ratchet session with it (the X3DH-style handshake). See
 * `ratchet.ts`'s `bootstrapSessionAsInitiator`. */
export interface PrekeyBundle {
  deviceId: string;
  identityPublicKey: string;
  identitySigningPublicKey: string;
  signedPrekeyPublicKey: string;
  signedPrekeySignature: string;
  oneTimePrekeyId: string | null;
  oneTimePrekeyPublicKey: string | null;
}

/** Thrown when a device hasn't published a signed prekey (or a signing
 * key) yet -- i.e. it hasn't opted into the Double Ratchet. Distinct from a
 * network failure so `ratchet.ts` can fall back to the legacy per-device
 * `crypto.ts` path instead of treating this as "DM sending is broken." */
export class RatchetNotSupportedError extends Error {
  constructor(message = 'This device has not opted into the Double Ratchet yet.') {
    super(message);
    this.name = 'RatchetNotSupportedError';
  }
}

export async function fetchPrekeyBundle(deviceId: string): Promise<PrekeyBundle> {
  const response = await withTimeout(
    apiFetch(`${apiBase()}/api/v1/devices/${deviceId}/prekey-bundle`, {
      headers: getAuthHeaders(),
    }),
    DEVICE_NETWORK_TIMEOUT_MS,
    'Timed out fetching a prekey bundle.'
  );
  if (response.status === 404) {
    throw new RatchetNotSupportedError();
  }
  if (!response.ok) {
    throw new Error('Failed to fetch a prekey bundle');
  }
  const body = await response.json();
  return {
    deviceId: body.device_id,
    identityPublicKey: body.identity_public_key,
    identitySigningPublicKey: body.identity_signing_public_key,
    signedPrekeyPublicKey: body.signed_prekey_public_key,
    signedPrekeySignature: body.signed_prekey_signature,
    oneTimePrekeyId: body.one_time_prekey_id,
    oneTimePrekeyPublicKey: body.one_time_prekey_public_key,
  };
}

/** This device's own encrypted backup of its session with one peer
 * device -- opaque, client-encrypted state plus `updatedAt` for
 * optimistic-concurrency writes. NOT shared with the peer device: see
 * migration 0038's doc comment on why this is a directed, per-owning-
 * device backup rather than a row shared between the two devices in a
 * conversation. See `ratchet.ts`'s `loadSession`/`saveSession`. */
export interface RatchetSessionPickle {
  pickleCiphertext: string;
  pickleNonce: string;
  updatedAt: string;
}

/** Thrown by `fetchRatchetSession` when this device has no backup saved
 * yet for this peer -- distinct from a network failure, so `ratchet.ts`
 * knows to bootstrap a session via `fetchPrekeyBundle` instead of
 * retrying (or, if it already has local session state, that it simply
 * hasn't backed it up yet). */
export class NoRatchetSessionError extends Error {
  constructor(message = 'No ratchet session backup exists yet for this device pair.') {
    super(message);
    this.name = 'NoRatchetSessionError';
  }
}

/** Fetches THIS device's own backup of its session with `peerDeviceId`.
 * `myDeviceId` must be one of the current user's own devices. */
export async function fetchRatchetSession(myDeviceId: string, peerDeviceId: string): Promise<RatchetSessionPickle> {
  const response = await apiFetch(`${apiBase()}/api/v1/ratchet-sessions/${myDeviceId}/${peerDeviceId}`, {
    headers: getAuthHeaders(),
  });
  if (response.status === 404) {
    throw new NoRatchetSessionError();
  }
  if (!response.ok) {
    throw new Error('Failed to fetch ratchet session');
  }
  const body = await response.json();
  return { pickleCiphertext: body.pickle_ciphertext, pickleNonce: body.pickle_nonce, updatedAt: body.updated_at };
}

/** Thrown by `putRatchetSession` when this backup's server-side state has
 * moved on since the caller last read it (a concurrent write from this
 * same device, e.g. two tabs). The caller must re-fetch and reconcile --
 * see `ratchet.rs`'s `put_ratchet_session` doc comment on why this can't
 * be resolved for the caller automatically. */
export class RatchetSessionConflictError extends Error {
  constructor(message = 'This ratchet session backup was updated elsewhere; re-fetch before writing again.') {
    super(message);
    this.name = 'RatchetSessionConflictError';
  }
}

/** Saves THIS device's own backup of its session with `peerDeviceId`.
 * `myDeviceId` must be one of the current user's own devices. */
export async function putRatchetSession(
  myDeviceId: string,
  peerDeviceId: string,
  pickleCiphertext: string,
  pickleNonce: string,
  expectedUpdatedAt: string | null
): Promise<RatchetSessionPickle> {
  const response = await apiFetch(`${apiBase()}/api/v1/ratchet-sessions/${myDeviceId}/${peerDeviceId}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
    body: JSON.stringify({
      pickle_ciphertext: pickleCiphertext,
      pickle_nonce: pickleNonce,
      expected_updated_at: expectedUpdatedAt,
    }),
  });
  if (response.status === 403) {
    throw new RatchetSessionConflictError();
  }
  if (!response.ok) {
    throw new Error('Failed to save ratchet session');
  }
  const body = await response.json();
  return { pickleCiphertext: body.pickle_ciphertext, pickleNonce: body.pickle_nonce, updatedAt: body.updated_at };
}

/** Lists every registered device of every CURRENT member of a channel's
 * server -- what a client needs before composing an encrypted channel
 * send: encrypt once per device in this list (the sending device
 * included, same as `fetchParticipantDevices`). Unlike a DM's fixed pair,
 * this set can be large and grows or shrinks as members join or leave --
 * it's fetched fresh per channel rather than cached. */
export async function fetchChannelMemberDevices(channelId: string): Promise<ParticipantDevice[]> {
  const response = await withTimeout(
    apiFetch(`${apiBase()}/api/v1/channels/${channelId}/member-devices`, {
      headers: getAuthHeaders(),
    }),
    DEVICE_NETWORK_TIMEOUT_MS,
    'Timed out fetching this channel\'s member devices.'
  );
  if (!response.ok) {
    throw new Error('Failed to fetch channel member devices');
  }
  return response.json();
}
