// Live presence for voice channels -- who's "in" one right now. This is
// groundwork for group voice calls, matching the server's `voice.rs`: it
// tracks membership and nothing else. No audio/video is wired to this yet;
// that depends on whether group calls end up using a mesh of WebRTC peer
// connections (small channels only) or an SFU (media server, for larger
// ones) -- a decision that's still open, see the project's README and the
// PR this shipped in.

import { writable, type Writable } from 'svelte/store';
import { apiFetch, apiBase } from './api';
import { wsClient } from './websocket';

/** channel_id -> user_ids currently present in that voice channel. */
export const voiceParticipants: Writable<Record<string, string[]>> = writable({});

/** The voice channel this device has joined, if any. Presence only --
 * joining doesn't (yet) connect any audio. */
export const myVoiceChannelId: Writable<string | null> = writable(null);

/** Populates `voiceParticipants` for a server's voice channels. Call when a
 * server is opened; live changes after that arrive over the WS. */
export async function fetchVoiceParticipants(serverId: string): Promise<void> {
  try {
    const res = await apiFetch(`${apiBase()}/api/v1/servers/${serverId}/voice-participants`);
    if (!res.ok) return;
    const data: Record<string, string[]> = await res.json();
    voiceParticipants.set(data);
  } catch (e) {
    console.error('Failed to fetch voice channel participants:', e);
  }
}

export async function joinVoiceChannel(channelId: string): Promise<void> {
  const res = await apiFetch(`${apiBase()}/api/v1/channels/${channelId}/voice/join`, { method: 'POST' });
  if (res.ok) myVoiceChannelId.set(channelId);
}

export async function leaveVoiceChannel(channelId: string): Promise<void> {
  await apiFetch(`${apiBase()}/api/v1/channels/${channelId}/voice/leave`, { method: 'POST' });
  myVoiceChannelId.update((id) => (id === channelId ? null : id));
}

function onVoiceChannelJoined(data: { channel_id: string; participants: string[] }) {
  voiceParticipants.update((map) => ({ ...map, [data.channel_id]: data.participants }));
}

function onVoiceChannelLeft(data: { channel_id: string; user_id: string }) {
  voiceParticipants.update((map) => {
    const current = map[data.channel_id];
    if (!current) return map;
    const next = current.filter((id) => id !== data.user_id);
    const updated = { ...map };
    if (next.length > 0) {
      updated[data.channel_id] = next;
    } else {
      delete updated[data.channel_id];
    }
    return updated;
  });
}

let signalingInitialized = false;

/** Wires up the WS listeners that keep `voiceParticipants` live. Call once
 * -- `wsClient.on` just adds listeners, so a second call would double them
 * up (same pattern as `initCallSignaling` in `lib/calls.ts`, but guarded
 * explicitly here since this one's plausible to call from more than one
 * place as the feature grows). */
export function initVoiceChannelSignaling() {
  if (signalingInitialized) return;
  signalingInitialized = true;
  wsClient.on('voice_channel_joined', onVoiceChannelJoined);
  wsClient.on('voice_channel_left', onVoiceChannelLeft);
}
