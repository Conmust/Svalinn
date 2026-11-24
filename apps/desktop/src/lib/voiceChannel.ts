// Multi-person voice channels: everyone currently in a channel forms a full
// mesh of WebRTC connections with everyone else in it (unlike `calls.ts`'s
// 1:1 calls, which are exactly one peer connection). Signaling rides the
// same authenticated WebSocket as those calls, under separate "voice-*"
// event names so the two don't interfere (see `routes/ws.rs`); who's
// currently in which channel is tracked server-side too, so a client
// reconnecting or opening the channel list for the first time can learn the
// roster without having seen every join/leave event live (`routes/voice.rs`).
//
// Scope, same caveat as `calls.ts`: a mesh stops scaling past a handful of
// participants. Fine for the small servers this app targets; a channel that
// regularly gets crowded would need a real SFU instead.

import { writable, type Writable } from 'svelte/store';
import { apiFetch, apiBase } from './api';
import { wsClient } from './websocket';
import { getCurrentUser } from './auth';

export interface VoiceParticipant {
  userId: string;
  username: string;
  muted: boolean;
  /** True while audio from this participant is actively above the noise floor. */
  speaking: boolean;
}

export type VoiceChannelStatus = 'idle' | 'connecting' | 'connected';

export interface VoiceChannelState {
  status: VoiceChannelStatus;
  channelId: string | null;
  channelName: string | null;
  serverId: string | null;
  error: string | null;
}

const initialState: VoiceChannelState = {
  status: 'idle',
  channelId: null,
  channelName: null,
  serverId: null,
  error: null,
};

/** The voice channel I'm currently connected to, if any. */
export const voiceChannelState: Writable<VoiceChannelState> = writable(initialState);
/** Other participants of the channel I'm connected to, keyed by user id. */
export const voiceParticipants: Writable<Map<string, VoiceParticipant>> = writable(new Map());
export const myVoiceMuted: Writable<boolean> = writable(false);
export const myVoiceDeafened: Writable<boolean> = writable(false);

/**
 * Who's in each voice channel of the currently-open server, whether or not
 * I've joined any of them -- for the channel list's participant previews.
 * Keyed by channel id; a channel with nobody in it just isn't a key here.
 */
export const voiceRosters: Writable<Map<string, VoiceParticipant[]>> = writable(new Map());

let currentState: VoiceChannelState = initialState;
voiceChannelState.subscribe((s) => (currentState = s));
let mutedNow = false;
myVoiceMuted.subscribe((m) => (mutedNow = m));
let deafenedNow = false;
myVoiceDeafened.subscribe((d) => (deafenedNow = d));

let localMedia: MediaStream | null = null;
const peerConnections = new Map<string, RTCPeerConnection>();
const remoteAudioEls = new Map<string, HTMLAudioElement>();
const pendingCandidates = new Map<string, RTCIceCandidateInit[]>();
const speakingAnalysers = new Map<string, { ctx: AudioContext; raf: number }>();

async function getIceServers(): Promise<RTCIceServer[]> {
  try {
    const res = await apiFetch(`${apiBase()}/api/v1/calls/turn-credentials`);
    if (!res.ok) throw new Error(`${res.status}`);
    const data = await res.json();
    return data.ice_servers ?? [];
  } catch (e) {
    console.error('Failed to fetch TURN credentials, falling back to STUN only:', e);
    return [{ urls: 'stun:stun.l.google.com:19302' }];
  }
}

function sendSignal(type: string, channelId: string, toUser: string, payload: Record<string, unknown> = {}) {
  wsClient.send(type, { ...payload, channel_id: channelId, to_user: toUser });
}

function updateParticipant(userId: string, patch: Partial<VoiceParticipant>) {
  voiceParticipants.update((map) => {
    const existing = map.get(userId);
    if (!existing) return map;
    map.set(userId, { ...existing, ...patch });
    return new Map(map);
  });
}

/** Watches a remote stream's audio level and flips `speaking` while it's talking. */
function watchSpeaking(userId: string, stream: MediaStream) {
  stopWatchingSpeaking(userId);
  if (stream.getAudioTracks().length === 0) return;

  try {
    const ctx = new AudioContext();
    const source = ctx.createMediaStreamSource(stream);
    const analyser = ctx.createAnalyser();
    analyser.fftSize = 512;
    source.connect(analyser);
    const data = new Uint8Array(analyser.frequencyBinCount);

    let speaking = false;
    const tick = () => {
      analyser.getByteFrequencyData(data);
      const level = data.reduce((sum, v) => sum + v, 0) / data.length;
      const now = level > 12; // empirical noise floor; not meant to be precise
      if (now !== speaking) {
        speaking = now;
        updateParticipant(userId, { speaking });
      }
      const raf = requestAnimationFrame(tick);
      const entry = speakingAnalysers.get(userId);
      if (entry) entry.raf = raf;
    };
    const raf = requestAnimationFrame(tick);
    speakingAnalysers.set(userId, { ctx, raf });
  } catch (e) {
    console.error('Failed to set up speaking detection:', e);
  }
}

function stopWatchingSpeaking(userId: string) {
  const entry = speakingAnalysers.get(userId);
  if (entry) {
    cancelAnimationFrame(entry.raf);
    entry.ctx.close().catch(() => {});
    speakingAnalysers.delete(userId);
  }
}

function teardownPeer(userId: string) {
  const pc = peerConnections.get(userId);
  if (pc) {
    pc.onicecandidate = null;
    pc.ontrack = null;
    pc.onconnectionstatechange = null;
    pc.close();
    peerConnections.delete(userId);
  }
  pendingCandidates.delete(userId);
  stopWatchingSpeaking(userId);
  const audioEl = remoteAudioEls.get(userId);
  if (audioEl) {
    audioEl.srcObject = null;
    audioEl.remove();
    remoteAudioEls.delete(userId);
  }
}

function attachRemoteStream(userId: string, stream: MediaStream) {
  let audioEl = remoteAudioEls.get(userId);
  if (!audioEl) {
    audioEl = new Audio();
    audioEl.autoplay = true;
    remoteAudioEls.set(userId, audioEl);
  }
  audioEl.srcObject = stream;
  audioEl.muted = deafenedNow;
  watchSpeaking(userId, stream);
}

async function createPeerConnection(channelId: string, peerId: string): Promise<RTCPeerConnection> {
  const iceServers = await getIceServers();
  const pc = new RTCPeerConnection({ iceServers });

  if (localMedia) {
    localMedia.getTracks().forEach((track) => pc.addTrack(track, localMedia!));
  }

  pc.onicecandidate = (event) => {
    if (event.candidate) {
      sendSignal('voice-ice-candidate', channelId, peerId, { candidate: event.candidate.toJSON() });
    }
  };

  pc.ontrack = (event) => {
    const stream = event.streams[0];
    if (stream) attachRemoteStream(peerId, stream);
  };

  pc.onconnectionstatechange = () => {
    if (pc.connectionState === 'failed' || pc.connectionState === 'closed') {
      teardownPeer(peerId);
    }
  };

  peerConnections.set(peerId, pc);
  return pc;
}

/** Offers a connection to a peer already in the channel (called for every
 * existing participant right after joining -- see `joinVoiceChannel`). */
async function offerTo(channelId: string, peerId: string) {
  const pc = await createPeerConnection(channelId, peerId);
  const offer = await pc.createOffer();
  await pc.setLocalDescription(offer);
  sendSignal('voice-offer', channelId, peerId, { sdp: offer });
}

function resetLocalMedia() {
  localMedia?.getTracks().forEach((t) => t.stop());
  localMedia = null;
}

/** Joins a voice channel, leaving whichever one (if any) I was already in. */
export async function joinVoiceChannel(channelId: string, channelName: string, serverId: string) {
  if (currentState.channelId === channelId && currentState.status !== 'idle') return; // already here
  if (currentState.channelId) await leaveVoiceChannel();

  voiceChannelState.set({ status: 'connecting', channelId, channelName, serverId, error: null });
  voiceParticipants.set(new Map());

  try {
    localMedia = await navigator.mediaDevices.getUserMedia({ audio: true, video: false });
    localMedia.getAudioTracks().forEach((t) => (t.enabled = !mutedNow));

    const res = await apiFetch(`${apiBase()}/api/v1/channels/${channelId}/voice/join`, { method: 'POST' });
    if (!res.ok) throw new Error('Failed to join voice channel');
    const existing: { user_id: string; username: string; muted: boolean }[] = await res.json();

    const participants = new Map<string, VoiceParticipant>();
    for (const p of existing) {
      participants.set(p.user_id, { userId: p.user_id, username: p.username, muted: p.muted, speaking: false });
    }
    voiceParticipants.set(participants);

    // I'm the one joining, so I offer to everyone already there -- they
    // just wait for my offer (see `initVoiceSignaling`'s 'voice-offer'
    // handler), so there's no chance of both sides offering at once.
    await Promise.all(existing.map((p) => offerTo(channelId, p.user_id)));

    voiceChannelState.update((s) => (s.channelId === channelId ? { ...s, status: 'connected' } : s));
  } catch (e) {
    console.error('Failed to join voice channel:', e);
    const message =
      e instanceof DOMException && (e.name === 'NotAllowedError' || e.name === 'PermissionDeniedError')
        ? 'Microphone permission denied'
        : e instanceof DOMException && e.name === 'NotFoundError'
          ? 'No microphone found'
          : 'Could not join voice channel';
    resetLocalMedia();
    voiceChannelState.set({ ...initialState, error: message });
  }
}

/** Leaves the voice channel I'm currently in, if any. */
export async function leaveVoiceChannel() {
  const { channelId } = currentState;
  if (!channelId) return;

  for (const userId of [...peerConnections.keys()]) teardownPeer(userId);
  resetLocalMedia();
  voiceParticipants.set(new Map());
  voiceChannelState.set(initialState);

  try {
    await apiFetch(`${apiBase()}/api/v1/channels/${channelId}/voice/leave`, { method: 'POST' });
  } catch (e) {
    console.error('Failed to notify server of voice channel leave:', e);
  }
}

export function toggleVoiceMic() {
  if (!localMedia || !currentState.channelId) return;
  const audioTrack = localMedia.getAudioTracks()[0];
  if (!audioTrack) return;
  audioTrack.enabled = !audioTrack.enabled;
  const muted = !audioTrack.enabled;
  myVoiceMuted.set(muted);

  apiFetch(`${apiBase()}/api/v1/channels/${currentState.channelId}/voice/state`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ muted }),
  }).catch((e) => console.error('Failed to broadcast mute state:', e));
}

/** Deafening also mutes the mic, same as Discord -- hard to claim you can't
 * hear anyone while still talking at them. */
export function toggleVoiceDeafen() {
  const deafened = !deafenedNow;
  myVoiceDeafened.set(deafened);
  remoteAudioEls.forEach((el) => (el.muted = deafened));
  if (deafened && !mutedNow) toggleVoiceMic();
}

/** Loads the roster of every voice channel in a server, e.g. when the
 * channel list mounts/switches servers. Kept fresh afterward by the
 * 'voice_participant_joined'/'left' WS events below. */
export async function loadVoiceRosters(serverId: string) {
  try {
    const res = await apiFetch(`${apiBase()}/api/v1/servers/${serverId}/voice-rosters`);
    if (!res.ok) return;
    const data: Record<string, { user_id: string; username: string; muted: boolean }[]> = await res.json();
    const rosters = new Map<string, VoiceParticipant[]>();
    for (const [channelId, participants] of Object.entries(data)) {
      rosters.set(
        channelId,
        participants.map((p) => ({ userId: p.user_id, username: p.username, muted: p.muted, speaking: false })),
      );
    }
    voiceRosters.set(rosters);
  } catch (e) {
    console.error('Failed to load voice rosters:', e);
  }
}

function addToRoster(channelId: string, participant: VoiceParticipant) {
  voiceRosters.update((map) => {
    const roster = (map.get(channelId) ?? []).filter((p) => p.userId !== participant.userId);
    roster.push(participant);
    map.set(channelId, roster);
    return new Map(map);
  });
}

function removeFromRoster(channelId: string, userId: string) {
  voiceRosters.update((map) => {
    const roster = (map.get(channelId) ?? []).filter((p) => p.userId !== userId);
    if (roster.length > 0) map.set(channelId, roster);
    else map.delete(channelId);
    return new Map(map);
  });
}

let signalingInitialized = false;

/** Wires up the WS listeners. Call once, e.g. from App.svelte on mount. */
export function initVoiceSignaling() {
  if (signalingInitialized) return;
  signalingInitialized = true;

  // Looked up fresh on every event rather than once here: this is wired up
  // from App.svelte's top-level script, which can run before login (no
  // stored user yet), so caching it at this point could permanently miss.
  const isMe = (userId: string) => userId === getCurrentUser()?.id;

  wsClient.on(
    'voice_participant_joined',
    (data: { channel_id: string; user_id: string; username: string; muted: boolean }) => {
      addToRoster(data.channel_id, { userId: data.user_id, username: data.username, muted: data.muted, speaking: false });
      // My own join already populated `voiceParticipants` locally with the
      // *other* participants (see `joinVoiceChannel`) -- nothing more to do.
      if (isMe(data.user_id)) return;
      if (currentState.channelId === data.channel_id) {
        voiceParticipants.update((map) => {
          map.set(data.user_id, { userId: data.user_id, username: data.username, muted: data.muted, speaking: false });
          return new Map(map);
        });
        // They're the one who just joined, so they'll offer to me -- I
        // just wait for 'voice-offer' and answer it below.
      }
    },
  );

  wsClient.on('voice_participant_left', (data: { channel_id: string; user_id: string }) => {
    removeFromRoster(data.channel_id, data.user_id);
    if (isMe(data.user_id)) return;
    if (currentState.channelId === data.channel_id) {
      teardownPeer(data.user_id);
      voiceParticipants.update((map) => {
        map.delete(data.user_id);
        return new Map(map);
      });
    }
  });

  wsClient.on('voice_state_updated', (data: { channel_id: string; user_id: string; muted: boolean }) => {
    voiceRosters.update((map) => {
      const roster = map.get(data.channel_id);
      if (roster) map.set(data.channel_id, roster.map((p) => (p.userId === data.user_id ? { ...p, muted: data.muted } : p)));
      return new Map(map);
    });
    if (currentState.channelId === data.channel_id) updateParticipant(data.user_id, { muted: data.muted });
  });

  wsClient.on('voice-offer', async (data: { from_user: string; channel_id: string; sdp: RTCSessionDescriptionInit }) => {
    if (data.channel_id !== currentState.channelId) return; // stale/unrelated channel
    const pc = peerConnections.get(data.from_user) ?? (await createPeerConnection(data.channel_id, data.from_user));
    await pc.setRemoteDescription(new RTCSessionDescription(data.sdp));
    for (const candidate of pendingCandidates.get(data.from_user) ?? []) {
      await pc.addIceCandidate(new RTCIceCandidate(candidate));
    }
    pendingCandidates.delete(data.from_user);

    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);
    sendSignal('voice-answer', data.channel_id, data.from_user, { sdp: answer });
  });

  wsClient.on('voice-answer', async (data: { from_user: string; channel_id: string; sdp: RTCSessionDescriptionInit }) => {
    const pc = peerConnections.get(data.from_user);
    if (!pc) return;
    await pc.setRemoteDescription(new RTCSessionDescription(data.sdp));
    for (const candidate of pendingCandidates.get(data.from_user) ?? []) {
      await pc.addIceCandidate(new RTCIceCandidate(candidate));
    }
    pendingCandidates.delete(data.from_user);
  });

  wsClient.on('voice-ice-candidate', async (data: { from_user: string; candidate: RTCIceCandidateInit }) => {
    const pc = peerConnections.get(data.from_user);
    if (pc && pc.remoteDescription) {
      await pc.addIceCandidate(new RTCIceCandidate(data.candidate));
    } else {
      const queued = pendingCandidates.get(data.from_user) ?? [];
      queued.push(data.candidate);
      pendingCandidates.set(data.from_user, queued);
    }
  });
}
