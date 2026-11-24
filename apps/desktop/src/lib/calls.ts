// 1:1 voice/video calls over plain peer-to-peer WebRTC. Signaling (who's
// calling whom, the offer/answer/ICE exchange) rides the existing
// authenticated WebSocket (see `wsClient` in `websocket.ts` and the relay in
// the server's `routes/ws.rs`); only the already-encrypted media itself
// flows browser-to-browser (or through the TURN relay as a fallback -- see
// `routes/calls.rs` for how its credentials are minted).
//
// Scope is deliberately 1:1 only: a mesh of peer connections stops scaling
// past a handful of participants, so group calls would need a media server
// (SFU) instead -- a separate, much bigger piece of work.

import { writable, type Writable } from 'svelte/store';
import { apiFetch, apiBase } from './api';
import { wsClient } from './websocket';
import { getCurrentUser } from './auth';

export type CallStatus =
  | 'idle'
  | 'outgoing' // we called someone, waiting for them to answer
  | 'incoming' // someone is calling us, waiting for us to answer
  | 'connecting' // answered, WebRTC is negotiating
  | 'connected'
  | 'ended';

export interface CallState {
  status: CallStatus;
  peerId: string | null;
  peerUsername: string | null;
  withVideo: boolean;
  /** Why the call ended, shown briefly before the overlay clears itself. */
  endReason: string | null;
}

const initialState: CallState = {
  status: 'idle',
  peerId: null,
  peerUsername: null,
  withVideo: true,
  endReason: null,
};

export const callState: Writable<CallState> = writable(initialState);
export const localStream: Writable<MediaStream | null> = writable(null);
export const remoteStream: Writable<MediaStream | null> = writable(null);
export const micMuted: Writable<boolean> = writable(false);
export const cameraOff: Writable<boolean> = writable(false);

let pc: RTCPeerConnection | null = null;
let localMedia: MediaStream | null = null;
// Buffers ICE candidates that arrive before the remote description is set
// (they can race the offer/answer over the WS).
let pendingCandidates: RTCIceCandidateInit[] = [];
let callTimeout: ReturnType<typeof setTimeout> | null = null;

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

function resetLocalMedia() {
  localMedia?.getTracks().forEach((t) => t.stop());
  localMedia = null;
  localStream.set(null);
}

function teardownPeerConnection() {
  if (pc) {
    pc.onicecandidate = null;
    pc.ontrack = null;
    pc.onconnectionstatechange = null;
    pc.close();
    pc = null;
  }
  pendingCandidates = [];
  remoteStream.set(null);
}

function clearCallTimeout() {
  if (callTimeout) {
    clearTimeout(callTimeout);
    callTimeout = null;
  }
}

function endCall(reason: string | null) {
  clearCallTimeout();
  teardownPeerConnection();
  resetLocalMedia();
  micMuted.set(false);
  cameraOff.set(false);
  callState.update((s) => ({ ...s, status: 'ended', endReason: reason }));
  // Give the UI a moment to show the end reason, then fully reset.
  setTimeout(() => {
    callState.update((s) => (s.status === 'ended' ? { ...initialState } : s));
  }, 2500);
}

function sendSignal(type: string, toUser: string, payload: Record<string, unknown> = {}) {
  wsClient.send(type, { ...payload, to_user: toUser });
}

async function createPeerConnection(peerId: string): Promise<RTCPeerConnection> {
  const iceServers = await getIceServers();
  const connection = new RTCPeerConnection({ iceServers });

  connection.onicecandidate = (event) => {
    if (event.candidate) {
      sendSignal('ice-candidate', peerId, { candidate: event.candidate.toJSON() });
    }
  };

  connection.ontrack = (event) => {
    remoteStream.set(event.streams[0] ?? null);
  };

  connection.onconnectionstatechange = () => {
    if (connection.connectionState === 'connected') {
      clearCallTimeout();
      callState.update((s) => ({ ...s, status: 'connected' }));
    } else if (connection.connectionState === 'failed' || connection.connectionState === 'closed') {
      endCall('Call disconnected');
    }
  };

  return connection;
}

async function acquireLocalMedia(withVideo: boolean): Promise<MediaStream> {
  const stream = await navigator.mediaDevices.getUserMedia({
    audio: true,
    video: withVideo,
  });
  localMedia = stream;
  localStream.set(stream);
  return stream;
}

/** Starts an outgoing call. `peerUsername` is just for display. */
export async function startCall(peerId: string, peerUsername: string, withVideo: boolean) {
  let current: CallState = initialState;
  callState.subscribe((s) => (current = s))();
  if (current.status !== 'idle' && current.status !== 'ended') return; // already in/starting a call

  callState.set({ status: 'outgoing', peerId, peerUsername, withVideo, endReason: null });

  try {
    const stream = await acquireLocalMedia(withVideo);
    pc = await createPeerConnection(peerId);
    stream.getTracks().forEach((track) => pc!.addTrack(track, stream));

    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    sendSignal('call-invite', peerId, {
      with_video: withVideo,
      from_username: getCurrentUser()?.username ?? '',
    });
    sendSignal('webrtc-offer', peerId, { sdp: offer });

    // Give up if nobody answers.
    callTimeout = setTimeout(() => {
      sendSignal('call-cancel', peerId);
      endCall('No answer');
    }, 45000);
  } catch (e) {
    console.error('Failed to start call:', e);
    endCall(mediaErrorMessage(e));
  }
}

/** Accepts the current incoming call. */
export async function acceptCall() {
  let current: CallState = initialState;
  callState.subscribe((s) => (current = s))();
  if (current.status !== 'incoming' || !current.peerId) return;

  clearCallTimeout();
  callState.update((s) => ({ ...s, status: 'connecting' }));

  try {
    const stream = await acquireLocalMedia(current.withVideo);
    pc = await createPeerConnection(current.peerId);
    stream.getTracks().forEach((track) => pc!.addTrack(track, stream));

    if (pendingOffer) {
      await pc.setRemoteDescription(new RTCSessionDescription(pendingOffer));
      pendingOffer = null;
      for (const candidate of pendingCandidates) {
        await pc.addIceCandidate(new RTCIceCandidate(candidate));
      }
      pendingCandidates = [];

      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);
      sendSignal('call-accept', current.peerId);
      sendSignal('webrtc-answer', current.peerId, { sdp: answer });
    }
  } catch (e) {
    console.error('Failed to accept call:', e);
    const reason = mediaErrorMessage(e);
    // Distinguish "couldn't accept" from an actual decline so the caller
    // sees why the call ended instead of being told it was declined.
    if (current.peerId) sendSignal('call-reject', current.peerId, { reason });
    endCall(reason);
  }
}

/** Rejects/hangs up the current call, whatever state it's in. */
export function rejectOrHangUp() {
  let current: CallState = initialState;
  callState.subscribe((s) => (current = s))();
  if (!current.peerId) return;

  if (current.status === 'incoming') {
    sendSignal('call-reject', current.peerId);
    endCall(null);
  } else if (current.status === 'outgoing') {
    sendSignal('call-cancel', current.peerId);
    endCall(null);
  } else {
    sendSignal('call-hangup', current.peerId);
    endCall(null);
  }
}

export function toggleMic() {
  if (!localMedia) return;
  const audioTrack = localMedia.getAudioTracks()[0];
  if (!audioTrack) return;
  audioTrack.enabled = !audioTrack.enabled;
  micMuted.set(!audioTrack.enabled);
}

export function toggleCamera() {
  if (!localMedia) return;
  const videoTrack = localMedia.getVideoTracks()[0];
  if (!videoTrack) return;
  videoTrack.enabled = !videoTrack.enabled;
  cameraOff.set(!videoTrack.enabled);
}

function mediaErrorMessage(e: unknown): string {
  if (e instanceof DOMException && (e.name === 'NotAllowedError' || e.name === 'PermissionDeniedError')) {
    return 'Camera/microphone permission denied';
  }
  if (e instanceof DOMException && e.name === 'NotFoundError') {
    return 'No camera/microphone found';
  }
  if (e instanceof DOMException && e.name === 'NotReadableError') {
    // Thrown when the camera/mic is already claimed by another
    // application or browser tab -- common when testing two accounts on
    // one machine, which only has one camera between them.
    return 'Camera/microphone already in use elsewhere';
  }
  return 'Call failed';
}

// Buffers the remote offer until the user accepts (we don't want to touch
// media devices before that).
let pendingOffer: RTCSessionDescriptionInit | null = null;

/** Wires up the WS listeners. Call once, e.g. from App.svelte on mount. */
export function initCallSignaling() {
  wsClient.on('call-invite', (data: { from_user: string; with_video: boolean; from_username?: string }) => {
    let current: CallState = initialState;
    callState.subscribe((s) => (current = s))();
    // Already on a call: let the caller know we're busy instead of silently dropping it.
    if (current.status !== 'idle' && current.status !== 'ended') {
      sendSignal('call-busy', data.from_user);
      return;
    }
    callState.set({
      status: 'incoming',
      peerId: data.from_user,
      peerUsername: data.from_username || 'Someone',
      withVideo: data.with_video,
      endReason: null,
    });
    callTimeout = setTimeout(() => endCall('Missed call'), 45000);
  });

  wsClient.on('webrtc-offer', (data: { from_user: string; sdp: RTCSessionDescriptionInit }) => {
    pendingOffer = data.sdp;
  });

  wsClient.on('webrtc-answer', async (data: { from_user: string; sdp: RTCSessionDescriptionInit }) => {
    if (!pc) return;
    await pc.setRemoteDescription(new RTCSessionDescription(data.sdp));
    for (const candidate of pendingCandidates) {
      await pc.addIceCandidate(new RTCIceCandidate(candidate));
    }
    pendingCandidates = [];
  });

  wsClient.on('ice-candidate', async (data: { from_user: string; candidate: RTCIceCandidateInit }) => {
    if (pc && pc.remoteDescription) {
      await pc.addIceCandidate(new RTCIceCandidate(data.candidate));
    } else {
      pendingCandidates.push(data.candidate);
    }
  });

  wsClient.on('call-accept', () => {
    callState.update((s) => ({ ...s, status: 'connecting' }));
  });

  wsClient.on('call-reject', (data: { reason?: string }) => endCall(data?.reason || 'Call declined'));
  wsClient.on('call-busy', () => endCall('User is busy'));
  wsClient.on('call-cancel', () => endCall('Call cancelled'));
  wsClient.on('call-hangup', () => endCall(null));
}
