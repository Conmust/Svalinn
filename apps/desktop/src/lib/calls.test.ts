// Regression test for a 1:1 call-signaling authorization gap: the server's
// own relay check (`relay_dm_signal` in `routes/ws.rs`) only verifies that
// the sender and recipient of a call-signaling event share SOME DM
// conversation -- it has no notion of "who's actually in a call with
// whom" to check against. Without a client-side check scoping each event
// to the CURRENT call's actual peer, any of a user's DM contacts (not just
// the one they're calling) could forge a `call-hangup`/`call-reject`/
// `call-busy`/`call-cancel` to kill an unrelated ongoing call -- a trivial
// griefing/DoS vector -- or race a forged `webrtc-answer`/`ice-candidate`
// against the real peer's to disrupt or hijack the WebRTC negotiation.
//
// `from_user` itself is trustworthy here (the server stamps it server-side
// from the authenticated sender, see `relay_dm_signal`'s own comment), so
// this test exercises the events that need no WebRTC/media access to
// verify (`call-accept`/`call-reject`/`call-busy`/`call-cancel`/
// `call-hangup`) by simulating them via `wsClient.emit`, which delivers to
// local listeners exactly as a real relayed server message would.
import { describe, expect, it, beforeEach } from 'vitest';
import { wsClient } from './websocket';
import { callState, initCallSignaling } from './calls';

function snapshot() {
  let value: any;
  callState.subscribe((s) => (value = s))();
  return value;
}

describe('call signaling is scoped to the actual call peer', () => {
  beforeEach(() => {
    // Fresh listener set and fresh state for each test.
    (wsClient as unknown as { listeners: Map<string, Set<unknown>> }).listeners = new Map();
    initCallSignaling();
    callState.set({ status: 'idle', peerId: null, peerUsername: null, withVideo: true, endReason: null });
  });

  it('ignores a call-hangup from someone other than the current peer', () => {
    wsClient.emit('call-invite', { from_user: 'bob', with_video: false, from_username: 'Bob' });
    expect(snapshot()).toMatchObject({ status: 'incoming', peerId: 'bob' });

    // Eve shares a DM with us (so the server would relay this) but isn't
    // who this call is with.
    wsClient.emit('call-hangup', { from_user: 'eve' });
    expect(snapshot()).toMatchObject({ status: 'incoming', peerId: 'bob' });

    // The real peer can still end it.
    wsClient.emit('call-hangup', { from_user: 'bob' });
    expect(snapshot().status).toBe('ended');
  });

  it('ignores a call-reject/call-busy/call-cancel from a non-peer', () => {
    wsClient.emit('call-invite', { from_user: 'bob', with_video: false, from_username: 'Bob' });

    wsClient.emit('call-reject', { from_user: 'eve', reason: 'nope' });
    expect(snapshot()).toMatchObject({ status: 'incoming', peerId: 'bob' });

    wsClient.emit('call-busy', { from_user: 'eve' });
    expect(snapshot()).toMatchObject({ status: 'incoming', peerId: 'bob' });

    wsClient.emit('call-cancel', { from_user: 'eve' });
    expect(snapshot()).toMatchObject({ status: 'incoming', peerId: 'bob' });
  });

  it('ignores a call-accept from a non-peer', () => {
    callState.set({ status: 'outgoing', peerId: 'bob', peerUsername: 'Bob', withVideo: false, endReason: null });

    wsClient.emit('call-accept', { from_user: 'eve' });
    expect(snapshot().status).toBe('outgoing');

    wsClient.emit('call-accept', { from_user: 'bob' });
    expect(snapshot().status).toBe('connecting');
  });
});
