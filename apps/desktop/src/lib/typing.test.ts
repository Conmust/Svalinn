import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const sendMock = vi.fn();
vi.mock('./websocket', () => ({
  wsClient: { send: (...args: unknown[]) => sendMock(...args) },
}));

describe('notifyTypingInChannel / notifyTypingInConversation', () => {
  beforeEach(() => {
    vi.resetModules();
    sendMock.mockClear();
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('sends a typing event for a channel', async () => {
    const { notifyTypingInChannel } = await import('./typing');
    notifyTypingInChannel('chan-1');
    expect(sendMock).toHaveBeenCalledWith('typing', { channel_id: 'chan-1' });
  });

  it('sends a typing event for a conversation', async () => {
    const { notifyTypingInConversation } = await import('./typing');
    notifyTypingInConversation('conv-1');
    expect(sendMock).toHaveBeenCalledWith('typing', { conversation_id: 'conv-1' });
  });

  it('throttles repeated calls for the same channel within the window', async () => {
    const { notifyTypingInChannel } = await import('./typing');
    notifyTypingInChannel('chan-1');
    notifyTypingInChannel('chan-1');
    notifyTypingInChannel('chan-1');
    expect(sendMock).toHaveBeenCalledTimes(1);
  });

  it('sends again once the throttle window has passed', async () => {
    const { notifyTypingInChannel } = await import('./typing');
    notifyTypingInChannel('chan-1');
    vi.advanceTimersByTime(3000);
    notifyTypingInChannel('chan-1');
    expect(sendMock).toHaveBeenCalledTimes(2);
  });

  it('throttles each channel/conversation independently', async () => {
    const { notifyTypingInChannel, notifyTypingInConversation } = await import('./typing');
    notifyTypingInChannel('chan-1');
    notifyTypingInConversation('chan-1'); // same raw id, different kind -- must not share the throttle key
    expect(sendMock).toHaveBeenCalledTimes(2);
  });
});

describe('TypingTracker', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('reports a user as typing once seen', async () => {
    const { TypingTracker } = await import('./typing');
    const tracker = new TypingTracker(() => {});
    tracker.see('user-1');
    expect(tracker.ids()).toEqual(['user-1']);
  });

  it('fires onChange when the set of typers changes', async () => {
    const { TypingTracker } = await import('./typing');
    const onChange = vi.fn();
    const tracker = new TypingTracker(onChange);
    tracker.see('user-1');
    expect(onChange).toHaveBeenCalledTimes(1);
  });

  it('expires a typer after the timeout with no further sighting', async () => {
    const { TypingTracker } = await import('./typing');
    const tracker = new TypingTracker(() => {});
    tracker.see('user-1');
    vi.advanceTimersByTime(6001);
    expect(tracker.ids()).toEqual([]);
  });

  it('resets the timeout on a fresh sighting rather than stacking one', async () => {
    const { TypingTracker } = await import('./typing');
    const tracker = new TypingTracker(() => {});
    tracker.see('user-1');
    vi.advanceTimersByTime(4000);
    tracker.see('user-1'); // refreshes the 6s window
    vi.advanceTimersByTime(4000); // 8s since the first sighting, but only 4s since the second
    expect(tracker.ids()).toEqual(['user-1']);
    vi.advanceTimersByTime(2001);
    expect(tracker.ids()).toEqual([]);
  });

  it('tracks multiple typers independently', async () => {
    const { TypingTracker } = await import('./typing');
    const tracker = new TypingTracker(() => {});
    tracker.see('user-1');
    vi.advanceTimersByTime(3000);
    tracker.see('user-2');
    vi.advanceTimersByTime(3001); // user-1's 6s window has elapsed, user-2's hasn't
    expect(tracker.ids()).toEqual(['user-2']);
  });

  it('clear() removes a typer immediately, e.g. once their message arrives', async () => {
    const { TypingTracker } = await import('./typing');
    const tracker = new TypingTracker(() => {});
    tracker.see('user-1');
    tracker.clear('user-1');
    expect(tracker.ids()).toEqual([]);
  });

  it('clear() on a user not currently typing is a harmless no-op', async () => {
    const { TypingTracker } = await import('./typing');
    const onChange = vi.fn();
    const tracker = new TypingTracker(onChange);
    tracker.clear('nobody');
    expect(onChange).not.toHaveBeenCalled();
  });

  it('reset() clears every current typer at once', async () => {
    const { TypingTracker } = await import('./typing');
    const tracker = new TypingTracker(() => {});
    tracker.see('user-1');
    tracker.see('user-2');
    tracker.reset();
    expect(tracker.ids()).toEqual([]);
  });

  it('destroy() prevents a pending timeout from firing onChange afterward', async () => {
    const { TypingTracker } = await import('./typing');
    const onChange = vi.fn();
    const tracker = new TypingTracker(onChange);
    tracker.see('user-1');
    onChange.mockClear();
    tracker.destroy();
    vi.advanceTimersByTime(7000);
    expect(onChange).not.toHaveBeenCalled();
  });
});
