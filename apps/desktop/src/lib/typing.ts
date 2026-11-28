// "Someone is typing..." indicators, for both channels and DMs.
//
// This is NOT end-to-end encrypted, and deliberately never carries any
// message content -- just "this user id is typing in this channel/
// conversation id right now". Unlike a message's content, that fact isn't
// something this app's threat model protects: the server already knows
// who's a member of which channel and conversation, so it learning "this
// member is composing something" right now reveals nothing it doesn't
// already know the shape of. See `routes/ws.rs::handle_typing` for the
// server side and its own scoping (a typing indicator reaches the exact
// same audience a real message to that channel/conversation would).
//
// There's no explicit "stopped typing" event. The sender just resends
// "typing" every few seconds while the user is actively composing
// (throttled below), and the receiver times a given sender out on its own
// after a few seconds of silence (`TypingTracker` below) -- so a sender
// whose tab closes, loses connection, or sends the message (and so stops
// typing) never leaves a stuck "is typing" indicator on someone else's
// screen waiting for an event that will never come.
import { wsClient } from './websocket';

/** How often a single composer resends "typing" while the user keeps
 * typing. Throttled, not debounced -- the point is a steady heartbeat
 * while composing continues, not a single event after a pause. */
const SEND_THROTTLE_MS = 2500;

/** How long a received "typing" is shown before `TypingTracker` treats it
 * as stale. Comfortably longer than `SEND_THROTTLE_MS` so normal
 * resending never causes a visible flicker between two different
 * "typing..." renders. */
const RECEIVE_TIMEOUT_MS = 6000;

const lastSentAt = new Map<string, number>();

/** Internal: throttled per `key` (one channel or conversation id), so a
 * caller can call this on every keystroke without flooding the socket. */
function notifyTyping(payload: Record<string, string>, key: string): void {
  const now = Date.now();
  if (now - (lastSentAt.get(key) ?? 0) < SEND_THROTTLE_MS) return;
  lastSentAt.set(key, now);
  wsClient.send('typing', payload);
}

export function notifyTypingInChannel(channelId: string): void {
  notifyTyping({ channel_id: channelId }, `channel:${channelId}`);
}

export function notifyTypingInConversation(conversationId: string): void {
  notifyTyping({ conversation_id: conversationId }, `conversation:${conversationId}`);
}

/** Tracks who's currently typing (in one channel or conversation -- the
 * caller owns one instance per open chat pane), expiring each sender on
 * its own after `RECEIVE_TIMEOUT_MS` of silence. `onChange` fires
 * whenever the current set of typing user ids changes, so a Svelte
 * component can just re-read `ids()` into reactive state from it rather
 * than polling. */
export class TypingTracker {
  private timeouts = new Map<string, ReturnType<typeof setTimeout>>();
  private onChange: () => void;

  constructor(onChange: () => void) {
    this.onChange = onChange;
  }

  /** Call whenever a `typing` event for this userId arrives (already
   * filtered by the caller to the right channel/conversation and to not
   * be this device's own user). Resets that user's timeout rather than
   * stacking a new one. */
  see(userId: string): void {
    const existing = this.timeouts.get(userId);
    if (existing) clearTimeout(existing);
    this.timeouts.set(
      userId,
      setTimeout(() => {
        this.timeouts.delete(userId);
        this.onChange();
      }, RECEIVE_TIMEOUT_MS)
    );
    this.onChange();
  }

  /** Call when a user's own message actually arrives -- no reason to keep
   * showing "typing..." for someone who just finished sending. */
  clear(userId: string): void {
    const existing = this.timeouts.get(userId);
    if (!existing) return;
    clearTimeout(existing);
    this.timeouts.delete(userId);
    this.onChange();
  }

  /** Call on switching to a different channel/conversation -- a typer in
   * the one just left isn't typing in the new one. */
  reset(): void {
    if (this.timeouts.size === 0) return;
    for (const handle of this.timeouts.values()) clearTimeout(handle);
    this.timeouts.clear();
    this.onChange();
  }

  ids(): string[] {
    return [...this.timeouts.keys()];
  }

  /** Call from the component's `onDestroy`, so a pending timeout doesn't
   * fire (and call `onChange` into a torn-down component) after it's gone. */
  destroy(): void {
    for (const handle of this.timeouts.values()) clearTimeout(handle);
    this.timeouts.clear();
  }
}
