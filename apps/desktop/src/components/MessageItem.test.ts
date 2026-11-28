// @vitest-environment happy-dom
//
// Component-level test for the attachment-evicted notice added alongside
// the server's attachment-storage-quota eviction (see messages.ts's
// `attachment_evicted` doc comment). This is a presentational, prop-only
// component with no onMount network/crypto work, so it's mountable
// directly -- unlike ChatArea.svelte/DMChatArea.svelte, which fan out to
// ~10 modules (websocket, crypto, ratchet, device setup, ...) on mount
// and would need a correspondingly large mock surface to render at all.
import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen } from '@testing-library/svelte';
import MessageItem from './MessageItem.svelte';
import type { Message } from '../lib/messages';

// @testing-library/svelte normally registers this itself, but only when
// beforeEach/afterEach are true globals (vitest's `test.globals` option,
// which this project doesn't enable -- every other test file here imports
// them from 'vitest' explicitly instead). Without this, each render leaks
// into the next test's DOM.
afterEach(() => cleanup());

function baseMessage(overrides: Partial<Message> = {}): Message {
  return {
    id: 'msg-1',
    channel_id: 'channel-1',
    user_id: 'user-1',
    username: 'alice',
    content: 'hello world',
    created_at: new Date().toISOString(),
    is_edited: false,
    updated_at: null,
    is_locked: false,
    is_encrypted: false,
    ...overrides,
  };
}

describe('MessageItem attachment-evicted notice', () => {
  it('shows the eviction notice instead of an attachment when attachment_evicted is set', () => {
    render(MessageItem, {
      props: {
        message: baseMessage({ attachment_url: null, attachment_evicted: true }),
      },
    });

    expect(screen.getByText(/Attachment removed to free up server storage space/)).toBeTruthy();
  });

  it('shows the real attachment, not the eviction notice, when attachment_url is present', () => {
    render(MessageItem, {
      props: {
        message: baseMessage({
          attachment_url: '/files/some-attachment.png',
          attachment_mime_type: 'image/png',
          attachment_evicted: false,
        }),
      },
    });

    expect(screen.queryByText(/Attachment removed to free up server storage space/)).toBeNull();
  });

  it('shows neither the attachment nor the eviction notice for an ordinary message', () => {
    render(MessageItem, { props: { message: baseMessage() } });

    expect(screen.queryByText(/Attachment removed to free up server storage space/)).toBeNull();
  });
});
