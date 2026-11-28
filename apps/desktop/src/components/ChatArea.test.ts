// @vitest-environment happy-dom
//
// Mounts the real ChatArea.svelte (rather than just its extracted pure
// helpers) to cover two behaviors that only exist as wiring inside this
// component: the unpin-confirmation flow (pin.ts's unpinMessage returning
// requires_confirmation opens ConfirmModal with the server's warning, and
// confirming retries with confirm=true) and the slowmode send-side
// countdown (a 429 from sendChannelMessage disables Send and ticks a
// countdown back down to 0).
//
// ChatArea.svelte fans out to ~10 modules on mount (websocket, crypto,
// ratchet, device-keypair recovery, server members, channel-member
// devices, role lookup) -- every one of those is mocked below so the
// component can mount without touching real crypto, IndexedDB, or the
// network. Only the two modules these two behaviors actually exercise
// (messages.ts's unpinMessage/sendChannelMessage/SendChannelMessageError)
// are mocked with per-test control; everything else is a fixed, minimal
// stub.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import ChatArea from './ChatArea.svelte';
import type { Message } from '../lib/messages';

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
  vi.useRealTimers();
});

vi.mock('../lib/websocket', () => ({
  wsClient: { connect: vi.fn(), on: vi.fn(), off: vi.fn(), send: vi.fn() },
}));

vi.mock('../lib/api', () => ({
  apiFetch: vi.fn(async (url: string) => {
    if (url.includes('/role')) {
      return { ok: true, json: async () => ({ role: 'owner' }) } as Response;
    }
    return { ok: true, json: async () => ({}) } as Response;
  }),
  getAuthHeaders: () => ({}),
  apiBase: () => '',
  fileUrl: (u: string) => u,
}));

// Fully stubbed: neither test sends an attachment or exercises a
// ratchet-encrypted message, so nothing here needs to do real crypto.
vi.mock('../lib/crypto', () => {
  class CryptoLibraryError extends Error {}
  class DeviceSetupError extends Error {}
  return {
    encryptForRecipient: vi.fn(),
    decryptFromSender: vi.fn(),
    encryptFileForFanout: vi.fn(),
    wrapFileKey: vi.fn(),
    unwrapFileKey: vi.fn(),
    decryptFileBytes: vi.fn(),
    ensureDeviceKeypair: vi.fn(),
    CryptoLibraryError,
    DeviceSetupError,
  };
});

vi.mock('../lib/ratchet', () => {
  class RatchetNotSupportedError extends Error {}
  return {
    encryptMessage: vi.fn(),
    decryptMessage: vi.fn(),
    RatchetNotSupportedError,
    b64: (x: unknown) => x,
    fromB64: (x: unknown) => x,
  };
});

vi.mock('../lib/devices', () => ({
  fetchChannelMemberDevices: vi.fn(async () => []),
}));

vi.mock('../lib/members', () => ({
  fetchServerMembers: vi.fn(async () => []),
}));

const { activeDeviceKeypair } = await vi.hoisted(async () => {
  const { writable } = await import('svelte/store');
  return { activeDeviceKeypair: writable(null) };
});
vi.mock('../lib/recovery', () => ({
  activeDeviceKeypair,
  deviceEncryptionReady: vi.fn(async () => ({
    privateKey: 'fake-private-key',
    publicKey: 'fake-public-key',
    deviceId: 'device-1',
  })),
}));

const { fetchChannelMessages, fetchPinnedMessages, sendChannelMessage, unpinMessage, SendChannelMessageError } =
  vi.hoisted(() => {
    class SendChannelMessageError extends Error {
      status: number;
      serverMessage: string | null;
      retryAfterSeconds: number | null;
      constructor(status: number, serverMessage: string | null, retryAfterSeconds: number | null = null) {
        super(serverMessage ?? `Send failed with status ${status}`);
        this.status = status;
        this.serverMessage = serverMessage;
        this.retryAfterSeconds = retryAfterSeconds;
      }
    }
    return {
      fetchChannelMessages: vi.fn(async () => [] as Message[]),
      fetchPinnedMessages: vi.fn(async () => [] as Message[]),
      sendChannelMessage: vi.fn(),
      unpinMessage: vi.fn(),
      SendChannelMessageError,
    };
  });

vi.mock('../lib/messages', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../lib/messages')>();
  return {
    ...actual,
    fetchChannelMessages,
    fetchPinnedMessages,
    sendChannelMessage,
    unpinMessage,
    SendChannelMessageError,
  };
});

function baseMessage(overrides: Partial<Message> = {}): Message {
  return {
    id: 'msg-1',
    channel_id: 'channel-1',
    user_id: 'other-user',
    username: 'alice',
    content: 'an old pinned message',
    created_at: new Date().toISOString(),
    is_edited: false,
    updated_at: null,
    is_locked: false,
    is_encrypted: false,
    is_pinned: true,
    ...overrides,
  };
}

beforeEach(() => {
  activeDeviceKeypair.set(null);
});

describe('ChatArea unpin-confirmation flow', () => {
  it('shows ConfirmModal with the server warning, and confirming unpins with confirm=true', async () => {
    const pinned = baseMessage();
    fetchChannelMessages.mockResolvedValue([pinned]);
    fetchPinnedMessages.mockResolvedValue([pinned]);
    unpinMessage.mockResolvedValueOnce({
      id: pinned.id,
      requires_confirmation: true,
      warning: "This message is old enough that unpinning it will delete it immediately. This can't be undone.",
    });

    render(ChatArea, {
      props: { channelId: 'channel-1', serverId: 'server-1', currentUser: { id: 'me' } },
    });

    const unpinButton = await screen.findByTitle('Unpin');
    await fireEvent.click(unpinButton);

    await waitFor(() => {
      expect(unpinMessage).toHaveBeenCalledWith(pinned.id);
    });

    await waitFor(() => {
      expect(screen.queryByText(/This message is old enough that unpinning it will delete it immediately/)).toBeTruthy();
    }, { timeout: 2000 });

    unpinMessage.mockResolvedValueOnce({ id: pinned.id, deleted: false });
    await fireEvent.click(screen.getByText('[Unpin and delete]'));

    await waitFor(() => {
      expect(unpinMessage).toHaveBeenLastCalledWith(pinned.id, true);
    });
  });
});

describe('ChatArea slowmode send-side countdown', () => {
  it('disables Send and counts down from a 429, then re-enables at 0', async () => {
    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval', 'Date'] });
    fetchChannelMessages.mockResolvedValue([]);
    fetchPinnedMessages.mockResolvedValue([]);
    sendChannelMessage.mockRejectedValueOnce(new SendChannelMessageError(429, null, 2));

    render(ChatArea, {
      props: { channelId: 'channel-1', serverId: 'server-1', currentUser: { id: 'me' } },
    });

    const input = await screen.findByPlaceholderText('Type a message...');
    await fireEvent.input(input, { target: { value: 'hello there' } });

    const sendButton = screen.getByText('Send') as HTMLButtonElement;
    await fireEvent.click(sendButton.closest('form')!, { submit: true });
    await fireEvent.submit(sendButton.closest('form')!);

    await waitFor(() => {
      expect(screen.getByText(/Slowmode: wait \d+s before sending another message here/)).toBeTruthy();
    });

    const disabledSendButton = screen.getByRole('button', { name: /2s|1s/ }) as HTMLButtonElement;
    expect(disabledSendButton.disabled).toBe(true);

    await vi.advanceTimersByTimeAsync(1000);
    expect(screen.getByRole('button', { name: '1s' })).toBeTruthy();

    await vi.advanceTimersByTimeAsync(1000);
    await waitFor(() => {
      const button = screen.getByRole('button', { name: 'Send' }) as HTMLButtonElement;
      expect(button.disabled).toBe(false);
    });
  });
});
