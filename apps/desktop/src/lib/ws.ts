import { wsBase } from './api';
let socket: WebSocket | null = null;
let intentionalClose = false;
let reconnectTimeout: ReturnType<typeof setTimeout> | null = null;
let currentChannelId: string | null = null;

export function connectWebSocket(
  channelId: string,
  onMessage: (message: any) => void
) {
  const token = localStorage.getItem('svalinn_token');
  if (!token) {
    console.warn('No auth token — skipping WebSocket connection');
    return;
  }

  // Clean up any existing connection first
  disconnectWebSocket();
  intentionalClose = false;
  currentChannelId = channelId;

  const params = new URLSearchParams({ token, channel_id: channelId });
  const wsUrl = `${wsBase()}/api/v1/ws?${params.toString()}`;
  socket = new WebSocket(wsUrl);

  socket.onopen = () => {
    console.log(`✅ WebSocket connected to channel ${channelId}`);
  };

  socket.onmessage = (event) => {
    try {
      const message = JSON.parse(event.data);
      onMessage(message);
    } catch (e) {
      console.error('Failed to parse WS message', e);
    }
  };

  socket.onclose = () => {
    // Only reconnect if the close was unexpected
    if (!intentionalClose && currentChannelId === channelId) {
      console.log('⚠️ WebSocket closed unexpectedly, reconnecting in 3s...');
      reconnectTimeout = setTimeout(
        () => connectWebSocket(channelId, onMessage),
        3000
      );
    }
  };

  socket.onerror = (err) => {
    console.error('WebSocket error:', err);
  };
}

export function disconnectWebSocket() {
  intentionalClose = true;
  currentChannelId = null;
  if (reconnectTimeout) {
    clearTimeout(reconnectTimeout);
    reconnectTimeout = null;
  }
  if (socket) {
    socket.close();
    socket = null;
  }
}