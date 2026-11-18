import { getValidAccessToken, endSession } from './api';

// Close codes the server uses when access is revoked.
const CLOSE_SESSION_ENDED = 4001;
const CLOSE_BANNED = 4003;

type EventHandler = (data: any) => void;

export class WSClient {
  private ws: WebSocket | null = null;
  private listeners: Map<string, Set<EventHandler>> = new Map();
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;

  private connecting = false;

  async connect() {
    if (this.connecting) return;
    if (this.ws && (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING)) return;

    this.connecting = true;
    let token: string | null;
    try {
      // Access tokens only last 5 minutes, so get a fresh one for every attempt.
      token = await getValidAccessToken();
    } finally {
      this.connecting = false;
    }
    if (!token) return; // logged out

    this.ws = new WebSocket(`ws://localhost:3001/api/v1/ws?token=${encodeURIComponent(token)}`);

    this.ws.onopen = () => {
      console.log('WebSocket connected');
      this.reconnectAttempts = 0;
    };

    this.ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        // Handle both { type, payload } format and flat format
        const eventType = data.type || data.event;
        const payload = data.payload || data;
        
        if (eventType && this.listeners.has(eventType)) {
          this.listeners.get(eventType)!.forEach(handler => handler(payload));
        }
      } catch (e) {
        console.error('Failed to parse WebSocket message', e);
      }
    };

    this.ws.onclose = (event) => {
      if (event.code === CLOSE_BANNED || event.code === CLOSE_SESSION_ENDED) {
        // Access was revoked: don't reconnect, go back to the login screen.
        this.ws = null;
        endSession(event.reason || 'Your session has ended. Please log in again.');
        return;
      }
      console.log('WebSocket disconnected');
      this.attemptReconnect();
    };

    this.ws.onerror = (error) => {
      console.error('WebSocket error:', error);
    };
  }

  on(event: string, handler: EventHandler) {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, new Set());
    }
    this.listeners.get(event)!.add(handler);
  }

  off(event: string, handler?: EventHandler) {
    if (!handler) {
      this.listeners.delete(event);
      return;
    }
    const handlers = this.listeners.get(event);
    if (handlers) {
      handlers.delete(handler);
      if (handlers.size === 0) {
        this.listeners.delete(event);
      }
    }
  }

  send(type: string, payload: any) {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify({ type, payload }));
    } else {
      console.warn('WebSocket is not connected');
    }
  }

  disconnect() {
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
  }

  private attemptReconnect() {
    if (this.reconnectAttempts < this.maxReconnectAttempts) {
      this.reconnectAttempts++;
      setTimeout(() => this.connect(), 2000 * this.reconnectAttempts);
    }
  }
}

export const wsClient = new WSClient();