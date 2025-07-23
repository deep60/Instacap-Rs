class WebSocketService {
  constructor() {
    this.connections = new Map();
    this.messageHandlers = new Map();
  }

  connect(url, options = {}) {
    if (this.connections.has(url)) {
      return this.connections.get(url);
    }

    const ws = new WebSocket(url);
    
    ws.onopen = () => {
      console.log(`WebSocket connected to ${url}`);
      if (options.onOpen) options.onOpen();
    };

    ws.onmessage = (event) => {
      const handlers = this.messageHandlers.get(url);
      if (handlers) {
        handlers.forEach(handler => handler(event));
      }
      if (options.onMessage) options.onMessage(event);
    };

    ws.onclose = () => {
      console.log(`WebSocket disconnected from ${url}`);
      this.connections.delete(url);
      if (options.onClose) options.onClose();
    };

    ws.onerror = (error) => {
      console.error(`WebSocket error on ${url}:`, error);
      if (options.onError) options.onError(error);
    };

    this.connections.set(url, ws);
    return ws;
  }

  disconnect(url) {
    const ws = this.connections.get(url);
    if (ws) {
      ws.close();
      this.connections.delete(url);
      this.messageHandlers.delete(url);
    }
  }

  send(url, data) {
    const ws = this.connections.get(url);
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(typeof data === 'string' ? data : JSON.stringify(data));
    } else {
      console.error(`WebSocket not connected to ${url}`);
    }
  }

  addMessageHandler(url, handler) {
    if (!this.messageHandlers.has(url)) {
      this.messageHandlers.set(url, new Set());
    }
    this.messageHandlers.get(url).add(handler);
  }

  removeMessageHandler(url, handler) {
    const handlers = this.messageHandlers.get(url);
    if (handlers) {
      handlers.delete(handler);
    }
  }

  disconnectAll() {
    this.connections.forEach((ws, url) => {
      ws.close();
    });
    this.connections.clear();
    this.messageHandlers.clear();
  }
}

export const webSocketService = new WebSocketService();