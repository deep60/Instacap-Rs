import { formatThreatData, formatPacketData } from '../utils/formatters';

// WebSocket connection states
export const WS_STATES = {
  CONNECTING: 'connecting',
  CONNECTED: 'connected',
  DISCONNECTED: 'disconnected',
  ERROR: 'error',
  RECONNECTING: 'reconnecting'
};

// WebSocket message types
export const WS_MESSAGE_TYPES = {
  // Packet data
  PACKET_CAPTURED: 'packet_captured',
  PACKET_ANALYZED: 'packet_analyzed',
  TRAFFIC_STATS: 'traffic_stats',
  
  // Threat detection
  THREAT_DETECTED: 'threat_detected',
  THREAT_UPDATED: 'threat_updated',
  THREAT_RESOLVED: 'threat_resolved',
  
  // Performance metrics
  PERFORMANCE_UPDATE: 'performance_update',
  BANDWIDTH_UPDATE: 'bandwidth_update',
  LATENCY_UPDATE: 'latency_update',
  
  // System events
  SYSTEM_ALERT: 'system_alert',
  CAPTURE_STATUS: 'capture_status',
  ANALYSIS_STATUS: 'analysis_status',
  
  // Heartbeat
  PING: 'ping',
  PONG: 'pong'
};

// Subscription channels
export const WS_CHANNELS = {
  PACKETS: 'packets',
  THREATS: 'threats',
  PERFORMANCE: 'performance',
  ALERTS: 'alerts',
  SYSTEM: 'system'
};

class WebSocketService {
  constructor() {
    this.ws = null;
    this.url = process.env.REACT_APP_WS_URL || 'ws://localhost:8080/ws';
    this.state = WS_STATES.DISCONNECTED;
    this.reconnectAttempts = 0;
    this.maxReconnectAttempts = 5;
    this.reconnectDelay = 1000; // Start with 1 second
    this.maxReconnectDelay = 30000; // Max 30 seconds
    this.heartbeatInterval = null;
    this.heartbeatTimeout = null;
    this.pingInterval = 30000; // 30 seconds
    this.pongTimeout = 5000; // 5 seconds
    
    // Event listeners
    this.listeners = new Map();
    this.subscriptions = new Set();
    
    // Message queue for when disconnected
    this.messageQueue = [];
    this.maxQueueSize = 100;
    
    // Auto-reconnect flag
    this.shouldReconnect = true;
    
    // Connection options
    this.options = {
      protocols: [],
      headers: {}
    };
    
    this.connect();
  }

  /**
   * Connect to WebSocket server
   * @param {Object} options - Connection options
   */
  connect(options = {}) {
    if (this.ws && (this.ws.readyState === WebSocket.CONNECTING || this.ws.readyState === WebSocket.OPEN)) {
      console.log('WebSocket already connected or connecting');
      return;
    }

    this.options = { ...this.options, ...options };
    this.setState(WS_STATES.CONNECTING);
    
    try {
      // Add authentication token if available
      const token = localStorage.getItem('auth_token');
      const wsUrl = token ? `${this.url}?token=${token}` : this.url;
      
      this.ws = new WebSocket(wsUrl, this.options.protocols);
      this.setupEventHandlers();
      
      console.log('Attempting WebSocket connection to:', wsUrl);
    } catch (error) {
      console.error('Error creating WebSocket connection:', error);
      this.setState(WS_STATES.ERROR);
      this.handleReconnect();
    }
  }

  /**
   * Setup WebSocket event handlers
   */
  setupEventHandlers() {
    if (!this.ws) return;

    this.ws.onopen = (event) => {
      console.log('WebSocket connected');
      this.setState(WS_STATES.CONNECTED);
      this.reconnectAttempts = 0;
      this.reconnectDelay = 1000;
      
      // Start heartbeat
      this.startHeartbeat();
      
      // Process queued messages
      this.processMessageQueue();
      
      // Resubscribe to channels
      this.resubscribe();
      
      this.emit('connected', event);
    };

    this.ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        this.handleMessage(data);
      } catch (error) {
        console.error('Error parsing WebSocket message:', error);
        console.log('Raw message:', event.data);
      }
    };

    this.ws.onclose = (event) => {
      console.log('WebSocket disconnected:', event.code, event.reason);
      this.setState(WS_STATES.DISCONNECTED);
      this.stopHeartbeat();
      
      this.emit('disconnected', { code: event.code, reason: event.reason });
      
      // Attempt reconnection if not a clean close
      if (this.shouldReconnect && event.code !== 1000) {
        this.handleReconnect();
      }
    };

    this.ws.onerror = (error) => {
      console.error('WebSocket error:', error);
      this.setState(WS_STATES.ERROR);
      this.emit('error', error);
    };
  }

  /**
   * Handle incoming messages
   * @param {Object} data - Message data
   */
  handleMessage(data) {
    const { type, payload, channel, timestamp } = data;
    
    // Handle heartbeat
    if (type === WS_MESSAGE_TYPES.PING) {
      this.send({ type: WS_MESSAGE_TYPES.PONG, timestamp: Date.now() });
      return;
    }
    
    if (type === WS_MESSAGE_TYPES.PONG) {
      this.handlePong();
      return;
    }
    
    // Process different message types
    switch (type) {
      case WS_MESSAGE_TYPES.PACKET_CAPTURED:
        this.emit('packet', formatPacketData(payload));
        break;
        
      case WS_MESSAGE_TYPES.PACKET_ANALYZED:
        this.emit('packetAnalyzed', formatPacketData(payload));
        break;
        
      case WS_MESSAGE_TYPES.TRAFFIC_STATS:
        this.emit('trafficStats', payload);
        break;
        
      case WS_MESSAGE_TYPES.THREAT_DETECTED:
        this.emit('threat', formatThreatData(payload));
        this.emit('newThreat', formatThreatData(payload));
        break;
        
      case WS_MESSAGE_TYPES.THREAT_UPDATED:
        this.emit('threatUpdated', formatThreatData(payload));
        break;
        
      case WS_MESSAGE_TYPES.THREAT_RESOLVED:
        this.emit('threatResolved', formatThreatData(payload));
        break;
        
      case WS_MESSAGE_TYPES.PERFORMANCE_UPDATE:
        this.emit('performance', payload);
        break;
        
      case WS_MESSAGE_TYPES.BANDWIDTH_UPDATE:
        this.emit('bandwidth', payload);
        break;
        
      case WS_MESSAGE_TYPES.LATENCY_UPDATE:
        this.emit('latency', payload);
        break;
        
      case WS_MESSAGE_TYPES.SYSTEM_ALERT:
        this.emit('alert', payload);
        this.emit('systemAlert', payload);
        break;
        
      case WS_MESSAGE_TYPES.CAPTURE_STATUS:
        this.emit('captureStatus', payload);
        break;
        
      case WS_MESSAGE_TYPES.ANALYSIS_STATUS:
        this.emit('analysisStatus', payload);
        break;
        
      default:
        console.log('Unknown message type:', type);
        this.emit('message', data);
    }
    
    // Emit channel-specific events
    if (channel) {
      this.emit(`${channel}:${type}`, payload);
      this.emit(`channel:${channel}`, { type, payload, timestamp });
    }
  }

  /**
   * Send message to server
   * @param {Object} message - Message to send
   */
  send(message) {
    if (this.isConnected()) {
      try {
        this.ws.send(JSON.stringify(message));
      } catch (error) {
        console.error('Error sending WebSocket message:', error);
      }
    } else {
      // Queue message if not connected
      if (this.messageQueue.length >= this.maxQueueSize) {
        this.messageQueue.shift(); // Remove oldest message
      }
      this.messageQueue.push(message);
    }
  }

  /**
   * Subscribe to a channel or event type
   * @param {string} channel - Channel to subscribe to
   * @param {Object} options - Subscription options
   */
  subscribe(channel, options = {}) {
    const subscription = {
      action: 'subscribe',
      channel,
      ...options
    };
    
    this.subscriptions.add(channel);
    this.send(subscription);
    
    console.log(`Subscribed to channel: ${channel}`);
  }

  /**
   * Unsubscribe from a channel
   * @param {string} channel - Channel to unsubscribe from
   */
  unsubscribe(channel) {
    const subscription = {
      action: 'unsubscribe',
      channel
    };
    
    this.subscriptions.delete(channel);
    this.send(subscription);
    
    console.log(`Unsubscribed from channel: ${channel}`);
  }

  /**
   * Resubscribe to all channels after reconnection
   */
  resubscribe() {
    this.subscriptions.forEach(channel => {
      this.subscribe(channel);
    });
  }

  /**
   * Add event listener
   * @param {string} event - Event name
   * @param {Function} callback - Callback function
   */
  on(event, callback) {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, new Set());
    }
    this.listeners.get(event).add(callback);
  }

  /**
   * Remove event listener
   * @param {string} event - Event name
   * @param {Function} callback - Callback function
   */
  off(event, callback) {
    if (this.listeners.has(event)) {
      this.listeners.get(event).delete(callback);
      
      // Clean up empty event sets
      if (this.listeners.get(event).size === 0) {
        this.listeners.delete(event);
      }
    }
  }

  /**
   * Emit event to listeners
   * @param {string} event - Event name
   * @param {*} data - Event data
   */
  emit(event, data) {
    if (this.listeners.has(event)) {
      this.listeners.get(event).forEach(callback => {
        try {
          callback(data);
        } catch (error) {
          console.error(`Error in WebSocket event handler for ${event}:`, error);
        }
      });
    }
  }

  /**
   * Start heartbeat mechanism
   */
  startHeartbeat() {
    this.stopHeartbeat();
    
    this.heartbeatInterval = setInterval(() => {
      if (this.isConnected()) {
        this.send({ type: WS_MESSAGE_TYPES.PING, timestamp: Date.now() });
        
        // Set timeout for pong response
        this.heartbeatTimeout = setTimeout(() => {
          console.log('WebSocket heartbeat timeout');
          this.ws.close();
        }, this.pongTimeout);
      }
    }, this.pingInterval);
  }

  /**
   * Stop heartbeat mechanism
   */
  stopHeartbeat() {
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
      this.heartbeatInterval = null;
    }
    
    if (this.heartbeatTimeout) {
      clearTimeout(this.heartbeatTimeout);
      this.heartbeatTimeout = null;
    }
  }

  /**
   * Handle pong response
   */
  handlePong() {
    if (this.heartbeatTimeout) {
      clearTimeout(this.heartbeatTimeout);
      this.heartbeatTimeout = null;
    }
  }

  /**
   * Process queued messages
   */
  processMessageQueue() {
    while (this.messageQueue.length > 0 && this.isConnected()) {
      const message = this.messageQueue.shift();
      this.send(message);
    }
  }

  /**
   * Handle reconnection logic
   */
  handleReconnect() {
    if (!this.shouldReconnect || this.reconnectAttempts >= this.maxReconnectAttempts) {
      console.log('Max reconnection attempts reached or reconnection disabled');
      return;
    }

    this.setState(WS_STATES.RECONNECTING);
    this.reconnectAttempts++;
    
    console.log(`Attempting to reconnect (${this.reconnectAttempts}/${this.maxReconnectAttempts}) in ${this.reconnectDelay}ms`);
    
    setTimeout(() => {
      this.connect();
    }, this.reconnectDelay);
    
    // Exponential backoff with jitter
    this.reconnectDelay = Math.min(
      this.reconnectDelay * 2 + Math.random() * 1000,
      this.maxReconnectDelay
    );
  }

  /**
   * Set connection state
   * @param {string} state - New state
   */
  setState(state) {
    const previousState = this.state;
    this.state = state;
    this.emit('stateChange', { state, previousState });
  }

  /**
   * Check if WebSocket is connected
   * @returns {boolean} Connection status
   */
  isConnected() {
    return this.ws && this.ws.readyState === WebSocket.OPEN;
  }

  /**
   * Get current connection state
   * @returns {string} Current state
   */
  getState() {
    return this.state;
  }

  /**
   * Get connection statistics
   * @returns {Object} Connection statistics
   */
  getStats() {
    return {
      state: this.state,
      reconnectAttempts: this.reconnectAttempts,
      subscriptions: Array.from(this.subscriptions),
      queuedMessages: this.messageQueue.length,
      listeners: Object.fromEntries(
        Array.from(this.listeners.entries()).map(([event, callbacks]) => [
          event,
          callbacks.size
        ])
      )
    };
  }

  /**
   * Disconnect WebSocket
   * @param {boolean} shouldReconnect - Whether to attempt reconnection
   */
  disconnect(shouldReconnect = false) {
    this.shouldReconnect = shouldReconnect;
    this.stopHeartbeat();
    
    if (this.ws) {
      this.ws.close(1000, 'Client disconnect');
      this.ws = null;
    }
    
    this.setState(WS_STATES.DISCONNECTED);
  }

  /**
   * Clear all listeners and subscriptions
   */
  cleanup() {
    this.disconnect(false);
    this.listeners.clear();
    this.subscriptions.clear();
    this.messageQueue = [];
  }

  /**
   * Request specific data types
   * @param {Array} dataTypes - Types of data to request
   */
  requestData(dataTypes = []) {
    this.send({
      action: 'request_data',
      types: dataTypes,
      timestamp: Date.now()
    });
  }

  /**
   * Set packet capture filters
   * @param {Object} filters - Capture filters
   */
  setPacketFilters(filters) {
    this.send({
      action: 'set_packet_filters',
      filters,
      timestamp: Date.now()
    });
  }

  /**
   * Control packet capture
   * @param {string} action - start|stop|pause|resume
   */
  controlCapture(action) {
    this.send({
      action: 'control_capture',
      command: action,
      timestamp: Date.now()
    });
  }
}

// Create and export singleton instance
const webSocketService = new WebSocketService();

// Export service and constants
export { webSocketService as default, WS_STATES, WS_MESSAGE_TYPES, WS_CHANNELS };