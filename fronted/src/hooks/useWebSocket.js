import { useState, useEffect, useCallback, useRef } from 'react';

const useWebSocket = (url, options = {}) => {
  const {
    protocols = [],
    onOpen,
    onMessage,
    onClose,
    onError,
    shouldReconnect = true,
    reconnectAttempts = 5,
    reconnectInterval = 1000,
    maxReconnectInterval = 30000,
    reconnectDecay = 1.5,
    heartbeatInterval = 30000,
    binaryType = 'blob',
    share = false,
    filter,
    retryOnError = true,
    queryParams = {}
  } = options;

  // Connection state
  const [socket, setSocket] = useState(null);
  const [lastMessage, setLastMessage] = useState(null);
  const [readyState, setReadyState] = useState(0); // 0: CONNECTING, 1: OPEN, 2: CLOSING, 3: CLOSED
  const [connectionAttempts, setConnectionAttempts] = useState(0);
  const [lastPing, setLastPing] = useState(null);
  const [lastPong, setLastPong] = useState(null);

  // Message handling
  const [messageHistory, setMessageHistory] = useState([]);
  const [sendQueue, setSendQueue] = useState([]);

  // Refs for stable references
  const reconnectTimeoutRef = useRef(null);
  const heartbeatTimeoutRef = useRef(null);
  const socketRef = useRef(null);
  const optionsRef = useRef(options);
  const urlRef = useRef(url);
  const reconnectAttemptsRef = useRef(0);
  const currentReconnectInterval = useRef(reconnectInterval);

  // Update refs when options change
  useEffect(() => {
    optionsRef.current = options;
    urlRef.current = url;
  }, [options, url]);

  // Build WebSocket URL with query parameters
  const buildUrl = useCallback(() => {
    const baseUrl = urlRef.current;
    if (Object.keys(queryParams).length === 0) {
      return baseUrl;
    }

    const url = new URL(baseUrl);
    Object.entries(queryParams).forEach(([key, value]) => {
      if (value !== null && value !== undefined) {
        url.searchParams.set(key, value.toString());
      }
    });
    return url.toString();
  }, [queryParams]);

  // Send heartbeat ping
  const sendHeartbeat = useCallback(() => {
    if (socketRef.current?.readyState === WebSocket.OPEN) {
      const pingMessage = JSON.stringify({ 
        type: 'ping', 
        timestamp: Date.now() 
      });
      socketRef.current.send(pingMessage);
      setLastPing(Date.now());
    }
  }, []);

  // Setup heartbeat
  const setupHeartbeat = useCallback(() => {
    if (!heartbeatInterval || heartbeatTimeoutRef.current) return;

    const startHeartbeat = () => {
      heartbeatTimeoutRef.current = setInterval(() => {
        sendHeartbeat();
      }, heartbeatInterval);
    };

    startHeartbeat();
  }, [heartbeatInterval, sendHeartbeat]);

  // Clear heartbeat
  const clearHeartbeat = useCallback(() => {
    if (heartbeatTimeoutRef.current) {
      clearInterval(heartbeatTimeoutRef.current);
      heartbeatTimeoutRef.current = null;
    }
  }, []);

  // Handle incoming messages
  const handleMessage = useCallback((event) => {
    try {
      let messageData;
      
      // Handle different message types
      if (typeof event.data === 'string') {
        try {
          messageData = JSON.parse(event.data);
        } catch {
          messageData = event.data;
        }
      } else {
        messageData = event.data;
      }

      // Handle pong messages for heartbeat
      if (messageData?.type === 'pong') {
        setLastPong(Date.now());
        return;
      }

      // Apply filter if provided
      if (filter && !filter(messageData)) {
        return;
      }

      const message = {
        data: messageData,
        timestamp: Date.now(),
        id: `msg_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
      };

      setLastMessage(message);
      
      // Update message history (keep last 100 messages)
      setMessageHistory(prev => [...prev.slice(-99), message]);

      // Call custom message handler
      onMessage?.(event, message);
    } catch (error) {
      console.error('Error handling WebSocket message:', error);
      onError?.({ 
        type: 'message_error', 
        error, 
        originalEvent: event 
      });
    }
  }, [filter, onMessage, onError]);

  // Handle connection open
  const handleOpen = useCallback((event) => {
    console.log('WebSocket connected');
    setReadyState(WebSocket.OPEN);
    setConnectionAttempts(0);
    reconnectAttemptsRef.current = 0;
    currentReconnectInterval.current = reconnectInterval;

    // Setup heartbeat
    setupHeartbeat();

    // Send queued messages
    setSendQueue(queue => {
      queue.forEach(message => {
        if (socketRef.current?.readyState === WebSocket.OPEN) {
          socketRef.current.send(message);
        }
      });
      return [];
    });

    onOpen?.(event);
  }, [reconnectInterval, setupHeartbeat, onOpen]);

  // Handle connection close
  const handleClose = useCallback((event) => {
    console.log('WebSocket disconnected:', event.code, event.reason);
    setReadyState(WebSocket.CLOSED);
    clearHeartbeat();
    
    onClose?.(event);

    // Attempt reconnection if enabled and not a clean close
    if (shouldReconnect && 
        event.code !== 1000 && 
        reconnectAttemptsRef.current < reconnectAttempts) {
      
      const timeout = Math.min(
        currentReconnectInterval.current * Math.pow(reconnectDecay, reconnectAttemptsRef.current),
        maxReconnectInterval
      );

      console.log(`Reconnecting in ${timeout}ms... (attempt ${reconnectAttemptsRef.current + 1}/${reconnectAttempts})`);
      
      reconnectTimeoutRef.current = setTimeout(() => {
        reconnectAttemptsRef.current += 1;
        setConnectionAttempts(reconnectAttemptsRef.current);
        connect();
      }, timeout);
    }
  }, [shouldReconnect, reconnectAttempts, reconnectDecay, maxReconnectInterval, clearHeartbeat, onClose]);

  // Handle connection error
  const handleError = useCallback((event) => {
    console.error('WebSocket error:', event);
    
    const errorInfo = {
      type: 'connection_error',
      event,
      readyState: socketRef.current?.readyState,
      url: urlRef.current
    };

    onError?.(errorInfo);

    if (retryOnError && shouldReconnect) {
      setReadyState(WebSocket.CLOSED);
    }
  }, [onError, retryOnError, shouldReconnect]);

  // Connect to WebSocket
  const connect = useCallback(() => {
    // Close existing connection
    if (socketRef.current) {
      socketRef.current.close();
    }

    // Clear existing timeouts
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }

    clearHeartbeat();

    try {
      setReadyState(WebSocket.CONNECTING);
      
      const wsUrl = buildUrl();
      const ws = new WebSocket(wsUrl, protocols);
      
      ws.binaryType = binaryType;

      // Attach event listeners
      ws.onopen = handleOpen;
      ws.onmessage = handleMessage;
      ws.onclose = handleClose;
      ws.onerror = handleError;

      socketRef.current = ws;
      setSocket(ws);

    } catch (error) {
      console.error('Failed to create WebSocket connection:', error);
      setReadyState(WebSocket.CLOSED);
      onError?.({ type: 'connection_failed', error });
    }
  }, [
    protocols, 
    binaryType, 
    buildUrl, 
    handleOpen, 
    handleMessage, 
    handleClose, 
    handleError, 
    clearHeartbeat, 
    onError
  ]);

  // Disconnect from WebSocket
  const disconnect = useCallback(() => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }

    clearHeartbeat();

    if (socketRef.current) {
      setReadyState(WebSocket.CLOSING);
      socketRef.current.close(1000, 'Manual disconnect');
      socketRef.current = null;
      setSocket(null);
    }
  }, [clearHeartbeat]);

  // Send message
  const sendMessage = useCallback((message) => {
    if (!message) return false;

    const messageToSend = typeof message === 'string' ? message : JSON.stringify(message);

    if (socketRef.current?.readyState === WebSocket.OPEN) {
      try {
        socketRef.current.send(messageToSend);
        return true;
      } catch (error) {
        console.error('Failed to send message:', error);
        onError?.({ type: 'send_error', error, message });
        return false;
      }
    } else {
      // Queue message if not connected
      setSendQueue(prev => [...prev, messageToSend]);
      return false;
    }
  }, [onError]);

  // Send JSON message
  const sendJsonMessage = useCallback((message) => {
    return sendMessage(JSON.stringify(message));
  }, [sendMessage]);

  // Get connection state info
  const getReadyState = useCallback(() => {
    const states = {
      [WebSocket.CONNECTING]: 'CONNECTING',
      [WebSocket.OPEN]: 'OPEN',
      [WebSocket.CLOSING]: 'CLOSING',
      [WebSocket.CLOSED]: 'CLOSED'
    };
    return states[readyState] || 'UNKNOWN';
  }, [readyState]);

  // Get connection statistics
  const getConnectionStats = useCallback(() => {
    return {
      readyState,
      readyStateLabel: getReadyState(),
      connectionAttempts,
      messageHistory: messageHistory.length,
      queuedMessages: sendQueue.length,
      lastPing,
      lastPong,
      latency: lastPing && lastPong ? lastPong - lastPing : null,
      isConnected: readyState === WebSocket.OPEN,
      isConnecting: readyState === WebSocket.CONNECTING
    };
  }, [readyState, getReadyState, connectionAttempts, messageHistory.length, sendQueue.length, lastPing, lastPong]);

  // Clear message history
  const clearMessageHistory = useCallback(() => {
    setMessageHistory([]);
  }, []);

  // Auto-connect on mount
  useEffect(() => {
    connect();

    // Cleanup on unmount
    return () => {
      disconnect();
    };
  }, [connect, disconnect]);

  // Cleanup timeouts on unmount
  useEffect(() => {
    return () => {
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
      clearHeartbeat();
    };
  }, [clearHeartbeat]);

  return {
    // WebSocket instance
    socket,
    
    // Connection state
    readyState,
    readyStateLabel: getReadyState(),
    connectionAttempts,
    
    // Messages
    lastMessage,
    messageHistory,
    sendQueue,
    
    // Connection info
    lastPing,
    lastPong,
    
    // Actions
    connect,
    disconnect,
    sendMessage,
    sendJsonMessage,
    
    // Utilities
    getReadyState,
    getConnectionStats,
    clearMessageHistory,
    
    // Computed properties
    isConnected: readyState === WebSocket.OPEN,
    isConnecting: readyState === WebSocket.CONNECTING,
    isDisconnected: readyState === WebSocket.CLOSED,
    latency: lastPing && lastPong ? lastPong - lastPing : null
  };
};

export default useWebSocket;
export { useWebSocket };
