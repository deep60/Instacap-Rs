import { useState, useEffect, useCallback, useRef } from 'react';
import { websocketService } from '../services/websocket';

const useRealTimeUpdates = (options = {}) => {
  const {
    autoConnect = true,
    reconnectAttempts = 5,
    reconnectDelay = 1000,
    maxReconnectDelay = 30000,
    enableHeartbeat = true,
    heartbeatInterval = 30000,
    bufferSize = 1000,
    subscriptions = ['packets', 'threats', 'alerts', 'performance'],
    onPacketReceived,
    onThreatDetected,
    onAlertReceived,
    onPerformanceUpdate,
    onConnectionChange,
    onError
  } = options;

  const [isConnected, setIsConnected] = useState(false);
  const [connectionStatus, setConnectionStatus] = useState('disconnected');
  const [lastUpdate, setLastUpdate] = useState(null);
  const [updateCount, setUpdateCount] = useState(0);
  const [reconnectCount, setReconnectCount] = useState(0);
  const [latency, setLatency] = useState(0);
  const [error, setError] = useState(null);

  // Buffers for different data types
  const [packetBuffer, setPacketBuffer] = useState([]);
  const [threatBuffer, setThreatBuffer] = useState([]);
  const [alertBuffer, setAlertBuffer] = useState([]);
  const [performanceBuffer, setPerformanceBuffer] = useState([]);

  // Refs for managing state
  const wsRef = useRef(null);
  const reconnectTimeoutRef = useRef(null);
  const heartbeatIntervalRef = useRef(null);
  const pingTimeRef = useRef(null);
  const currentReconnectDelayRef = useRef(reconnectDelay);

  // Statistics
  const [statistics, setStatistics] = useState({
    packetsReceived: 0,
    threatsDetected: 0,
    alertsReceived: 0,
    performanceUpdates: 0,
    bytesReceived: 0,
    messagesPerSecond: 0,
    avgLatency: 0
  });

  const statisticsRef = useRef(statistics);
  const messageTimestampsRef = useRef([]);

  // Update statistics
  const updateStatistics = useCallback((type, data) => {
    const now = Date.now();
    messageTimestampsRef.current.push(now);
    
    // Keep only last minute of timestamps
    messageTimestampsRef.current = messageTimestampsRef.current.filter(
      timestamp => now - timestamp < 60000
    );

    const messagesPerSecond = messageTimestampsRef.current.length / 60;

    setStatistics(prev => {
      const updated = {
        ...prev,
        bytesReceived: prev.bytesReceived + (JSON.stringify(data).length || 0),
        messagesPerSecond: Math.round(messagesPerSecond * 100) / 100
      };

      switch (type) {
        case 'packet':
          updated.packetsReceived += 1;
          break;
        case 'threat':
          updated.threatsDetected += 1;
          break;
        case 'alert':
          updated.alertsReceived += 1;
          break;
        case 'performance':
          updated.performanceUpdates += 1;
          break;
      }

      statisticsRef.current = updated;
      return updated;
    });
  }, []);

  // Handle incoming messages
  const handleMessage = useCallback((event) => {
    try {
      const data = JSON.parse(event.data);
      const now = Date.now();
      
      setLastUpdate(now);
      setUpdateCount(prev => prev + 1);

      // Calculate latency if timestamp is provided
      if (data.timestamp) {
        const messageLatency = now - new Date(data.timestamp).getTime();
        setLatency(messageLatency);
        
        setStatistics(prev => ({
          ...prev,
          avgLatency: Math.round(((prev.avgLatency * (prev.packetsReceived - 1)) + messageLatency) / prev.packetsReceived)
        }));
      }

      // Handle different message types
      switch (data.type) {
        case 'packet':
          setPacketBuffer(prev => {
            const updated = [data.payload, ...prev].slice(0, bufferSize);
            onPacketReceived?.(data.payload, updated);
            return updated;
          });
          updateStatistics('packet', data.payload);
          break;

        case 'threat':
          setThreatBuffer(prev => {
            const updated = [data.payload, ...prev].slice(0, bufferSize);
            onThreatDetected?.(data.payload, updated);
            return updated;
          });
          updateStatistics('threat', data.payload);
          break;

        case 'alert':
          setAlertBuffer(prev => {
            const updated = [data.payload, ...prev].slice(0, bufferSize);
            onAlertReceived?.(data.payload, updated);
            return updated;
          });
          updateStatistics('alert', data.payload);
          break;

        case 'performance':
          setPerformanceBuffer(prev => {
            const updated = [data.payload, ...prev].slice(0, bufferSize);
            onPerformanceUpdate?.(data.payload, updated);
            return updated;
          });
          updateStatistics('performance', data.payload);
          break;

        case 'pong':
          if (pingTimeRef.current) {
            const pingLatency = now - pingTimeRef.current;
            setLatency(pingLatency);
            pingTimeRef.current = null;
          }
          break;

        case 'error':
          setError(data.message || 'WebSocket error received');
          onError?.(data);
          break;

        default:
          console.warn('Unknown message type:', data.type);
      }
    } catch (err) {
      console.error('Error parsing WebSocket message:', err);
      setError('Failed to parse incoming message');
      onError?.(err);
    }
  }, [bufferSize, onPacketReceived, onThreatDetected, onAlertReceived, onPerformanceUpdate, onError, updateStatistics]);

  // Setup heartbeat
  const setupHeartbeat = useCallback(() => {
    if (!enableHeartbeat || heartbeatIntervalRef.current) return;

    heartbeatIntervalRef.current = setInterval(() => {
      if (wsRef.current?.readyState === WebSocket.OPEN) {
        pingTimeRef.current = Date.now();
        wsRef.current.send(JSON.stringify({ type: 'ping', timestamp: pingTimeRef.current }));
      }
    }, heartbeatInterval);
  }, [enableHeartbeat, heartbeatInterval]);

  // Clear heartbeat
  const clearHeartbeat = useCallback(() => {
    if (heartbeatIntervalRef.current) {
      clearInterval(heartbeatIntervalRef.current);
      heartbeatIntervalRef.current = null;
    }
  }, []);

  // Connect to WebSocket
  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      return Promise.resolve();
    }

    return new Promise((resolve, reject) => {
      try {
        setConnectionStatus('connecting');
        setError(null);

        wsRef.current = websocketService.connect({
          onOpen: () => {
            setIsConnected(true);
            setConnectionStatus('connected');
            setReconnectCount(0);
            currentReconnectDelayRef.current = reconnectDelay;
            
            // Subscribe to channels
            subscriptions.forEach(subscription => {
              wsRef.current.send(JSON.stringify({
                type: 'subscribe',
                channel: subscription
              }));
            });

            setupHeartbeat();
            onConnectionChange?.(true);
            resolve();
          },
          onMessage: handleMessage,
          onClose: (event) => {
            setIsConnected(false);
            setConnectionStatus('disconnected');
            clearHeartbeat();
            onConnectionChange?.(false);

            // Attempt reconnection if not a clean close
            if (event.code !== 1000 && reconnectCount < reconnectAttempts) {
              scheduleReconnect();
            }
          },
          onError: (error) => {
            setError(error.message || 'WebSocket connection error');
            setConnectionStatus('error');
            onError?.(error);
            reject(error);
          }
        });
      } catch (err) {
        setError(err.message);
        setConnectionStatus('error');
        reject(err);
      }
    });
  }, [subscriptions, handleMessage, setupHeartbeat, onConnectionChange, onError, reconnectCount, reconnectAttempts, reconnectDelay]);

  // Schedule reconnection
  const scheduleReconnect = useCallback(() => {
    if (reconnectTimeoutRef.current) return;

    setConnectionStatus('reconnecting');
    setReconnectCount(prev => prev + 1);

    reconnectTimeoutRef.current = setTimeout(() => {
      reconnectTimeoutRef.current = null;
      connect().catch(() => {
        // Exponential backoff
        currentReconnectDelayRef.current = Math.min(
          currentReconnectDelayRef.current * 2,
          maxReconnectDelay
        );
      });
    }, currentReconnectDelayRef.current);
  }, [connect, maxReconnectDelay]);

  // Disconnect from WebSocket
  const disconnect = useCallback(() => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }

    clearHeartbeat();

    if (wsRef.current) {
      wsRef.current.close(1000, 'Manual disconnect');
      wsRef.current = null;
    }

    setIsConnected(false);
    setConnectionStatus('disconnected');
  }, [clearHeartbeat]);

  // Send message
  const sendMessage = useCallback((message) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(message));
      return true;
    }
    return false;
  }, []);

  // Subscribe to channel
  const subscribe = useCallback((channel) => {
    return sendMessage({ type: 'subscribe', channel });
  }, [sendMessage]);

  // Unsubscribe from channel
  const unsubscribe = useCallback((channel) => {
    return sendMessage({ type: 'unsubscribe', channel });
  }, [sendMessage]);

  // Clear buffers
  const clearBuffers = useCallback(() => {
    setPacketBuffer([]);
    setThreatBuffer([]);
    setAlertBuffer([]);
    setPerformanceBuffer([]);
  }, []);

  // Reset statistics
  const resetStatistics = useCallback(() => {
    setStatistics({
      packetsReceived: 0,
      threatsDetected: 0,
      alertsReceived: 0,
      performanceUpdates: 0,
      bytesReceived: 0,
      messagesPerSecond: 0,
      avgLatency: 0
    });
    messageTimestampsRef.current = [];
    setUpdateCount(0);
  }, []);

  // Auto-connect on mount
  useEffect(() => {
    if (autoConnect) {
      connect();
    }

    return () => {
      disconnect();
    };
  }, [autoConnect, connect, disconnect]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
      clearHeartbeat();
    };
  }, [clearHeartbeat]);

  return {
    // Connection state
    isConnected,
    connectionStatus,
    reconnectCount,
    latency,
    error,
    
    // Data buffers
    packetBuffer,
    threatBuffer,
    alertBuffer,
    performanceBuffer,
    
    // Statistics
    statistics,
    lastUpdate,
    updateCount,
    
    // Actions
    connect,
    disconnect,
    sendMessage,
    subscribe,
    unsubscribe,
    clearBuffers,
    resetStatistics,
    
    // Utilities
    setError: (err) => setError(err),
    clearError: () => setError(null)
  };
};

export default useRealTimeUpdates;