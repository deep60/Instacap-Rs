import { useCallback, useEffect, useRef } from 'react';
import { useWebSocket } from './useWebSocket';

export const useRealTimeUpdates = () => {
  const { lastMessage, sendMessage, readyState } = useWebSocket('ws://localhost:8080/realtime');
  const subscribers = useRef(new Map());

  const subscribe = useCallback((channel, callback) => {
    if (!subscribers.current.has(channel)) {
      subscribers.current.set(channel, new Set());
    }
    subscribers.current.get(channel).add(callback);
    
    // Subscribe to channel on server
    if (readyState === 1) {
      sendMessage({
        type: 'subscribe',
        channel: channel
      });
    }
  }, [sendMessage, readyState]);

  const unsubscribe = useCallback((channel, callback) => {
    if (subscribers.current.has(channel)) {
      subscribers.current.get(channel).delete(callback);
      
      if (subscribers.current.get(channel).size === 0) {
        subscribers.current.delete(channel);
        
        // Unsubscribe from channel on server
        if (readyState === 1) {
          sendMessage({
            type: 'unsubscribe',
            channel: channel
          });
        }
      }
    }
  }, [sendMessage, readyState]);

  const publish = useCallback((channel, data) => {
    sendMessage({
      type: 'publish',
      channel: channel,
      data: data
    });
  }, [sendMessage]);

  // Handle incoming messages
  useEffect(() => {
    if (lastMessage) {
      try {
        const message = JSON.parse(lastMessage.data);
        const { channel, data, type } = message;
        
        if (type === 'data' && subscribers.current.has(channel)) {
          subscribers.current.get(channel).forEach(callback => {
            callback(data);
          });
        }
        
        // Handle specific data types
        if (type === 'traffic-update') {
          const trafficCallbacks = subscribers.current.get('traffic-data');
          if (trafficCallbacks) {
            trafficCallbacks.forEach(callback => {
              const now = new Date();
              callback({
                timestamp: now.toLocaleTimeString('en-US', { 
                  hour12: false,
                  hour: '2-digit',
                  minute: '2-digit'
                }),
                inbound: data.inbound || Math.floor(Math.random() * 1000) + 200,
                outbound: data.outbound || Math.floor(Math.random() * 800) + 150,
                total: (data.inbound || 0) + (data.outbound || 0)
              });
            });
          }
        }
        
        if (type === 'performance-update') {
          const perfCallbacks = subscribers.current.get('performance-data');
          if (perfCallbacks) {
            perfCallbacks.forEach(callback => callback(data));
          }
        }
        
      } catch (err) {
        console.error('Error parsing real-time message:', err);
      }
    }
  }, [lastMessage]);

  // Simulate real-time data for demo
  useEffect(() => {
    const interval = setInterval(() => {
      // Simulate traffic data
      const trafficCallbacks = subscribers.current.get('traffic-data');
      if (trafficCallbacks && trafficCallbacks.size > 0) {
        const now = new Date();
        const data = {
          timestamp: now.toLocaleTimeString('en-US', { 
            hour12: false,
            hour: '2-digit',
            minute: '2-digit'
          }),
          inbound: Math.floor(Math.random() * 1000) + 200,
          outbound: Math.floor(Math.random() * 800) + 150,
          total: 0
        };
        data.total = data.inbound + data.outbound;
        
        trafficCallbacks.forEach(callback => callback(data));
      }
      
      // Simulate performance data
      const perfCallbacks = subscribers.current.get('performance-data');
      if (perfCallbacks && perfCallbacks.size > 0) {
        const data = {
          latency: Math.floor(Math.random() * 100) + 10,
          jitter: Math.floor(Math.random() * 20) + 1,
          packetLoss: Math.random() * 2,
          timestamp: new Date().toISOString()
        };
        
        perfCallbacks.forEach(callback => callback(data));
      }
      
    }, 2000); // Update every 2 seconds
    
    return () => clearInterval(interval);
  }, []);

  return {
    subscribe,
    unsubscribe,
    publish,
    isConnected: readyState === 1
  };
};