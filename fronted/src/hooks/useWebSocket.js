import { useState, useEffect, useRef, useCallback } from 'react';

export const useWebSocket = (url) => {
  const [socket, setSocket] = useState(null);
  const [lastMessage, setLastMessage] = useState(null);
  const [readyState, setReadyState] = useState(0);
  const [error, setError] = useState(null);
  const messageQueue = useRef([]);
  const reconnectTimeoutId = useRef(null);
  const reconnectAttempts = useRef(0);

  const connect = useCallback(() => {
    try {
      const ws = new WebSocket(url);
      
      ws.onopen = () => {
        console.log('WebSocket connected');
        setReadyState(1);
        setError(null);
        reconnectAttempts.current = 0;
        
        // Send queued messages
        while (messageQueue.current.length > 0) {
          const message = messageQueue.current.shift();
          ws.send(message);
        }
      };
      
      ws.onmessage = (event) => {
        setLastMessage({
          data: event.data,
          timestamp: new Date().toISOString()
        });
      };
      
      ws.onclose = () => {
        console.log('WebSocket disconnected');
        setReadyState(0);
        
        // Attempt to reconnect
        if (reconnectAttempts.current < 5) {
          reconnectAttempts.current += 1;
          reconnectTimeoutId.current = setTimeout(() => {
            connect();
          }, Math.pow(2, reconnectAttempts.current) * 1000);
        }
      };
      
      ws.onerror = (error) => {
        console.error('WebSocket error:', error);
        setError(error);
      };
      
      setSocket(ws);
    } catch (err) {
      setError(err);
    }
  }, [url]);

  useEffect(() => {
    connect();
    
    return () => {
      if (reconnectTimeoutId.current) {
        clearTimeout(reconnectTimeoutId.current);
      }
      if (socket) {
        socket.close();
      }
    };
  }, [connect]);

  const sendMessage = useCallback((message) => {
    if (socket && readyState === 1) {
      socket.send(typeof message === 'string' ? message : JSON.stringify(message));
    } else {
      messageQueue.current.push(typeof message === 'string' ? message : JSON.stringify(message));
    }
  }, [socket, readyState]);

  return {
    socket,
    lastMessage,
    readyState,
    error,
    sendMessage
  };
};