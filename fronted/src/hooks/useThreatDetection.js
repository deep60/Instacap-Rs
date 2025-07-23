import { useState, useEffect, useCallback } from 'react';
import { threatService } from '../services/threatService';
import { useWebSocket } from './useWebSocket';

export const useThreatDetection = () => {
  const [threats, setThreats] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [stats, setStats] = useState({
    total: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0
  });

  const { lastMessage } = useWebSocket('ws://localhost:8080/threats');

  const fetchThreats = useCallback(async () => {
    setLoading(true);
    setError(null);
    
    try {
      const [threatsData, statsData] = await Promise.all([
        threatService.getThreats(),
        threatService.getThreatStats()
      ]);
      
      setThreats(threatsData);
      setStats(statsData);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  const acknowledgeThreal = useCallback(async (threatId) => {
    try {
      await threatService.acknowledgeThreat(threatId);
      setThreats(prev => prev.map(threat => 
        threat.id === threatId 
          ? { ...threat, acknowledged: true }
          : threat
      ));
    } catch (err) {
      setError(err.message);
    }
  }, []);

  const dismissThreat = useCallback(async (threatId) => {
    try {
      await threatService.dismissThreat(threatId);
      setThreats(prev => prev.filter(threat => threat.id !== threatId));
    } catch (err) {
      setError(err.message);
    }
  }, []);

  useEffect(() => {
    fetchThreats();
  }, [fetchThreats]);

  // Handle real-time threat updates
  useEffect(() => {
    if (lastMessage) {
      try {
        const threatData = JSON.parse(lastMessage.data);
        if (threatData.type === 'new_threat') {
          setThreats(prev => [threatData.threat, ...prev]);
          setStats(prev => ({
            ...prev,
            total: prev.total + 1,
            [threatData.threat.severity]: prev[threatData.threat.severity] + 1
          }));
        }
      } catch (err) {
        console.error('Error parsing threat message:', err);
      }
    }
  }, [lastMessage]);

  return {
    threats,
    loading,
    error,
    stats,
    refreshThreats: fetchThreats,
    acknowledgeThreal,
    dismissThreat
  };
};