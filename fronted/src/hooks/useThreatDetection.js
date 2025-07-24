import { useState, useEffect, useCallback, useRef } from 'react';
import { threatService } from '../services/threatService';

const useThreatDetection = (options = {}) => {
  const {
    autoFetch = true,
    refreshInterval = 30000,
    maxThreats = 1000,
    alertThreshold = 'medium',
    enableRealTimeAlerts = true,
    enableGeolocation = true,
    onThreatDetected,
    onCriticalThreat,
    onThreatResolved,
    onError
  } = options;

  // Core state
  const [threats, setThreats] = useState([]);
  const [activeThreat, setActiveThreat] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [lastUpdate, setLastUpdate] = useState(null);

  // Filtering and pagination
  const [filters, setFilters] = useState({
    severity: '',
    type: '',
    status: 'active',
    sourceIp: '',
    timeRange: '24h'
  });
  const [sortConfig, setSortConfig] = useState({ 
    key: 'detectedAt', 
    direction: 'desc' 
  });
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);

  // Statistics and analytics
  const [statistics, setStatistics] = useState({
    totalThreats: 0,
    activeThreats: 0,
    resolvedThreats: 0,
    criticalThreats: 0,
    highThreats: 0,
    mediumThreats: 0,
    lowThreats: 0,
    threatsByType: {},
    threatsBySource: {},
    threatTrends: [],
    avgResolutionTime: 0,
    detectionRate: 0
  });

  // Real-time state
  const [alertQueue, setAlertQueue] = useState([]);
  const [isMonitoring, setIsMonitoring] = useState(false);
  const [detectionRules, setDetectionRules] = useState([]);
  const [whitelistedIPs, setWhitelistedIPs] = useState([]);
  const [blacklistedIPs, setBlacklistedIPs] = useState([]);

  // Refs for cleanup and management
  const refreshIntervalRef = useRef(null);
  const abortControllerRef = useRef(null);
  const threatCacheRef = useRef(new Map());

  // Fetch threats from API
  const fetchThreats = useCallback(async (options = {}) => {
    try {
      setLoading(true);
      setError(null);

      // Cancel previous request
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
      abortControllerRef.current = new AbortController();

      const response = await threatService.getThreats({
        filters,
        page: currentPage,
        pageSize,
        sortBy: sortConfig.key,
        sortDirection: sortConfig.direction,
        includeResolved: filters.status === 'all',
        signal: abortControllerRef.current.signal,
        ...options
      });

      if (response.success) {
        const newThreats = response.data.threats || [];
        
        if (options.append) {
          setThreats(prev => [...prev, ...newThreats]);
        } else {
          setThreats(newThreats);
        }

        setStatistics(response.data.statistics || statistics);
        setLastUpdate(new Date());

        // Cache threats for offline access
        newThreats.forEach(threat => {
          threatCacheRef.current.set(threat.id, threat);
        });
      } else {
        setError(response.error || 'Failed to fetch threats');
      }
    } catch (err) {
      if (err.name !== 'AbortError') {
        setError(err.message || 'An error occurred while fetching threats');
        onError?.(err);
      }
    } finally {
      setLoading(false);
    }
  }, [filters, currentPage, pageSize, sortConfig, statistics, onError]);

  // Add new threat (from real-time updates)
  const addThreat = useCallback((newThreat) => {
    const enrichedThreat = {
      ...newThreat,
      id: newThreat.id || `threat_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      detectedAt: newThreat.detectedAt || new Date().toISOString(),
      status: newThreat.status || 'active',
      isNew: true
    };

    // Check if threat already exists
    setThreats(prev => {
      const exists = prev.some(threat => threat.id === enrichedThreat.id);
      if (exists) return prev;

      const updated = [enrichedThreat, ...prev].slice(0, maxThreats);
      
      // Update statistics
      setStatistics(prevStats => ({
        ...prevStats,
        totalThreats: prevStats.totalThreats + 1,
        activeThreats: prevStats.activeThreats + 1,
        [`${enrichedThreat.severity}Threats`]: (prevStats[`${enrichedThreat.severity}Threats`] || 0) + 1,
        threatsByType: {
          ...prevStats.threatsByType,
          [enrichedThreat.type]: (prevStats.threatsByType[enrichedThreat.type] || 0) + 1
        },
        threatsBySource: {
          ...prevStats.threatsBySource,
          [enrichedThreat.sourceIp]: (prevStats.threatsBySource[enrichedThreat.sourceIp] || 0) + 1
        }
      }));

      return updated;
    });

    // Cache the threat
    threatCacheRef.current.set(enrichedThreat.id, enrichedThreat);

    // Handle alerts
    if (enableRealTimeAlerts) {
      addAlert(enrichedThreat);
    }

    // Trigger callbacks
    onThreatDetected?.(enrichedThreat);
    
    if (enrichedThreat.severity === 'critical') {
      onCriticalThreat?.(enrichedThreat);
    }
  }, [maxThreats, enableRealTimeAlerts, onThreatDetected, onCriticalThreat]);

  // Update threat status
  const updateThreat = useCallback(async (threatId, updates) => {
    try {
      const response = await threatService.updateThreat(threatId, updates);
      
      if (response.success) {
        setThreats(prev => prev.map(threat => 
          threat.id === threatId 
            ? { ...threat, ...updates, updatedAt: new Date().toISOString() }
            : threat
        ));

        // Update cache
        const cachedThreat = threatCacheRef.current.get(threatId);
        if (cachedThreat) {
          threatCacheRef.current.set(threatId, { ...cachedThreat, ...updates });
        }

        // Update statistics if status changed
        if (updates.status === 'resolved') {
          setStatistics(prev => ({
            ...prev,
            activeThreats: Math.max(0, prev.activeThreats - 1),
            resolvedThreats: prev.resolvedThreats + 1
          }));

          const threat = threats.find(t => t.id === threatId);
          if (threat) {
            onThreatResolved?.(threat);
          }
        }

        return response.data;
      } else {
        throw new Error(response.error || 'Failed to update threat');
      }
    } catch (err) {
      setError(err.message);
      onError?.(err);
      throw err;
    }
  }, [threats, onThreatResolved, onError]);

  // Resolve threat
  const resolveThreat = useCallback(async (threatId, resolution) => {
    return updateThreat(threatId, {
      status: 'resolved',
      resolution,
      resolvedAt: new Date().toISOString()
    });
  }, [updateThreat]);

  // Dismiss threat
  const dismissThreat = useCallback(async (threatId, reason) => {
    return updateThreat(threatId, {
      status: 'dismissed',
      dismissReason: reason,
      dismissedAt: new Date().toISOString()
    });
  }, [updateThreat]);

  // Add to alert queue
  const addAlert = useCallback((threat) => {
    const shouldAlert = () => {
      switch (alertThreshold) {
        case 'low': return true;
        case 'medium': return ['medium', 'high', 'critical'].includes(threat.severity);
        case 'high': return ['high', 'critical'].includes(threat.severity);
        case 'critical': return threat.severity === 'critical';
        default: return true;
      }
    };

    if (shouldAlert()) {
      const alert = {
        id: `alert_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        threat,
        timestamp: new Date().toISOString(),
        acknowledged: false
      };

      setAlertQueue(prev => [alert, ...prev].slice(0, 100)); // Keep last 100 alerts
    }
  }, [alertThreshold]);

  // Acknowledge alert
  const acknowledgeAlert = useCallback((alertId) => {
    setAlertQueue(prev => prev.map(alert =>
      alert.id === alertId ? { ...alert, acknowledged: true } : alert
    ));
  }, []);

  // Clear all alerts
  const clearAlerts = useCallback(() => {
    setAlertQueue([]);
  }, []);

  // Filter threats
  const getFilteredThreats = useCallback(() => {
    let filtered = threats;

    // Apply filters
    if (filters.severity) {
      filtered = filtered.filter(threat => threat.severity === filters.severity);
    }
    
    if (filters.type) {
      filtered = filtered.filter(threat => threat.type === filters.type);
    }
    
    if (filters.status && filters.status !== 'all') {
      filtered = filtered.filter(threat => threat.status === filters.status);
    }
    
    if (filters.sourceIp) {
      filtered = filtered.filter(threat => 
        threat.sourceIp && threat.sourceIp.includes(filters.sourceIp)
      );
    }

    // Apply time range filter
    if (filters.timeRange) {
      const now = new Date();
      const timeLimit = new Date();
      
      switch (filters.timeRange) {
        case '1h':
          timeLimit.setHours(now.getHours() - 1);
          break;
        case '24h':
          timeLimit.setDate(now.getDate() - 1);
          break;
        case '7d':
          timeLimit.setDate(now.getDate() - 7);
          break;
        case '30d':
          timeLimit.setDate(now.getDate() - 30);
          break;
        default:
          return filtered;
      }
      
      filtered = filtered.filter(threat => 
        new Date(threat.detectedAt) >= timeLimit
      );
    }

    // Apply sorting
    if (sortConfig.key) {
      filtered.sort((a, b) => {
        let aVal = a[sortConfig.key];
        let bVal = b[sortConfig.key];
        
        if (sortConfig.key === 'detectedAt' || sortConfig.key === 'updatedAt') {
          aVal = new Date(aVal);
          bVal = new Date(bVal);
        }
        
        if (aVal < bVal) return sortConfig.direction === 'asc' ? -1 : 1;
        if (aVal > bVal) return sortConfig.direction === 'asc' ? 1 : -1;
        return 0;
      });
    }

    return filtered;
  }, [threats, filters, sortConfig]);

  // Get threat by ID
  const getThreatById = useCallback((id) => {
    return threats.find(threat => threat.id === id) || threatCacheRef.current.get(id);
  }, [threats]);

  // Update filters
  const updateFilters = useCallback((newFilters) => {
    setFilters(prev => ({ ...prev, ...newFilters }));
    setCurrentPage(1);
  }, []);

  // Update sort
  const updateSort = useCallback((key, direction) => {
    setSortConfig({ key, direction });
  }, []);

  // Start monitoring
  const startMonitoring = useCallback(() => {
    setIsMonitoring(true);
    if (refreshInterval > 0) {
      refreshIntervalRef.current = setInterval(() => {
        fetchThreats({ append: false });
      }, refreshInterval);
    }
  }, [refreshInterval, fetchThreats]);

  // Stop monitoring
  const stopMonitoring = useCallback(() => {
    setIsMonitoring(false);
    if (refreshIntervalRef.current) {
      clearInterval(refreshIntervalRef.current);
      refreshIntervalRef.current = null;
    }
  }, []);

  // Load detection rules
  const loadDetectionRules = useCallback(async () => {
    try {
      const response = await threatService.getDetectionRules();
      if (response.success) {
        setDetectionRules(response.data || []);
      }
    } catch (err) {
      console.error('Failed to load detection rules:', err);
    }
  }, []);

  // Export threats
  const exportThreats = useCallback(async (format = 'json') => {
    try {
      const filtered = getFilteredThreats();
      const response = await threatService.exportThreats({
        threats: filtered,
        format,
        filters
      });
      return response;
    } catch (err) {
      setError(`Export failed: ${err.message}`);
      return null;
    }
  }, [getFilteredThreats, filters]);

  // Auto-fetch on mount and when dependencies change
  useEffect(() => {
    if (autoFetch) {
      fetchThreats();
      loadDetectionRules();
    }
  }, [autoFetch, fetchThreats, loadDetectionRules]);

  // Start/stop monitoring based on isMonitoring state
  useEffect(() => {
    if (isMonitoring) {
      startMonitoring();
    } else {
      stopMonitoring();
    }
    
    return stopMonitoring;
  }, [isMonitoring, startMonitoring, stopMonitoring]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
      if (refreshIntervalRef.current) {
        clearInterval(refreshIntervalRef.current);
      }
    };
  }, []);

  // Calculate pagination info
  const filteredThreats = getFilteredThreats();
  const totalCount = filteredThreats.length;
  const paginatedThreats = filteredThreats.slice(
    (currentPage - 1) * pageSize,
    currentPage * pageSize
  );

  const paginationInfo = {
    currentPage,
    pageSize,
    totalCount,
    totalPages: Math.ceil(totalCount / pageSize),
    hasNextPage: currentPage < Math.ceil(totalCount / pageSize),
    hasPrevPage: currentPage > 1
  };

  return {
    // Data
    threats: paginatedThreats,
    allThreats: filteredThreats,
    activeThreat,
    statistics,
    alertQueue,
    detectionRules,
    whitelistedIPs,
    blacklistedIPs,
    
    // State
    loading,
    error,
    lastUpdate,
    isMonitoring,
    filters,
    sortConfig,
    paginationInfo,
    
    // Actions
    fetchThreats,
    addThreat,
    updateThreat,
    resolveThreat,
    dismissThreat,
    setActiveThreat,
    updateFilters,
    updateSort,
    setCurrentPage: (page) => setCurrentPage(page),
    setPageSize: (size) => {
      setPageSize(size);
      setCurrentPage(1);
    },
    
    // Monitoring
    startMonitoring,
    stopMonitoring,
    
    // Alerts
    acknowledgeAlert,
    clearAlerts,
    
    // Utilities
    getThreatById,
    exportThreats,
    refresh: () => fetchThreats({ append: false }),
    setError: (err) => setError(err),
    clearError: () => setError(null)
  };
};

export default useThreatDetection;
export { useThreatDetection };
