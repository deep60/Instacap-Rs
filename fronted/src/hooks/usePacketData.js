import { useState, useEffect, useCallback, useRef } from 'react';
import { packetService } from '../services/packetService';

const usePacketData = (initialFilters = {}) => {
  const [packets, setPackets] = useState([]);
  const [filteredPackets, setFilteredPackets] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [totalCount, setTotalCount] = useState(0);
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);
  const [filters, setFilters] = useState(initialFilters);
  const [sortConfig, setSortConfig] = useState({ key: 'timestamp', direction: 'desc' });
  const [selectedPacket, setSelectedPacket] = useState(null);
  const [statistics, setStatistics] = useState({
    protocolDistribution: {},
    trafficVolume: 0,
    averagePacketSize: 0,
    topSources: [],
    topDestinations: []
  });

  const abortControllerRef = useRef(null);
  const cacheRef = useRef(new Map());

  // Fetch packets with filters and pagination
  const fetchPackets = useCallback(async (resetCache = false) => {
    try {
      setLoading(true);
      setError(null);

      // Cancel previous request
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }

      abortControllerRef.current = new AbortController();

      // Create cache key
      const cacheKey = JSON.stringify({ 
        filters, 
        currentPage, 
        pageSize, 
        sortConfig 
      });

      // Check cache first
      if (!resetCache && cacheRef.current.has(cacheKey)) {
        const cachedData = cacheRef.current.get(cacheKey);
        setPackets(cachedData.packets);
        setTotalCount(cachedData.totalCount);
        setStatistics(cachedData.statistics);
        setLoading(false);
        return;
      }

      const response = await packetService.getPackets({
        filters,
        page: currentPage,
        pageSize,
        sortBy: sortConfig.key,
        sortDirection: sortConfig.direction,
        signal: abortControllerRef.current.signal
      });

      if (response.success) {
        setPackets(response.data.packets || []);
        setTotalCount(response.data.totalCount || 0);
        setStatistics(response.data.statistics || statistics);

        // Cache the results
        cacheRef.current.set(cacheKey, {
          packets: response.data.packets || [],
          totalCount: response.data.totalCount || 0,
          statistics: response.data.statistics || statistics
        });

        // Limit cache size
        if (cacheRef.current.size > 10) {
          const firstKey = cacheRef.current.keys().next().value;
          cacheRef.current.delete(firstKey);
        }
      } else {
        setError(response.error || 'Failed to fetch packets');
      }
    } catch (err) {
      if (err.name !== 'AbortError') {
        setError(err.message || 'An error occurred while fetching packets');
      }
    } finally {
      setLoading(false);
    }
  }, [filters, currentPage, pageSize, sortConfig]);

  // Apply client-side filtering for real-time updates
  const applyFilters = useCallback((packetList) => {
    if (!filters || Object.keys(filters).length === 0) {
      return packetList;
    }

    return packetList.filter(packet => {
      // Protocol filter
      if (filters.protocol && packet.protocol !== filters.protocol) {
        return false;
      }

      // Source IP filter
      if (filters.sourceIp && !packet.sourceIp.includes(filters.sourceIp)) {
        return false;
      }

      // Destination IP filter
      if (filters.destinationIp && !packet.destinationIp.includes(filters.destinationIp)) {
        return false;
      }

      // Port filter
      if (filters.port && 
          packet.sourcePort !== filters.port && 
          packet.destinationPort !== filters.port) {
        return false;
      }

      // Size range filter
      if (filters.minSize && packet.size < filters.minSize) {
        return false;
      }
      if (filters.maxSize && packet.size > filters.maxSize) {
        return false;
      }

      // Time range filter
      if (filters.startTime && new Date(packet.timestamp) < new Date(filters.startTime)) {
        return false;
      }
      if (filters.endTime && new Date(packet.timestamp) > new Date(filters.endTime)) {
        return false;
      }

      // Custom filter function
      if (filters.customFilter && typeof filters.customFilter === 'function') {
        return filters.customFilter(packet);
      }

      return true;
    });
  }, [filters]);

  // Sort packets
  const sortPackets = useCallback((packetList) => {
    if (!sortConfig.key) return packetList;

    return [...packetList].sort((a, b) => {
      let aVal = a[sortConfig.key];
      let bVal = b[sortConfig.key];

      // Handle different data types
      if (sortConfig.key === 'timestamp') {
        aVal = new Date(aVal);
        bVal = new Date(bVal);
      } else if (typeof aVal === 'string') {
        aVal = aVal.toLowerCase();
        bVal = bVal.toLowerCase();
      }

      if (aVal < bVal) {
        return sortConfig.direction === 'asc' ? -1 : 1;
      }
      if (aVal > bVal) {
        return sortConfig.direction === 'asc' ? 1 : -1;
      }
      return 0;
    });
  }, [sortConfig]);

  // Update filtered packets when packets or filters change
  useEffect(() => {
    const filtered = applyFilters(packets);
    const sorted = sortPackets(filtered);
    setFilteredPackets(sorted);
  }, [packets, applyFilters, sortPackets]);

  // Fetch packets when dependencies change
  useEffect(() => {
    fetchPackets();
  }, [fetchPackets]);

  // Update filters
  const updateFilters = useCallback((newFilters) => {
    setFilters(prev => ({ ...prev, ...newFilters }));
    setCurrentPage(1); // Reset to first page
    cacheRef.current.clear(); // Clear cache
  }, []);

  // Clear filters
  const clearFilters = useCallback(() => {
    setFilters({});
    setCurrentPage(1);
    cacheRef.current.clear();
  }, []);

  // Update sort configuration
  const updateSort = useCallback((key, direction) => {
    setSortConfig({ key, direction });
    cacheRef.current.clear();
  }, []);

  // Change page
  const changePage = useCallback((page) => {
    setCurrentPage(page);
  }, []);

  // Change page size
  const changePageSize = useCallback((size) => {
    setPageSize(size);
    setCurrentPage(1);
    cacheRef.current.clear();
  }, []);

  // Select packet for detailed view
  const selectPacket = useCallback((packet) => {
    setSelectedPacket(packet);
  }, []);

  // Add new packet (for real-time updates)
  const addPacket = useCallback((newPacket) => {
    setPackets(prev => {
      const updated = [newPacket, ...prev];
      // Keep only recent packets to prevent memory issues
      return updated.slice(0, 1000);
    });
    
    // Update statistics
    setStatistics(prev => ({
      ...prev,
      trafficVolume: prev.trafficVolume + newPacket.size,
      protocolDistribution: {
        ...prev.protocolDistribution,
        [newPacket.protocol]: (prev.protocolDistribution[newPacket.protocol] || 0) + 1
      }
    }));
  }, []);

  // Refresh data
  const refresh = useCallback(() => {
    cacheRef.current.clear();
    fetchPackets(true);
  }, [fetchPackets]);

  // Get packet by ID
  const getPacketById = useCallback((id) => {
    return packets.find(packet => packet.id === id);
  }, [packets]);

  // Export packets
  const exportPackets = useCallback(async (format = 'json') => {
    try {
      const response = await packetService.exportPackets({
        packets: filteredPackets,
        format,
        filters
      });
      return response;
    } catch (err) {
      setError(`Export failed: ${err.message}`);
      return null;
    }
  }, [filteredPackets, filters]);

  // Calculate pagination info
  const paginationInfo = {
    currentPage,
    pageSize,
    totalCount,
    totalPages: Math.ceil(totalCount / pageSize),
    hasNextPage: currentPage < Math.ceil(totalCount / pageSize),
    hasPrevPage: currentPage > 1,
    startIndex: (currentPage - 1) * pageSize + 1,
    endIndex: Math.min(currentPage * pageSize, totalCount)
  };

  // Cleanup
  useEffect(() => {
    return () => {
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
    };
  }, []);

  return {
    // Data
    packets: filteredPackets,
    rawPackets: packets,
    selectedPacket,
    statistics,
    totalCount,
    
    // State
    loading,
    error,
    filters,
    sortConfig,
    paginationInfo,
    
    // Actions
    fetchPackets,
    updateFilters,
    clearFilters,
    updateSort,
    changePage,
    changePageSize,
    selectPacket,
    addPacket,
    refresh,
    getPacketById,
    exportPackets,
    
    // Utilities
    setError: (err) => setError(err),
    clearError: () => setError(null)
  };
};

export default usePacketData;