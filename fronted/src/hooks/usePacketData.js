import { useState, useEffect, useCallback } from 'react';
import { packetService } from '../services/packetService';

export const usePacketData = (filters = {}, autoRefresh = true) => {
  const [packets, setPackets] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [totalPackets, setTotalPackets] = useState(0);
  const [pagination, setPagination] = useState({
    page: 1,
    pageSize: 50,
    totalPages: 0
  });

  const fetchPackets = useCallback(async (page = 1, pageSize = 50) => {
    setLoading(true);
    setError(null);
    
    try {
      const response = await packetService.getPackets({
        ...filters,
        page,
        pageSize
      });
      
      setPackets(response.packets);
      setTotalPackets(response.total);
      setPagination({
        page: response.page,
        pageSize: response.pageSize,
        totalPages: Math.ceil(response.total / response.pageSize)
      });
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [filters]);

  const refreshPackets = useCallback(() => {
    fetchPackets(pagination.page, pagination.pageSize);
  }, [fetchPackets, pagination.page, pagination.pageSize]);

  const goToPage = useCallback((page) => {
    fetchPackets(page, pagination.pageSize);
  }, [fetchPackets, pagination.pageSize]);

  const changePageSize = useCallback((pageSize) => {
    fetchPackets(1, pageSize);
  }, [fetchPackets]);

  useEffect(() => {
    fetchPackets();
  }, [fetchPackets]);

  useEffect(() => {
    if (!autoRefresh) return;

    const interval = setInterval(() => {
      refreshPackets();
    }, 5000); // Refresh every 5 seconds

    return () => clearInterval(interval);
  }, [autoRefresh, refreshPackets]);

  return {
    packets,
    loading,
    error,
    totalPackets,
    pagination,
    refreshPackets,
    goToPage,
    changePageSize
  };
};