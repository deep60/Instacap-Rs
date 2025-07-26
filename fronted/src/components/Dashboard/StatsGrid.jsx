import React, { useState, useEffect } from 'react';
import StatCard from '../Common/StatCard';
import { formatBytes, formatNumber, formatPercentage } from '../../utils/formatters';
import { useRealTimeUpdates } from '../../hooks/useRealTimeUpdates';
import { 
  Package, 
  Database, 
  Zap, 
  BarChart3, 
  Globe, 
  Link, 
  AlertTriangle, 
  Clock 
} from 'lucide-react';

const StatsGrid = ({ refreshInterval = 5000 }) => {
  const [stats, setStats] = useState({
    totalPackets: 0,
    totalBytes: 0,
    packetsPerSecond: 0,
    bytesPerSecond: 0,
    uniqueIPs: 0,
    activeConnections: 0,
    protocolDistribution: {},
    packetLoss: 0,
    averageLatency: 0,
    threatLevel: 'low',
    blockedPackets: 0,
    bandwidth: 0
  });

  const [previousStats, setPreviousStats] = useState(null);
  const [loading, setLoading] = useState(true);

  // Custom hook for real-time updates
  const { isConnected, lastUpdate } = useRealTimeUpdates();

  useEffect(() => {
    fetchStats();
    const interval = setInterval(fetchStats, refreshInterval);
    return () => clearInterval(interval);
  }, [refreshInterval]); // fetchStats is defined inside the component and recreated on every render, so we don't need to include it

  const fetchStats = async () => {
    try {
      const response = await fetch('/api/network/stats');
      const data = await response.json();
      
      setPreviousStats(stats);
      setStats(data);
      setLoading(false);
    } catch (error) {
      console.error('Error fetching network stats:', error);
      setLoading(false);
    }
  };

  const calculateTrend = (current, previous) => {
    if (!previous || previous === 0) return 0;
    return ((current - previous) / previous) * 100;
  };

  const getThreatLevelColor = (level) => {
    switch (level.toLowerCase()) {
      case 'high': return 'text-red-600';
      case 'medium': return 'text-yellow-600';
      case 'low': return 'text-green-600';
      default: return 'text-gray-600';
    }
  };

  const getProtocolStats = () => {
    const protocols = stats.protocolDistribution;
    const total = Object.values(protocols).reduce((sum, count) => sum + count, 0);
    
    return Object.entries(protocols)
      .sort(([,a], [,b]) => b - a)
      .slice(0, 3)
      .map(([protocol, count]) => ({
        name: protocol.toUpperCase(),
        percentage: total > 0 ? (count / total) * 100 : 0,
        count
      }));
  };

  if (loading) {
    return (
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        {[...Array(8)].map((_, i) => (
          <div key={i} className="bg-white rounded-lg shadow-md p-6 animate-pulse">
            <div className="h-4 bg-gray-200 rounded w-1/2 mb-2"></div>
            <div className="h-8 bg-gray-200 rounded w-3/4 mb-2"></div>
            <div className="h-3 bg-gray-200 rounded w-1/3"></div>
          </div>
        ))}
      </div>
    );
  };

  const topProtocols = getProtocolStats();

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
      {/* Total Packets */}
      <StatCard
        title="Total Packets"
        value={formatNumber(stats.totalPackets)}
        trend={previousStats ? calculateTrend(stats.totalPackets, previousStats.totalPackets) : 0}
        icon={Package}
        status="info"
      />

      {/* Total Data */}
      <StatCard
        title="Total Data"
        value={formatBytes(stats.totalBytes)}
        trend={previousStats ? calculateTrend(stats.totalBytes, previousStats.totalBytes) : 0}
        icon={Database}
        status="success"
      />

      {/* Packets/Second */}
      <StatCard
        title="Packets/Sec"
        value={formatNumber(stats.packetsPerSecond)}
        trend={previousStats ? calculateTrend(stats.packetsPerSecond, previousStats.packetsPerSecond) : 0}
        icon={Zap}
        status="warning"
        subtitle="Real-time rate"
      />

      {/* Bandwidth */}
      <StatCard
        title="Bandwidth"
        value={formatBytes(stats.bytesPerSecond) + '/s'}
        trend={previousStats ? calculateTrend(stats.bytesPerSecond, previousStats.bytesPerSecond) : 0}
        icon={BarChart3}
        status="neutral"
      />

      {/* Unique IPs */}
      <StatCard
        title="Unique IPs"
        value={formatNumber(stats.uniqueIPs)}
        trend={previousStats ? calculateTrend(stats.uniqueIPs, previousStats.uniqueIPs) : 0}
        icon={Globe}
        status="info"
        subtitle="Active hosts"
      />

      {/* Active Connections */}
      <StatCard
        title="Active Connections"
        value={formatNumber(stats.activeConnections)}
        trend={previousStats ? calculateTrend(stats.activeConnections, previousStats.activeConnections) : 0}
        icon={Link}
        status="info"
      />

      {/* Packet Loss */}
      <StatCard
        title="Packet Loss"
        value={formatPercentage(stats.packetLoss)}
        trend={previousStats ? calculateTrend(stats.packetLoss, previousStats.packetLoss) : 0}
        icon={AlertTriangle}
        status={stats.packetLoss > 1 ? "error" : "success"}
      />

      {/* Average Latency */}
      <StatCard
        title="Avg Latency"
        value={`${stats.averageLatency}ms`}
        trend={previousStats ? calculateTrend(stats.averageLatency, previousStats.averageLatency) : 0}
        icon={Clock}
        status={stats.averageLatency > 100 ? "error" : "success"}
      />

      {/* Protocol Distribution Card */}
      <div className="bg-white rounded-lg shadow-md p-6 col-span-1 md:col-span-2">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-gray-800">Top Protocols</h3>
          <span className="text-2xl">🔍</span>
        </div>
        <div className="space-y-3">
          {topProtocols.map((protocol, index) => (
            <div key={protocol.name} className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <div className={`w-3 h-3 rounded-full ${
                  index === 0 ? 'bg-blue-500' : 
                  index === 1 ? 'bg-green-500' : 'bg-yellow-500'
                }`}></div>
                <span className="text-sm font-medium text-gray-700">{protocol.name}</span>
              </div>
              <div className="flex items-center space-x-2">
                <span className="text-sm text-gray-600">{formatPercentage(protocol.percentage)}</span>
                <span className="text-xs text-gray-500">({formatNumber(protocol.count)})</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Threat Level Card */}
      <div className="bg-white rounded-lg shadow-md p-6">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-gray-800">Threat Level</h3>
          <span className="text-2xl">🛡️</span>
        </div>
        <div className="text-center">
          <div className={`text-2xl font-bold capitalize ${getThreatLevelColor(stats.threatLevel)} mb-2`}>
            {stats.threatLevel}
          </div>
          <div className="text-sm text-gray-600">
            {formatNumber(stats.blockedPackets)} blocked packets
          </div>
        </div>
      </div>

      {/* Connection Status */}
      <div className="bg-white rounded-lg shadow-md p-6">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-gray-800">Connection</h3>
          <span className="text-2xl">📡</span>
        </div>
        <div className="text-center">
          <div className={`flex items-center justify-center space-x-2 mb-2`}>
            <div className={`w-3 h-3 rounded-full ${isConnected ? 'bg-green-500' : 'bg-red-500'}`}></div>
            <span className={`text-sm font-medium ${isConnected ? 'text-green-600' : 'text-red-600'}`}>
              {isConnected ? 'Connected' : 'Disconnected'}
            </span>
          </div>
          {lastUpdate && (
            <div className="text-xs text-gray-500">
              Last update: {new Date(lastUpdate).toLocaleTimeString()}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default StatsGrid;