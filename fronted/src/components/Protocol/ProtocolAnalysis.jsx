// components/Protocol/ProtocolAnalysis.jsx
import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { 
  PieChart, 
  Pie, 
  Cell, 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  Legend, 
  ResponsiveContainer,
  LineChart,
  Line,
  Area,
  AreaChart
} from 'recharts';
import { 
  RefreshCw, 
  Filter, 
  Download, 
  Settings, 
  AlertTriangle,
  TrendingUp,
  Activity,
  Network,
  Globe,
  Shield,
  Clock,
  Database
} from 'lucide-react';
import StatCard from '../Common/StatCard';
import LoadingSpinner from '../Common/LoadingSpinner';
import ProtocolChart from './ProtocolChart';
import ProtocolDetails from './ProtocolDetails';
import protocolService from '../../services/protocolService';
import { formatBytes, formatNumber, formatPercentage } from '../../utils/formatters';
import { PROTOCOL_COLORS, TIME_RANGES } from '../../utils/constants';

const ProtocolAnalysis = () => {
  // State management
  const [protocolData, setProtocolData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedTimeRange, setSelectedTimeRange] = useState('1h');
  const [selectedProtocol, setSelectedProtocol] = useState(null);
  const [filterCriteria, setFilterCriteria] = useState({
    minPackets: 0,
    minBytes: 0,
    protocols: [],
    ports: []
  });
  const [viewMode, setViewMode] = useState('overview'); // overview, detailed, comparison
  const [refreshInterval, setRefreshInterval] = useState(30000);
  const [autoRefresh, setAutoRefresh] = useState(true);

  // Fetch protocol data
  const fetchProtocolData = useCallback(async () => {
    try {
      setLoading(true);
      const [
        distributionData,
        trendsData,
        statsData,
        anomaliesData
      ] = await Promise.all([
        protocolService.getProtocolDistribution(selectedTimeRange),
        protocolService.getProtocolTrends(selectedTimeRange),
        protocolService.getProtocolStatistics(selectedTimeRange),
        protocolService.getProtocolAnomalies(selectedTimeRange)
      ]);

      if (distributionData.success && trendsData.success && statsData.success) {
        setProtocolData({
          distribution: distributionData.data,
          trends: trendsData.data,
          statistics: statsData.data,
          anomalies: anomaliesData.success ? anomaliesData.data : []
        });
        setError(null);
      } else {
        throw new Error('Failed to fetch protocol data');
      }
    } catch (err) {
      setError(err.message);
      console.error('Error fetching protocol data:', err);
    } finally {
      setLoading(false);
    }
  }, [selectedTimeRange]);

  // Initial data fetch
  useEffect(() => {
    fetchProtocolData();
  }, [fetchProtocolData]);

  // Auto-refresh setup
  useEffect(() => {
    if (!autoRefresh) return;

    const interval = setInterval(fetchProtocolData, refreshInterval);
    return () => clearInterval(interval);
  }, [fetchProtocolData, refreshInterval, autoRefresh]);

  // Filtered protocol data
  const filteredProtocolData = useMemo(() => {
    if (!protocolData?.distribution) return [];

    return protocolData.distribution.filter(protocol => {
      if (protocol.packet_count < filterCriteria.minPackets) return false;
      if (protocol.byte_count < filterCriteria.minBytes) return false;
      if (filterCriteria.protocols.length > 0 && 
          !filterCriteria.protocols.includes(protocol.name)) return false;
      return true;
    });
  }, [protocolData, filterCriteria]);

  // Calculate summary statistics
  const summaryStats = useMemo(() => {
    if (!protocolData?.statistics) return null;

    const stats = protocolData.statistics;
    return {
      totalProtocols: stats.unique_protocols || 0,
      totalPackets: stats.total_packets || 0,
      totalBytes: stats.total_bytes || 0,
      averagePacketSize: stats.average_packet_size || 0,
      topProtocol: stats.top_protocol || 'N/A',
      protocolDiversity: stats.protocol_diversity || 0
    };
  }, [protocolData]);

  // Handle protocol selection
  const handleProtocolSelect = (protocol) => {
    setSelectedProtocol(protocol);
    setViewMode('detailed');
  };

  // Handle filter updates
  const handleFilterUpdate = (newFilters) => {
    setFilterCriteria(prev => ({ ...prev, ...newFilters }));
  };

  // Export data
  const handleExport = async () => {
    try {
      const result = await protocolService.exportProtocolData(selectedTimeRange, 'csv');
      if (result.success) {
        const url = window.URL.createObjectURL(result.data);
        const a = document.createElement('a');
        a.href = url;
        a.download = result.filename;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
      }
    } catch (err) {
      console.error('Export failed:', err);
    }
  };

  // Render loading state
  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <LoadingSpinner size="lg" />
      </div>
    );
  }

  // Render error state
  if (error) {
    return (
      <div className="bg-red-50 border border-red-200 rounded-lg p-6">
        <div className="flex items-center">
          <AlertTriangle className="h-5 w-5 text-red-400 mr-2" />
          <h3 className="text-red-800 font-medium">Error Loading Protocol Data</h3>
        </div>
        <p className="text-red-700 mt-2">{error}</p>
        <button
          onClick={fetchProtocolData}
          className="mt-4 px-4 py-2 bg-red-600 text-white rounded-md hover:bg-red-700"
        >
          Retry
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Protocol Analysis</h1>
          <p className="text-gray-600">Network protocol distribution and behavior analysis</p>
        </div>

        <div className="flex items-center gap-3">
          {/* Time Range Selector */}
          <select
            value={selectedTimeRange}
            onChange={(e) => setSelectedTimeRange(e.target.value)}
            className="px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500"
          >
            {TIME_RANGES.map(range => (
              <option key={range.value} value={range.value}>
                {range.label}
              </option>
            ))}
          </select>

          {/* View Mode Selector */}
          <div className="flex rounded-md border border-gray-300">
            {['overview', 'detailed', 'comparison'].map(mode => (
              <button
                key={mode}
                onClick={() => setViewMode(mode)}
                className={`px-3 py-2 text-sm font-medium capitalize ${
                  viewMode === mode
                    ? 'bg-blue-500 text-white'
                    : 'bg-white text-gray-700 hover:bg-gray-50'
                } ${mode === 'overview' ? 'rounded-l-md' : mode === 'comparison' ? 'rounded-r-md' : ''}`}
              >
                {mode}
              </button>
            ))}
          </div>

          {/* Action Buttons */}
          <button
            onClick={handleExport}
            className="flex items-center px-3 py-2 bg-green-600 text-white rounded-md hover:bg-green-700"
          >
            <Download className="h-4 w-4 mr-1" />
            Export
          </button>

          <button
            onClick={fetchProtocolData}
            disabled={loading}
            className="flex items-center px-3 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50"
          >
            <RefreshCw className={`h-4 w-4 mr-1 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* Summary Statistics */}
      {summaryStats && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 xl:grid-cols-6 gap-4">
          <StatCard
            title="Total Protocols"
            value={summaryStats.totalProtocols}
            icon={Network}
            color="blue"
          />
          <StatCard
            title="Total Packets"
            value={formatNumber(summaryStats.totalPackets)}
            icon={Database}
            color="green"
          />
          <StatCard
            title="Total Bytes"
            value={formatBytes(summaryStats.totalBytes)}
            icon={Activity}
            color="purple"
          />
          <StatCard
            title="Avg Packet Size"
            value={formatBytes(summaryStats.averagePacketSize)}
            icon={TrendingUp}
            color="orange"
          />
          <StatCard
            title="Top Protocol"
            value={summaryStats.topProtocol}
            icon={Globe}
            color="indigo"
          />
          <StatCard
            title="Protocol Diversity"
            value={formatPercentage(summaryStats.protocolDiversity)}
            icon={Shield}
            color="teal"
          />
        </div>
      )}

      {/* Anomaly Alerts */}
      {protocolData?.anomalies && protocolData.anomalies.length > 0 && (
        <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
          <div className="flex items-center mb-2">
            <AlertTriangle className="h-5 w-5 text-yellow-600 mr-2" />
            <h3 className="text-yellow-800 font-medium">Protocol Anomalies Detected</h3>
          </div>
          <div className="space-y-2">
            {protocolData.anomalies.slice(0, 3).map((anomaly, index) => (
              <div key={index} className="text-sm text-yellow-700">
                <span className="font-medium">{anomaly.protocol}</span>: {anomaly.description}
                <span className="ml-2 text-xs text-yellow-600">
                  Severity: {anomaly.severity}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Main Content */}
      {viewMode === 'overview' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Protocol Distribution Pie Chart */}
          <div className="bg-white rounded-lg shadow-sm border p-6">
            <h3 className="text-lg font-semibold mb-4">Protocol Distribution</h3>
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie
                  data={filteredProtocolData}
                  cx="50%"
                  cy="50%"
                  labelLine={false}
                  label={({ name, percent }) => `${name} ${(percent * 100).toFixed(1)}%`}
                  outerRadius={80}
                  fill="#8884d8"
                  dataKey="percentage"
                >
                  {filteredProtocolData.map((entry, index) => (
                    <Cell 
                      key={`cell-${index}`} 
                      fill={PROTOCOL_COLORS[entry.name] || `hsl(${index * 45}, 70%, 60%)`}
                      onClick={() => handleProtocolSelect(entry)}
                      style={{ cursor: 'pointer' }}
                    />
                  ))}
                </Pie>
                <Tooltip formatter={(value) => `${value.toFixed(2)}%`} />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          </div>

          {/* Protocol Traffic Volume */}
          <div className="bg-white rounded-lg shadow-sm border p-6">
            <h3 className="text-lg font-semibold mb-4">Traffic Volume by Protocol</h3>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={filteredProtocolData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis 
                  dataKey="name" 
                  angle={-45}
                  textAnchor="end"
                  height={80}
                />
                <YAxis tickFormatter={formatBytes} />
                <Tooltip 
                  formatter={(value) => [formatBytes(value), 'Bytes']}
                  labelFormatter={(label) => `Protocol: ${label}`}
                />
                <Bar 
                  dataKey="byte_count" 
                  fill="#3b82f6"
                  onClick={(data) => handleProtocolSelect(data)}
                  style={{ cursor: 'pointer' }}
                />
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* Protocol Trends */}
          {protocolData?.trends && (
            <div className="lg:col-span-2 bg-white rounded-lg shadow-sm border p-6">
              <h3 className="text-lg font-semibold mb-4">Protocol Trends Over Time</h3>
              <ResponsiveContainer width="100%" height={300}>
                <LineChart data={protocolData.trends}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis 
                    dataKey="timestamp" 
                    tickFormatter={(value) => new Date(value).toLocaleTimeString()}
                  />
                  <YAxis tickFormatter={formatBytes} />
                  <Tooltip 
                    labelFormatter={(value) => new Date(value).toLocaleString()}
                    formatter={(value, name) => [formatBytes(value), name]}
                  />
                  <Legend />
                  {Object.keys(protocolData.trends[0] || {})
                    .filter(key => key !== 'timestamp')
                    .slice(0, 5)
                    .map((protocol, index) => (
                      <Line
                        key={protocol}
                        type="monotone"
                        dataKey={protocol}
                        stroke={PROTOCOL_COLORS[protocol] || `hsl(${index * 72}, 70%, 50%)`}
                        strokeWidth={2}
                      />
                    ))}
                </LineChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>
      )}

      {viewMode === 'detailed' && selectedProtocol && (
        <ProtocolDetails 
          protocol={selectedProtocol}
          timeRange={selectedTimeRange}
          onBack={() => setViewMode('overview')}
        />
      )}

      {viewMode === 'comparison' && (
        <div className="bg-white rounded-lg shadow-sm border p-6">
          <h3 className="text-lg font-semibold mb-4">Protocol Comparison</h3>
          <ProtocolChart 
            data={filteredProtocolData}
            type="comparison"
            timeRange={selectedTimeRange}
          />
        </div>
      )}

      {/* Protocol Table */}
      <div className="bg-white rounded-lg shadow-sm border">
        <div className="px-6 py-4 border-b border-gray-200">
          <div className="flex justify-between items-center">
            <h3 className="text-lg font-semibold">Protocol Details</h3>
            <div className="flex items-center gap-2">
              <Filter className="h-4 w-4 text-gray-400" />
              <input
                type="number"
                placeholder="Min packets"
                value={filterCriteria.minPackets}
                onChange={(e) => handleFilterUpdate({ minPackets: parseInt(e.target.value) || 0 })}
                className="px-2 py-1 border border-gray-300 rounded text-sm w-24"
              />
              <input
                type="text"
                placeholder="Min bytes"
                value={filterCriteria.minBytes}
                onChange={(e) => handleFilterUpdate({ minBytes: parseInt(e.target.value) || 0 })}
                className="px-2 py-1 border border-gray-300 rounded text-sm w-24"
              />
            </div>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Protocol
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Packets
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Bytes
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Percentage
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Avg Size
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {filteredProtocolData.map((protocol, index) => (
                <tr key={protocol.name} className="hover:bg-gray-50">
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="flex items-center">
                      <div 
                        className="w-3 h-3 rounded-full mr-3"
                        style={{ 
                          backgroundColor: PROTOCOL_COLORS[protocol.name] || `hsl(${index * 45}, 70%, 60%)` 
                        }}
                      ></div>
                      <span className="text-sm font-medium text-gray-900">
                        {protocol.name}
                      </span>
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    {formatNumber(protocol.packet_count)}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    {formatBytes(protocol.byte_count)}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    {formatPercentage(protocol.percentage)}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    {formatBytes(protocol.average_packet_size)}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                    <button
                      onClick={() => handleProtocolSelect(protocol)}
                      className="text-blue-600 hover:text-blue-900"
                    >
                      View Details
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Settings Panel */}
      <div className="bg-white rounded-lg shadow-sm border p-6">
        <div className="flex items-center mb-4">
          <Settings className="h-5 w-5 text-gray-400 mr-2" />
          <h3 className="text-lg font-semibold">Analysis Settings</h3>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Auto Refresh
            </label>
            <div className="flex items-center">
              <input
                type="checkbox"
                checked={autoRefresh}
                onChange={(e) => setAutoRefresh(e.target.checked)}
                className="mr-2"
              />
              <span className="text-sm text-gray-600">
                Every {refreshInterval / 1000}s
              </span>
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Refresh Interval
            </label>
            <select
              value={refreshInterval}
              onChange={(e) => setRefreshInterval(parseInt(e.target.value))}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500"
            >
              <option value={10000}>10 seconds</option>
              <option value={30000}>30 seconds</option>
              <option value={60000}>1 minute</option>
              <option value={300000}>5 minutes</option>
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Last Updated
            </label>
            <p className="text-sm text-gray-600">
              <Clock className="h-4 w-4 inline mr-1" />
              {new Date().toLocaleTimeString()}
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ProtocolAnalysis;