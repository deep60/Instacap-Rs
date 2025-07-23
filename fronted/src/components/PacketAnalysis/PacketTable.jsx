import React, { useState, useEffect, useMemo } from 'react';
import { ChevronDown, ChevronUp, Filter, Eye, Download, Pause, Play } from 'lucide-react';

const PacketTable = ({ 
  packets = [], 
  loading = false, 
  onPacketSelect, 
  selectedPacket,
  realTimeEnabled = true,
  onToggleRealTime 
}) => {
  const [sortConfig, setSortConfig] = useState({ key: 'timestamp', direction: 'desc' });
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);
  const [filters, setFilters] = useState({
    protocol: '',
    source: '',
    destination: '',
    port: ''
  });

  // Protocol color mapping
  const protocolColors = {
    'TCP': 'bg-blue-100 text-blue-800',
    'UDP': 'bg-green-100 text-green-800',
    'HTTP': 'bg-purple-100 text-purple-800',
    'HTTPS': 'bg-indigo-100 text-indigo-800',
    'DNS': 'bg-yellow-100 text-yellow-800',
    'ICMP': 'bg-red-100 text-red-800',
    'ARP': 'bg-orange-100 text-orange-800',
    'FTP': 'bg-pink-100 text-pink-800'
  };

  // Threat level indicators
  const getThreatLevelClass = (level) => {
    switch (level) {
      case 'high': return 'bg-red-500';
      case 'medium': return 'bg-yellow-500';
      case 'low': return 'bg-green-500';
      default: return 'bg-gray-300';
    }
  };

  // Format timestamp
  const formatTimestamp = (timestamp) => {
    return new Date(timestamp).toLocaleTimeString('en-US', {
      hour12: false,
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      fractionalSecondDigits: 3
    });
  };

  // Format bytes
  const formatBytes = (bytes) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  // Sorting function
  const handleSort = (key) => {
    let direction = 'asc';
    if (sortConfig.key === key && sortConfig.direction === 'asc') {
      direction = 'desc';
    }
    setSortConfig({ key, direction });
  };

  // Filter packets
  const filteredPackets = useMemo(() => {
    return packets.filter(packet => {
      return (
        (filters.protocol === '' || packet.protocol.toLowerCase().includes(filters.protocol.toLowerCase())) &&
        (filters.source === '' || packet.source.includes(filters.source)) &&
        (filters.destination === '' || packet.destination.includes(filters.destination)) &&
        (filters.port === '' || packet.sourcePort?.toString().includes(filters.port) || packet.destPort?.toString().includes(filters.port))
      );
    });
  }, [packets, filters]);

  // Sort packets
  const sortedPackets = useMemo(() => {
    const sortablePackets = [...filteredPackets];
    if (sortConfig.key) {
      sortablePackets.sort((a, b) => {
        let aValue = a[sortConfig.key];
        let bValue = b[sortConfig.key];

        // Handle different data types
        if (sortConfig.key === 'timestamp') {
          aValue = new Date(aValue).getTime();
          bValue = new Date(bValue).getTime();
        } else if (typeof aValue === 'string') {
          aValue = aValue.toLowerCase();
          bValue = bValue.toLowerCase();
        }

        if (aValue < bValue) {
          return sortConfig.direction === 'asc' ? -1 : 1;
        }
        if (aValue > bValue) {
          return sortConfig.direction === 'asc' ? 1 : -1;
        }
        return 0;
      });
    }
    return sortablePackets;
  }, [filteredPackets, sortConfig]);

  // Pagination
  const totalPages = Math.ceil(sortedPackets.length / pageSize);
  const startIndex = (currentPage - 1) * pageSize;
  const paginatedPackets = sortedPackets.slice(startIndex, startIndex + pageSize);

  // Reset to first page when filters change
  useEffect(() => {
    setCurrentPage(1);
  }, [filters]);

  const SortButton = ({ column, children }) => (
    <button
      onClick={() => handleSort(column)}
      className="flex items-center space-x-1 hover:bg-gray-100 px-2 py-1 rounded text-left w-full"
    >
      <span>{children}</span>
      {sortConfig.key === column && (
        sortConfig.direction === 'asc' ? 
          <ChevronUp className="w-4 h-4" /> : 
          <ChevronDown className="w-4 h-4" />
      )}
    </button>
  );

  const exportToCSV = () => {
    const headers = ['Timestamp', 'Source', 'Destination', 'Protocol', 'Length', 'Info'];
    const csvContent = [
      headers.join(','),
      ...sortedPackets.map(packet => [
        packet.timestamp,
        packet.source,
        packet.destination,
        packet.protocol,
        packet.length,
        packet.info?.replace(/,/g, ';') || ''
      ].join(','))
    ].join('\n');

    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `packets_${new Date().toISOString().split('T')[0]}.csv`;
    a.click();
    window.URL.revokeObjectURL(url);
  };

  return (
    <div className="bg-white rounded-lg shadow-lg overflow-hidden">
      {/* Header Controls */}
      <div className="bg-gray-50 border-b border-gray-200 p-4">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-gray-900">Network Packets</h2>
          <div className="flex items-center space-x-2">
            <button
              onClick={onToggleRealTime}
              className={`flex items-center space-x-2 px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                realTimeEnabled 
                  ? 'bg-green-100 text-green-800 hover:bg-green-200' 
                  : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
              }`}
            >
              {realTimeEnabled ? <Pause className="w-4 h-4" /> : <Play className="w-4 h-4" />}
              {realTimeEnabled ? 'Pause' : 'Resume'}
            </button>
            <button
              onClick={exportToCSV}
              className="flex items-center space-x-2 px-3 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors text-sm font-medium"
            >
              <Download className="w-4 h-4" />
              Export CSV
            </button>
          </div>
        </div>

        {/* Filters */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Protocol</label>
            <input
              type="text"
              placeholder="Filter by protocol..."
              value={filters.protocol}
              onChange={(e) => setFilters(prev => ({ ...prev, protocol: e.target.value }))}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent text-sm"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Source IP</label>
            <input
              type="text"
              placeholder="Filter by source..."
              value={filters.source}
              onChange={(e) => setFilters(prev => ({ ...prev, source: e.target.value }))}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent text-sm"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Destination IP</label>
            <input
              type="text"
              placeholder="Filter by destination..."
              value={filters.destination}
              onChange={(e) => setFilters(prev => ({ ...prev, destination: e.target.value }))}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent text-sm"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Port</label>
            <input
              type="text"
              placeholder="Filter by port..."
              value={filters.port}
              onChange={(e) => setFilters(prev => ({ ...prev, port: e.target.value }))}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent text-sm"
            />
          </div>
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                <SortButton column="timestamp">Time</SortButton>
              </th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                <SortButton column="source">Source</SortButton>
              </th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                <SortButton column="destination">Destination</SortButton>
              </th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                <SortButton column="protocol">Protocol</SortButton>
              </th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                <SortButton column="length">Length</SortButton>
              </th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Threat
              </th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Info
              </th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Actions
              </th>
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-200">
            {loading ? (
              <tr>
                <td colSpan="8" className="px-4 py-8 text-center">
                  <div className="flex items-center justify-center">
                    <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
                    <span className="ml-2 text-gray-600">Loading packets...</span>
                  </div>
                </td>
              </tr>
            ) : paginatedPackets.length === 0 ? (
              <tr>
                <td colSpan="8" className="px-4 py-8 text-center text-gray-500">
                  No packets found matching the current filters.
                </td>
              </tr>
            ) : (
              paginatedPackets.map((packet, index) => (
                <tr
                  key={packet.id || `packet-${startIndex + index}`}
                  className={`hover:bg-gray-50 cursor-pointer transition-colors ${
                    selectedPacket?.id === packet.id ? 'bg-blue-50 border-l-4 border-blue-500' : ''
                  }`}
                  onClick={() => onPacketSelect && onPacketSelect(packet)}
                >
                  <td className="px-4 py-3 whitespace-nowrap text-sm text-gray-900 font-mono">
                    {formatTimestamp(packet.timestamp)}
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap text-sm text-gray-900 font-mono">
                    <div>
                      <div>{packet.source}</div>
                      {packet.sourcePort && (
                        <div className="text-xs text-gray-500">:{packet.sourcePort}</div>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap text-sm text-gray-900 font-mono">
                    <div>
                      <div>{packet.destination}</div>
                      {packet.destPort && (
                        <div className="text-xs text-gray-500">:{packet.destPort}</div>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap">
                    <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${
                      protocolColors[packet.protocol] || 'bg-gray-100 text-gray-800'
                    }`}>
                      {packet.protocol}
                    </span>
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap text-sm text-gray-900">
                    {formatBytes(packet.length)}
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap">
                    <div className="flex items-center">
                      <div className={`w-3 h-3 rounded-full mr-2 ${getThreatLevelClass(packet.threatLevel)}`}></div>
                      <span className="text-xs text-gray-600 capitalize">
                        {packet.threatLevel || 'none'}
                      </span>
                    </div>
                  </td>
                  <td className="px-4 py-3 text-sm text-gray-900 max-w-xs truncate">
                    {packet.info || 'No additional information'}
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap text-sm font-medium">
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        onPacketSelect && onPacketSelect(packet);
                      }}
                      className="text-blue-600 hover:text-blue-900 transition-colors"
                    >
                      <Eye className="w-4 h-4" />
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="bg-white px-4 py-3 border-t border-gray-200 sm:px-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <span className="text-sm text-gray-700">
                Showing {startIndex + 1} to {Math.min(startIndex + pageSize, sortedPackets.length)} of{' '}
                {sortedPackets.length} packets
              </span>
              <select
                value={pageSize}
                onChange={(e) => {
                  setPageSize(Number(e.target.value));
                  setCurrentPage(1);
                }}
                className="ml-2 px-2 py-1 border border-gray-300 rounded text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value={25}>25 per page</option>
                <option value={50}>50 per page</option>
                <option value={100}>100 per page</option>
                <option value={200}>200 per page</option>
              </select>
            </div>
            <div className="flex items-center space-x-2">
              <button
                onClick={() => setCurrentPage(prev => Math.max(prev - 1, 1))}
                disabled={currentPage === 1}
                className="px-3 py-2 text-sm font-medium text-gray-500 bg-white border border-gray-300 rounded-md hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Previous
              </button>
              <span className="text-sm text-gray-700">
                Page {currentPage} of {totalPages}
              </span>
              <button
                onClick={() => setCurrentPage(prev => Math.min(prev + 1, totalPages))}
                disabled={currentPage === totalPages}
                className="px-3 py-2 text-sm font-medium text-gray-500 bg-white border border-gray-300 rounded-md hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Next
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

  export default PacketTable;