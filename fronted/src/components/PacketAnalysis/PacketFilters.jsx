import React, { useState, useEffect } from 'react';
import { Search, Filter, X, ChevronDown, Calendar, Clock, Globe, Shield, Zap } from 'lucide-react';

const PacketFilters = ({ onFiltersChange, initialFilters = {} }) => {
  const [filters, setFilters] = useState({
    search: '',
    protocol: 'all',
    sourceIp: '',
    destIp: '',
    sourcePort: '',
    destPort: '',
    timeRange: '1h',
    customTimeStart: '',
    customTimeEnd: '',
    packetSize: { min: '', max: '' },
    flags: [],
    severity: 'all',
    status: 'all',
    ...initialFilters
  });

  const [showAdvanced, setShowAdvanced] = useState(false);
  const [activeFiltersCount, setActiveFiltersCount] = useState(0);

  const protocols = [
    { value: 'all', label: 'All Protocols' },
    { value: 'tcp', label: 'TCP' },
    { value: 'udp', label: 'UDP' },
    { value: 'http', label: 'HTTP' },
    { value: 'https', label: 'HTTPS' },
    { value: 'dns', label: 'DNS' },
    { value: 'ftp', label: 'FTP' },
    { value: 'ssh', label: 'SSH' },
    { value: 'smtp', label: 'SMTP' },
    { value: 'icmp', label: 'ICMP' },
    { value: 'dhcp', label: 'DHCP' },
    { value: 'arp', label: 'ARP' }
  ];

  const timeRanges = [
    { value: '5m', label: 'Last 5 minutes' },
    { value: '15m', label: 'Last 15 minutes' },
    { value: '1h', label: 'Last hour' },
    { value: '6h', label: 'Last 6 hours' },
    { value: '24h', label: 'Last 24 hours' },
    { value: '7d', label: 'Last 7 days' },
    { value: 'custom', label: 'Custom range' }
  ];

  const tcpFlags = [
    { value: 'syn', label: 'SYN' },
    { value: 'ack', label: 'ACK' },
    { value: 'fin', label: 'FIN' },
    { value: 'rst', label: 'RST' },
    { value: 'psh', label: 'PSH' },
    { value: 'urg', label: 'URG' }
  ];

  const severityLevels = [
    { value: 'all', label: 'All Severity' },
    { value: 'low', label: 'Low', color: 'text-green-600' },
    { value: 'medium', label: 'Medium', color: 'text-yellow-600' },
    { value: 'high', label: 'High', color: 'text-orange-600' },
    { value: 'critical', label: 'Critical', color: 'text-red-600' }
  ];

  const statusOptions = [
    { value: 'all', label: 'All Status' },
    { value: 'normal', label: 'Normal' },
    { value: 'suspicious', label: 'Suspicious' },
    { value: 'blocked', label: 'Blocked' },
    { value: 'allowed', label: 'Allowed' }
  ];

  // Count active filters
  useEffect(() => {
    let count = 0;
    if (filters.search) count++;
    if (filters.protocol !== 'all') count++;
    if (filters.sourceIp) count++;
    if (filters.destIp) count++;
    if (filters.sourcePort) count++;
    if (filters.destPort) count++;
    if (filters.timeRange !== '1h') count++;
    if (filters.packetSize.min || filters.packetSize.max) count++;
    if (filters.flags.length > 0) count++;
    if (filters.severity !== 'all') count++;
    if (filters.status !== 'all') count++;
    
    setActiveFiltersCount(count);
  }, [filters]);

  // Notify parent component of filter changes
  useEffect(() => {
    onFiltersChange?.(filters);
  }, [filters, onFiltersChange]);

  const handleFilterChange = (key, value) => {
    setFilters(prev => ({
      ...prev,
      [key]: value
    }));
  };

  const handleFlagToggle = (flag) => {
    setFilters(prev => ({
      ...prev,
      flags: prev.flags.includes(flag)
        ? prev.flags.filter(f => f !== flag)
        : [...prev.flags, flag]
    }));
  };

  const handlePacketSizeChange = (type, value) => {
    setFilters(prev => ({
      ...prev,
      packetSize: {
        ...prev.packetSize,
        [type]: value
      }
    }));
  };

  const clearAllFilters = () => {
    setFilters({
      search: '',
      protocol: 'all',
      sourceIp: '',
      destIp: '',
      sourcePort: '',
      destPort: '',
      timeRange: '1h',
      customTimeStart: '',
      customTimeEnd: '',
      packetSize: { min: '', max: '' },
      flags: [],
      severity: 'all',
      status: 'all'
    });
  };

  const clearFilter = (filterKey) => {
    if (filterKey === 'packetSize') {
      handleFilterChange('packetSize', { min: '', max: '' });
    } else if (filterKey === 'flags') {
      handleFilterChange('flags', []);
    } else {
      handleFilterChange(filterKey, filterKey === 'protocol' || filterKey === 'severity' || filterKey === 'status' ? 'all' : '');
    }
  };

  return (
    <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center space-x-2">
          <Filter className="w-5 h-5 text-gray-600" />
          <h3 className="text-lg font-semibold text-gray-900">Packet Filters</h3>
          {activeFiltersCount > 0 && (
            <span className="bg-blue-100 text-blue-800 text-xs font-medium px-2.5 py-0.5 rounded-full">
              {activeFiltersCount} active
            </span>
          )}
        </div>
        <div className="flex items-center space-x-2">
          <button
            onClick={() => setShowAdvanced(!showAdvanced)}
            className="flex items-center space-x-1 text-sm text-gray-600 hover:text-gray-900 transition-colors"
          >
            <span>Advanced</span>
            <ChevronDown className={`w-4 h-4 transition-transform ${showAdvanced ? 'rotate-180' : ''}`} />
          </button>
          {activeFiltersCount > 0 && (
            <button
              onClick={clearAllFilters}
              className="text-sm text-red-600 hover:text-red-800 transition-colors"
            >
              Clear All
            </button>
          )}
        </div>
      </div>

      {/* Basic Filters */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4 mb-6">
        {/* Search */}
        <div className="relative">
          <label className="block text-sm font-medium text-gray-700 mb-1">Search</label>
          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
            <input
              type="text"
              value={filters.search}
              onChange={(e) => handleFilterChange('search', e.target.value)}
              placeholder="Search packets..."
              className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
            {filters.search && (
              <button
                onClick={() => clearFilter('search')}
                className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-gray-600"
              >
                <X className="w-4 h-4" />
              </button>
            )}
          </div>
        </div>

        {/* Protocol */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">Protocol</label>
          <select
            value={filters.protocol}
            onChange={(e) => handleFilterChange('protocol', e.target.value)}
            className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          >
            {protocols.map(proto => (
              <option key={proto.value} value={proto.value}>
                {proto.label}
              </option>
            ))}
          </select>
        </div>

        {/* Time Range */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            <Clock className="inline w-4 h-4 mr-1" />
            Time Range
          </label>
          <select
            value={filters.timeRange}
            onChange={(e) => handleFilterChange('timeRange', e.target.value)}
            className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          >
            {timeRanges.map(range => (
              <option key={range.value} value={range.value}>
                {range.label}
              </option>
            ))}
          </select>
        </div>

        {/* Severity */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            <Shield className="inline w-4 h-4 mr-1" />
            Severity
          </label>
          <select
            value={filters.severity}
            onChange={(e) => handleFilterChange('severity', e.target.value)}
            className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          >
            {severityLevels.map(level => (
              <option key={level.value} value={level.value}>
                {level.label}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Custom Time Range */}
      {filters.timeRange === 'custom' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6 p-4 bg-gray-50 rounded-lg">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Start Time</label>
            <input
              type="datetime-local"
              value={filters.customTimeStart}
              onChange={(e) => handleFilterChange('customTimeStart', e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">End Time</label>
            <input
              type="datetime-local"
              value={filters.customTimeEnd}
              onChange={(e) => handleFilterChange('customTimeEnd', e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
          </div>
        </div>
      )}

      {/* Advanced Filters */}
      {showAdvanced && (
        <div className="border-t border-gray-200 pt-6">
          <h4 className="text-md font-medium text-gray-900 mb-4 flex items-center">
            <Zap className="w-4 h-4 mr-2" />
            Advanced Filters
          </h4>
          
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4 mb-4">
            {/* Source IP */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                <Globe className="inline w-4 h-4 mr-1" />
                Source IP
              </label>
              <input
                type="text"
                value={filters.sourceIp}
                onChange={(e) => handleFilterChange('sourceIp', e.target.value)}
                placeholder="192.168.1.1"
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>

            {/* Destination IP */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                <Globe className="inline w-4 h-4 mr-1" />
                Destination IP
              </label>
              <input
                type="text"
                value={filters.destIp}
                onChange={(e) => handleFilterChange('destIp', e.target.value)}
                placeholder="192.168.1.2"
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>

            {/* Source Port */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Source Port</label>
              <input
                type="number"
                value={filters.sourcePort}
                onChange={(e) => handleFilterChange('sourcePort', e.target.value)}
                placeholder="80"
                min="1"
                max="65535"
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>

            {/* Destination Port */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Destination Port</label>
              <input
                type="number"
                value={filters.destPort}
                onChange={(e) => handleFilterChange('destPort', e.target.value)}
                placeholder="443"
                min="1"
                max="65535"
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>

            {/* Status */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Status</label>
              <select
                value={filters.status}
                onChange={(e) => handleFilterChange('status', e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              >
                {statusOptions.map(status => (
                  <option key={status.value} value={status.value}>
                    {status.label}
                  </option>
                ))}
              </select>
            </div>
          </div>

          {/* Packet Size Range */}
          <div className="mb-4">
            <label className="block text-sm font-medium text-gray-700 mb-2">Packet Size (bytes)</label>
            <div className="flex items-center space-x-2">
              <input
                type="number"
                value={filters.packetSize.min}
                onChange={(e) => handlePacketSizeChange('min', e.target.value)}
                placeholder="Min"
                min="0"
                className="flex-1 px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
              <span className="text-gray-500">to</span>
              <input
                type="number"
                value={filters.packetSize.max}
                onChange={(e) => handlePacketSizeChange('max', e.target.value)}
                placeholder="Max"
                min="0"
                className="flex-1 px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
          </div>

          {/* TCP Flags */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">TCP Flags</label>
            <div className="flex flex-wrap gap-2">
              {tcpFlags.map(flag => (
                <label key={flag.value} className="inline-flex items-center">
                  <input
                    type="checkbox"
                    checked={filters.flags.includes(flag.value)}
                    onChange={() => handleFlagToggle(flag.value)}
                    className="rounded border-gray-300 text-blue-600 shadow-sm focus:border-blue-300 focus:ring focus:ring-blue-200 focus:ring-opacity-50"
                  />
                  <span className="ml-2 text-sm text-gray-700">{flag.label}</span>
                </label>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Active Filters Display */}
      {activeFiltersCount > 0 && (
        <div className="mt-4 pt-4 border-t border-gray-200">
          <div className="flex flex-wrap gap-2">
            {filters.search && (
              <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                Search: {filters.search}
                <button onClick={() => clearFilter('search')} className="ml-1 text-blue-600 hover:text-blue-800">
                  <X className="w-3 h-3" />
                </button>
              </span>
            )}
            {filters.protocol !== 'all' && (
              <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                Protocol: {filters.protocol.toUpperCase()}
                <button onClick={() => clearFilter('protocol')} className="ml-1 text-green-600 hover:text-green-800">
                  <X className="w-3 h-3" />
                </button>
              </span>
            )}
            {filters.sourceIp && (
              <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-purple-100 text-purple-800">
                Source IP: {filters.sourceIp}
                <button onClick={() => clearFilter('sourceIp')} className="ml-1 text-purple-600 hover:text-purple-800">
                  <X className="w-3 h-3" />
                </button>
              </span>
            )}
            {filters.destIp && (
              <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-purple-100 text-purple-800">
                Dest IP: {filters.destIp}
                <button onClick={() => clearFilter('destIp')} className="ml-1 text-purple-600 hover:text-purple-800">
                  <X className="w-3 h-3" />
                </button>
              </span>
            )}
            {(filters.packetSize.min || filters.packetSize.max) && (
              <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-yellow-100 text-yellow-800">
                Size: {filters.packetSize.min || '0'}-{filters.packetSize.max || '∞'} bytes
                <button onClick={() => clearFilter('packetSize')} className="ml-1 text-yellow-600 hover:text-yellow-800">
                  <X className="w-3 h-3" />
                </button>
              </span>
            )}
            {filters.flags.length > 0 && (
              <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800">
                Flags: {filters.flags.join(', ').toUpperCase()}
                <button onClick={() => clearFilter('flags')} className="ml-1 text-red-600 hover:text-red-800">
                  <X className="w-3 h-3" />
                </button>
              </span>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

  export default PacketFilters;