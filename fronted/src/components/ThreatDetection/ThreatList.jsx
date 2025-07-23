import React, { useState, useEffect, useMemo } from 'react';
import { 
  AlertTriangle, 
  Shield, 
  Eye, 
  Filter, 
  Search, 
  Clock, 
  MapPin, 
  Activity,
  ChevronDown,
  ChevronUp,
  X
} from 'lucide-react';

const ThreatList = ({ 
  threats = [], 
  onThreatSelect, 
  onThreatAction,
  realTimeUpdates = true 
}) => {
  const [selectedThreats, setSelectedThreats] = useState(new Set());
  const [sortConfig, setSortConfig] = useState({ key: 'timestamp', direction: 'desc' });
  const [filterConfig, setFilterConfig] = useState({
    severity: 'all',
    status: 'all',
    type: 'all',
    searchTerm: ''
  });
  const [expandedRows, setExpandedRows] = useState(new Set());
  const [showFilters, setShowFilters] = useState(false);

  // Threat severity levels with colors
  const severityConfig = {
    critical: { color: 'text-red-600 bg-red-100', label: 'Critical', priority: 4 },
    high: { color: 'text-orange-600 bg-orange-100', label: 'High', priority: 3 },
    medium: { color: 'text-yellow-600 bg-yellow-100', label: 'Medium', priority: 2 },
    low: { color: 'text-blue-600 bg-blue-100', label: 'Low', priority: 1 },
    info: { color: 'text-gray-600 bg-gray-100', label: 'Info', priority: 0 }
  };

  // Threat status configuration
  const statusConfig = {
    active: { color: 'text-red-600 bg-red-100', label: 'Active' },
    investigating: { color: 'text-yellow-600 bg-yellow-100', label: 'Investigating' },
    resolved: { color: 'text-green-600 bg-green-100', label: 'Resolved' },
    false_positive: { color: 'text-gray-600 bg-gray-100', label: 'False Positive' }
  };

  // Filter and sort threats
  const filteredAndSortedThreats = useMemo(() => {
    let result = [...threats];

    // Apply filters
    result = result.filter(threat => {
      const matchesSeverity = filterConfig.severity === 'all' || threat.severity === filterConfig.severity;
      const matchesStatus = filterConfig.status === 'all' || threat.status === filterConfig.status;
      const matchesType = filterConfig.type === 'all' || threat.type === filterConfig.type;
      const matchesSearch = !filterConfig.searchTerm || 
        threat.description.toLowerCase().includes(filterConfig.searchTerm.toLowerCase()) ||
        threat.source_ip?.toLowerCase().includes(filterConfig.searchTerm.toLowerCase()) ||
        threat.destination_ip?.toLowerCase().includes(filterConfig.searchTerm.toLowerCase());

      return matchesSeverity && matchesStatus && matchesType && matchesSearch;
    });

    // Apply sorting
    result.sort((a, b) => {
      let aValue = a[sortConfig.key];
      let bValue = b[sortConfig.key];

      // Handle special sorting cases
      if (sortConfig.key === 'severity') {
        aValue = severityConfig[a.severity]?.priority || 0;
        bValue = severityConfig[b.severity]?.priority || 0;
      } else if (sortConfig.key === 'timestamp') {
        aValue = new Date(a.timestamp).getTime();
        bValue = new Date(b.timestamp).getTime();
      }

      if (aValue < bValue) return sortConfig.direction === 'asc' ? -1 : 1;
      if (aValue > bValue) return sortConfig.direction === 'asc' ? 1 : -1;
      return 0;
    });

    return result;
  }, [threats, filterConfig, sortConfig]);

  // Handle sorting
  const handleSort = (key) => {
    setSortConfig(prev => ({
      key,
      direction: prev.key === key && prev.direction === 'asc' ? 'desc' : 'asc'
    }));
  };

  // Handle threat selection
  const handleThreatSelection = (threatId, checked) => {
    const newSelected = new Set(selectedThreats);
    if (checked) {
      newSelected.add(threatId);
    } else {
      newSelected.delete(threatId);
    }
    setSelectedThreats(newSelected);
  };

  // Handle select all
  const handleSelectAll = (checked) => {
    if (checked) {
      setSelectedThreats(new Set(filteredAndSortedThreats.map(t => t.id)));
    } else {
      setSelectedThreats(new Set());
    }
  };

  // Toggle row expansion
  const toggleRowExpansion = (threatId) => {
    const newExpanded = new Set(expandedRows);
    if (newExpanded.has(threatId)) {
      newExpanded.delete(threatId);
    } else {
      newExpanded.add(threatId);
    }
    setExpandedRows(newExpanded);
  };

  // Format timestamp
  const formatTimestamp = (timestamp) => {
    return new Date(timestamp).toLocaleString();
  };

  // Format IP address with port
  const formatEndpoint = (ip, port) => {
    return port ? `${ip}:${port}` : ip;
  };

  // Get unique values for filter dropdowns
  const getUniqueValues = (key) => {
    return [...new Set(threats.map(threat => threat[key]).filter(Boolean))];
  };

  return (
    <div className="bg-white rounded-lg shadow-lg">
      {/* Header */}
      <div className="px-6 py-4 border-b border-gray-200">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <Shield className="h-5 w-5 text-red-600" />
            <h2 className="text-lg font-semibold text-gray-900">
              Threat Detection ({filteredAndSortedThreats.length})
            </h2>
            {realTimeUpdates && (
              <div className="flex items-center space-x-1 text-green-600">
                <Activity className="h-4 w-4" />
                <span className="text-sm">Live</span>
              </div>
            )}
          </div>
          
          <div className="flex items-center space-x-2">
            {/* Search */}
            <div className="relative">
              <Search className="h-4 w-4 absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" />
              <input
                type="text"
                placeholder="Search threats..."
                className="pl-10 pr-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                value={filterConfig.searchTerm}
                onChange={(e) => setFilterConfig(prev => ({ ...prev, searchTerm: e.target.value }))}
              />
            </div>
            
            {/* Filter Toggle */}
            <button
              onClick={() => setShowFilters(!showFilters)}
              className={`px-3 py-2 border rounded-md flex items-center space-x-1 ${
                showFilters ? 'bg-blue-50 border-blue-300 text-blue-700' : 'border-gray-300 text-gray-700'
              }`}
            >
              <Filter className="h-4 w-4" />
              <span>Filters</span>
            </button>
          </div>
        </div>

        {/* Filters Panel */}
        {showFilters && (
          <div className="mt-4 p-4 bg-gray-50 rounded-md">
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              {/* Severity Filter */}
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Severity</label>
                <select
                  value={filterConfig.severity}
                  onChange={(e) => setFilterConfig(prev => ({ ...prev, severity: e.target.value }))}
                  className="w-full border border-gray-300 rounded-md px-3 py-2 focus:ring-2 focus:ring-blue-500"
                >
                  <option value="all">All Severities</option>
                  {Object.entries(severityConfig).map(([key, config]) => (
                    <option key={key} value={key}>{config.label}</option>
                  ))}
                </select>
              </div>

              {/* Status Filter */}
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Status</label>
                <select
                  value={filterConfig.status}
                  onChange={(e) => setFilterConfig(prev => ({ ...prev, status: e.target.value }))}
                  className="w-full border border-gray-300 rounded-md px-3 py-2 focus:ring-2 focus:ring-blue-500"
                >
                  <option value="all">All Statuses</option>
                  {Object.entries(statusConfig).map(([key, config]) => (
                    <option key={key} value={key}>{config.label}</option>
                  ))}
                </select>
              </div>

              {/* Type Filter */}
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Type</label>
                <select
                  value={filterConfig.type}
                  onChange={(e) => setFilterConfig(prev => ({ ...prev, type: e.target.value }))}
                  className="w-full border border-gray-300 rounded-md px-3 py-2 focus:ring-2 focus:ring-blue-500"
                >
                  <option value="all">All Types</option>
                  {getUniqueValues('type').map(type => (
                    <option key={type} value={type}>{type}</option>
                  ))}
                </select>
              </div>

              {/* Clear Filters */}
              <div className="flex items-end">
                <button
                  onClick={() => setFilterConfig({ severity: 'all', status: 'all', type: 'all', searchTerm: '' })}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md text-gray-700 hover:bg-gray-50 flex items-center justify-center space-x-1"
                >
                  <X className="h-4 w-4" />
                  <span>Clear</span>
                </button>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Bulk Actions */}
      {selectedThreats.size > 0 && (
        <div className="px-6 py-3 bg-blue-50 border-b border-gray-200">
          <div className="flex items-center justify-between">
            <span className="text-sm text-gray-700">
              {selectedThreats.size} threat{selectedThreats.size !== 1 ? 's' : ''} selected
            </span>
            <div className="flex space-x-2">
              <button
                onClick={() => onThreatAction && onThreatAction('investigate', Array.from(selectedThreats))}
                className="px-3 py-1 bg-yellow-600 text-white rounded text-sm hover:bg-yellow-700"
              >
                Mark as Investigating
              </button>
              <button
                onClick={() => onThreatAction && onThreatAction('resolve', Array.from(selectedThreats))}
                className="px-3 py-1 bg-green-600 text-white rounded text-sm hover:bg-green-700"
              >
                Mark as Resolved
              </button>
              <button
                onClick={() => onThreatAction && onThreatAction('false_positive', Array.from(selectedThreats))}
                className="px-3 py-1 bg-gray-600 text-white rounded text-sm hover:bg-gray-700"
              >
                False Positive
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Threat Table */}
      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-6 py-3 text-left">
                <input
                  type="checkbox"
                  checked={filteredAndSortedThreats.length > 0 && selectedThreats.size === filteredAndSortedThreats.length}
                  onChange={(e) => handleSelectAll(e.target.checked)}
                  className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                />
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                <button
                  onClick={() => handleSort('timestamp')}
                  className="flex items-center space-x-1 hover:text-gray-700"
                >
                  <Clock className="h-4 w-4" />
                  <span>Time</span>
                  {sortConfig.key === 'timestamp' && (
                    sortConfig.direction === 'asc' ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />
                  )}
                </button>
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                <button
                  onClick={() => handleSort('severity')}
                  className="flex items-center space-x-1 hover:text-gray-700"
                >
                  <AlertTriangle className="h-4 w-4" />
                  <span>Severity</span>
                  {sortConfig.key === 'severity' && (
                    sortConfig.direction === 'asc' ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />
                  )}
                </button>
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Description</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                <MapPin className="h-4 w-4 inline mr-1" />
                Source → Destination
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-200">
            {filteredAndSortedThreats.map((threat) => (
              <React.Fragment key={threat.id}>
                <tr className={`hover:bg-gray-50 ${selectedThreats.has(threat.id) ? 'bg-blue-50' : ''}`}>
                  <td className="px-6 py-4">
                    <input
                      type="checkbox"
                      checked={selectedThreats.has(threat.id)}
                      onChange={(e) => handleThreatSelection(threat.id, e.target.checked)}
                      className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                    />
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    {formatTimestamp(threat.timestamp)}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className={`px-2 py-1 text-xs font-medium rounded-full ${severityConfig[threat.severity]?.color}`}>
                      {severityConfig[threat.severity]?.label || threat.severity}
                    </span>
                  </td>
                  <td className="px-6 py-4">
                    <div className="text-sm text-gray-900 font-medium">{threat.type}</div>
                    <div className="text-sm text-gray-500">{threat.description}</div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    <div className="flex flex-col space-y-1">
                      <span>{formatEndpoint(threat.source_ip, threat.source_port)}</span>
                      <span className="text-gray-400">↓</span>
                      <span>{formatEndpoint(threat.destination_ip, threat.destination_port)}</span>
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className={`px-2 py-1 text-xs font-medium rounded-full ${statusConfig[threat.status]?.color}`}>
                      {statusConfig[threat.status]?.label || threat.status}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm font-medium space-x-2">
                    <button
                      onClick={() => toggleRowExpansion(threat.id)}
                      className="text-blue-600 hover:text-blue-900"
                    >
                      {expandedRows.has(threat.id) ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                    </button>
                    <button
                      onClick={() => onThreatSelect && onThreatSelect(threat)}
                      className="text-blue-600 hover:text-blue-900"
                    >
                      <Eye className="h-4 w-4" />
                    </button>
                  </td>
                </tr>
                
                {/* Expanded Row Details */}
                {expandedRows.has(threat.id) && (
                  <tr>
                    <td colSpan="7" className="px-6 py-4 bg-gray-50">
                      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 text-sm">
                        <div>
                          <strong className="text-gray-700">Protocol:</strong>
                          <span className="ml-2">{threat.protocol || 'Unknown'}</span>
                        </div>
                        <div>
                          <strong className="text-gray-700">Packets:</strong>
                          <span className="ml-2">{threat.packet_count || 'N/A'}</span>
                        </div>
                        <div>
                          <strong className="text-gray-700">Bytes:</strong>
                          <span className="ml-2">{threat.byte_count || 'N/A'}</span>
                        </div>
                        <div>
                          <strong className="text-gray-700">First Seen:</strong>
                          <span className="ml-2">{threat.first_seen ? formatTimestamp(threat.first_seen) : 'N/A'}</span>
                        </div>
                        <div>
                          <strong className="text-gray-700">Last Seen:</strong>
                          <span className="ml-2">{threat.last_seen ? formatTimestamp(threat.last_seen) : 'N/A'}</span>
                        </div>
                        <div>
                          <strong className="text-gray-700">Confidence:</strong>
                          <span className="ml-2">{threat.confidence ? `${threat.confidence}%` : 'N/A'}</span>
                        </div>
                        {threat.additional_info && (
                          <div className="col-span-full">
                            <strong className="text-gray-700">Additional Info:</strong>
                            <pre className="ml-2 mt-1 text-xs bg-white p-2 rounded border overflow-x-auto">
                              {JSON.stringify(threat.additional_info, null, 2)}
                            </pre>
                          </div>
                        )}
                      </div>
                    </td>
                  </tr>
                )}
              </React.Fragment>
            ))}
          </tbody>
        </table>

        {/* Empty State */}
        {filteredAndSortedThreats.length === 0 && (
          <div className="text-center py-12">
            <Shield className="mx-auto h-12 w-12 text-gray-400" />
            <h3 className="mt-2 text-sm font-medium text-gray-900">No threats detected</h3>
            <p className="mt-1 text-sm text-gray-500">
              {threats.length === 0 
                ? "Your network appears to be secure. No threats have been detected."
                : "No threats match your current filter criteria."
              }
            </p>
          </div>
        )}
      </div>
    </div>
  );
};

export default ThreatList;