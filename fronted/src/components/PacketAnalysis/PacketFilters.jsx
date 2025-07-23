import React from 'react';
import { Search, Filter, Download, RefreshCw } from 'lucide-react';

const PacketFilters = ({ filters, onFiltersChange, packets }) => {
  const handleFilterChange = (key, value) => {
    onFiltersChange(prev => ({ ...prev, [key]: value }));
  };

  const clearFilters = () => {
    onFiltersChange({
      search: '',
      protocol: 'all',
      status: 'all'
    });
  };

  const protocols = [...new Set(packets.map(p => p.protocol))];
  const statuses = [...new Set(packets.map(p => p.status))];

  return (
    <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-4">
      <div className="flex flex-wrap items-center gap-4">
        {/* Search */}
        <div className="flex-1 min-w-64">
          <div className="relative">
            <Search className="w-4 h-4 text-gray-400 absolute left-3 top-1/2 transform -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search by IP, protocol, or port..."
              value={filters.search}
              onChange={(e) => handleFilterChange('search', e.target.value)}
              className="pl-10 pr-4 py-2 w-full border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
          </div>
        </div>

        {/* Protocol Filter */}
        <div className="min-w-32">
          <select
            value={filters.protocol}
            onChange={(e) => handleFilterChange('protocol', e.target.value)}
            className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          >
            <option value="all">All Protocols</option>
            {protocols.map(protocol => (
              <option key={protocol} value={protocol}>{protocol}</option>
            ))}
          </select>
        </div>

        {/* Status Filter */}
        <div className="min-w-32">
          <select
            value={filters.status}
            onChange={(e) => handleFilterChange('status', e.target.value)}
            className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          >
            <option value="all">All Status</option>
            {statuses.map(status => (
              <option key={status} value={status}>
                {status.charAt(0).toUpperCase() + status.slice(1)}
              </option>
            ))}
          </select>
        </div>

        {/* Action Buttons */}
        <div className="flex items-center space-x-2">
          <button
            onClick={clearFilters}
            className="flex items-center space-x-1 px-3 py-2 text-gray-600 hover:text-gray-800 hover:bg-gray-100 rounded-lg transition-colors"
          >
            <RefreshCw className="w-4 h-4" />
            <span>Clear</span>
          </button>
          
          <button className="flex items-center space-x-1 px-3 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors">
            <Download className="w-4 h-4" />
            <span>Export</span>
          </button>
        </div>
      </div>

      {/* Active Filters */}
      {(filters.search || filters.protocol !== 'all' || filters.status !== 'all') && (
        <div className="flex items-center space-x-2 mt-4 pt-4 border-t border-gray-200">
          <Filter className="w-4 h-4 text-gray-500" />
          <span className="text-sm text-gray-600">Active filters:</span>
          
          {filters.search && (
            <span className="px-2 py-1 bg-blue-100 text-blue-800 text-xs rounded-full">
              Search: {filters.search}
            </span>
          )}
          
          {filters.protocol !== 'all' && (
            <span className="px-2 py-1 bg-green-100 text-green-800 text-xs rounded-full">
              Protocol: {filters.protocol}
            </span>
          )}
          
          {filters.status !== 'all' && (
            <span className="px-2 py-1 bg-yellow-100 text-yellow-800 text-xs rounded-full">
              Status: {filters.status}
            </span>
          )}
        </div>
      )}
    </div>
  );
};

export default PacketFilters;