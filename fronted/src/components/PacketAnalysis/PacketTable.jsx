import React, { useState } from 'react';
import { Filter } from 'lucide-react';
import PacketFilters from './PacketFilters';
import { usePacketData } from '../../hooks/usePacketData';

const PacketTable = () => {
  const { packets, loading } = usePacketData();
  const [filters, setFilters] = useState({
    search: '',
    protocol: 'all',
    status: 'all'
  });

  const filteredPackets = packets.filter(packet => {
    const matchesSearch = packet.source.includes(filters.search) || 
                         packet.destination.includes(filters.search) ||
                         packet.protocol.toLowerCase().includes(filters.search.toLowerCase());
    const matchesProtocol = filters.protocol === 'all' || packet.protocol === filters.protocol;
    const matchesStatus = filters.status === 'all' || packet.status === filters.status;
    
    return matchesSearch && matchesProtocol && matchesStatus;
  });

  if (loading) {
    return (
      <div className="p-6 flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-3xl font-bold text-slate-800">Packet Analysis</h2>
        <div className="flex items-center space-x-2 text-sm text-slate-600">
          <Filter className="w-4 h-4" />
          <span>{filteredPackets.length} of {packets.length} packets</span>
        </div>
      </div>

      <PacketFilters 
        filters={filters}
        onFiltersChange={setFilters}
        packets={packets}
      />

      <div className="bg-white rounded-lg shadow-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-slate-50">
              <tr>
                <th className="text-left p-4 font-semibold text-slate-700">Timestamp</th>
                <th className="text-left p-4 font-semibold text-slate-700">Source</th>
                <th className="text-left p-4 font-semibold text-slate-700">Destination</th>
                <th className="text-left p-4 font-semibold text-slate-700">Protocol</th>
                <th className="text-left p-4 font-semibold text-slate-700">Size</th>
                <th className="text-left p-4 font-semibold text-slate-700">Port</th>
                <th className="text-left p-4 font-semibold text-slate-700">Status</th>
              </tr>
            </thead>
            <tbody>
              {filteredPackets.slice(0, 50).map(packet => (
                <tr key={packet.id} className="border-t border-slate-200 hover:bg-slate-50">
                  <td className="p-4 text-sm text-slate-600">
                    {new Date(packet.timestamp).toLocaleTimeString()}
                  </td>
                  <td className="p-4 font-mono text-sm">{packet.source}</td>
                  <td className="p-4 font-mono text-sm">{packet.destination}</td>
                  <td className="p-4">
                    <span className={`px-2 py-1 rounded text-xs font-medium ${
                      packet.protocol === 'HTTPS' ? 'bg-green-100 text-green-800' :
                      packet.protocol === 'HTTP' ? 'bg-blue-100 text-blue-800' :
                      packet.protocol === 'DNS' ? 'bg-purple-100 text-purple-800' :
                      packet.protocol === 'SSH' ? 'bg-yellow-100 text-yellow-800' :
                      'bg-slate-100 text-slate-800'
                    }`}>
                      {packet.protocol}
                    </span>
                  </td>
                  <td className="p-4 text-sm">{packet.size} bytes</td>
                  <td className="p-4 text-sm">{packet.port}</td>
                  <td className="p-4">
                    <span className={`px-2 py-1 rounded text-xs font-medium ${
                      packet.status === 'suspicious' ? 'bg-red-100 text-red-800' : 'bg-green-100 text-green-800'
                    }`}>
                      {packet.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {filteredPackets.length === 0 && (
          <div className="text-center py-8 text-slate-500">
            <p>No packets match the current filters</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default PacketTable;