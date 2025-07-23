import React from 'react';
import { X, Clock, MapPin, Shield, Activity } from 'lucide-react';

const PacketDetails = ({ packet, onClose }) => {
  if (!packet) return null;

  const formatBytes = (bytes) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  const getStatusColor = (status) => {
    return status === 'suspicious' 
      ? 'bg-red-100 text-red-800' 
      : 'bg-green-100 text-green-800';
  };

  const getProtocolColor = (protocol) => {
    const colors = {
      'HTTPS': 'bg-green-100 text-green-800',
      'HTTP': 'bg-blue-100 text-blue-800',
      'DNS': 'bg-purple-100 text-purple-800',
      'SSH': 'bg-yellow-100 text-yellow-800',
      'TCP': 'bg-indigo-100 text-indigo-800',
      'UDP': 'bg-orange-100 text-orange-800'
    };
    return colors[protocol] || 'bg-gray-100 text-gray-800';
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-xl shadow-2xl max-w-2xl w-full mx-4 max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-gray-200">
          <div>
            <h2 className="text-xl font-semibold text-gray-900">Packet Details</h2>
            <p className="text-sm text-gray-500">ID: {packet.id}</p>
          </div>
          <button
            onClick={onClose}
            className="p-2 hover:bg-gray-100 rounded-lg transition-colors"
          >
            <X className="w-5 h-5 text-gray-500" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 space-y-6">
          {/* Basic Info */}
          <div className="grid grid-cols-2 gap-6">
            <div className="space-y-4">
              <div>
                <h3 className="text-sm font-medium text-gray-700 mb-2">Source</h3>
                <div className="flex items-center space-x-2">
                  <MapPin className="w-4 h-4 text-blue-500" />
                  <span className="font-mono text-sm">{packet.source}:{packet.port}</span>
                </div>
              </div>

              <div>
                <h3 className="text-sm font-medium text-gray-700 mb-2">Protocol</h3>
                <span className={`px-2 py-1 rounded text-xs font-medium ${getProtocolColor(packet.protocol)}`}>
                  {packet.protocol}
                </span>
              </div>

              <div>
                <h3 className="text-sm font-medium text-gray-700 mb-2">Size</h3>
                <div className="flex items-center space-x-2">
                  <Activity className="w-4 h-4 text-green-500" />
                  <span>{formatBytes(packet.size)}</span>
                </div>
              </div>
            </div>

            <div className="space-y-4">
              <div>
                <h3 className="text-sm font-medium text-gray-700 mb-2">Destination</h3>
                <div className="flex items-center space-x-2">
                  <MapPin className="w-4 h-4 text-red-500" />
                  <span className="font-mono text-sm">{packet.destination}:{packet.destinationPort || packet.port}</span>
                </div>
              </div>

              <div>
                <h3 className="text-sm font-medium text-gray-700 mb-2">Status</h3>
                <div className="flex items-center space-x-2">
                  <Shield className="w-4 h-4" />
                  <span className={`px-2 py-1 rounded text-xs font-medium ${getStatusColor(packet.status)}`}>
                    {packet.status}
                  </span>
                </div>
              </div>

              <div>
                <h3 className="text-sm font-medium text-gray-700 mb-2">Timestamp</h3>
                <div className="flex items-center space-x-2">
                  <Clock className="w-4 h-4 text-purple-500" />
                  <span>{new Date(packet.timestamp).toLocaleString()}</span>
                </div>
              </div>
            </div>
          </div>

          {/* Additional Details */}
          <div className="border-t border-gray-200 pt-6">
            <h3 className="text-lg font-medium text-gray-900 mb-4">Additional Information</h3>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="bg-gray-50 rounded-lg p-4">
                <h4 className="font-medium text-gray-700 mb-2">Network Details</h4>
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-gray-500">TTL:</span>
                    <span>{packet.ttl || '64'}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-500">Flags:</span>
                    <span>{packet.flags || 'PSH, ACK'}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-500">Window Size:</span>
                    <span>{packet.windowSize || '65535'}</span>
                  </div>
                </div>
              </div>

              <div className="bg-gray-50 rounded-lg p-4">
                <h4 className="font-medium text-gray-700 mb-2">Security Analysis</h4>
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-gray-500">Risk Score:</span>
                    <span className={packet.status === 'suspicious' ? 'text-red-600' : 'text-green-600'}>
                      {packet.status === 'suspicious' ? 'High (85%)' : 'Low (15%)'}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-500">Encrypted:</span>
                    <span>{packet.protocol.includes('HTTPS') || packet.protocol.includes('SSH') ? 'Yes' : 'No'}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-500">Geo Location:</span>
                    <span>{packet.geoLocation || 'US-East'}</span>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Payload Preview */}
          {packet.payload && (
            <div className="border-t border-gray-200 pt-6">
              <h3 className="text-lg font-medium text-gray-900 mb-4">Payload Preview</h3>
              <div className="bg-gray-900 text-gray-100 p-4 rounded-lg font-mono text-sm overflow-x-auto">
                <pre>{packet.payload}</pre>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex justify-end space-x-3 p-6 border-t border-gray-200">
          <button
            onClick={onClose}
            className="px-4 py-2 text-gray-700 border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors"
          >
            Close
          </button>
          <button className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors">
            Export Details
          </button>
        </div>
      </div>
    </div>
  );
};

export default PacketDetails;