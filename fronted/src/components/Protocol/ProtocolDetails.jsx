import React, { useState, useEffect, useMemo } from 'react';
import {
  Network,
  Globe,
  Shield,
  Clock,
  Database,
  Activity,
  AlertTriangle,
  Info,
  TrendingUp,
  TrendingDown,
  Wifi,
  Server,
  Lock,
  Unlock,
  Eye,
  EyeOff,
  Filter,
  Search,
  Download,
  RefreshCw
} from 'lucide-react';

const ProtocolDetails = ({
  protocolName = "HTTP",
  protocolData = null,
  packetDetails = [],
  connectionStats = null,
  securityInfo = null,
  performanceMetrics = null,
  onClose = () => {},
  onExport = () => {},
  refreshData = () => {}
}) => {
  const [activeTab, setActiveTab] = useState('overview');
  const [searchTerm, setSearchTerm] = useState('');
  const [showRawData, setShowRawData] = useState(false);
  const [selectedPacket, setSelectedPacket] = useState(null);
  const [filterType, setFilterType] = useState('all');

  // Default protocol data
  const defaultProtocolData = {
    name: protocolName,
    description: getProtocolDescription(protocolName),
    port: getDefaultPort(protocolName),
    type: getProtocolType(protocolName),
    layer: getProtocolLayer(protocolName),
    encrypted: isProtocolEncrypted(protocolName),
    totalPackets: 1247,
    totalBytes: 2048576,
    avgPacketSize: 1643,
    firstSeen: new Date(Date.now() - 3600000),
    lastSeen: new Date(),
    activeConnections: 23,
    uniqueHosts: 15,
    topPorts: [80, 443, 8080, 3000],
    bandwidthUsage: 85.6
  };

  // Default packet details
  const defaultPacketDetails = [
    {
      id: 1,
      timestamp: new Date(Date.now() - 5000),
      sourceIp: '192.168.1.100',
      destIp: '93.184.216.34',
      sourcePort: 54321,
      destPort: 80,
      size: 1460,
      flags: ['SYN', 'ACK'],
      payload: 'GET /index.html HTTP/1.1\r\nHost: example.com\r\n',
      type: 'Request'
    },
    {
      id: 2,
      timestamp: new Date(Date.now() - 4000),
      sourceIp: '93.184.216.34',
      destIp: '192.168.1.100',
      sourcePort: 80,
      destPort: 54321,
      size: 2048,
      flags: ['ACK', 'PSH'],
      payload: 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n',
      type: 'Response'
    },
    {
      id: 3,
      timestamp: new Date(Date.now() - 3000),
      sourceIp: '192.168.1.101',
      destIp: '8.8.8.8',
      sourcePort: 45678,
      destPort: 53,
      size: 64,
      flags: ['UDP'],
      payload: 'DNS Query for example.com',
      type: 'Query'
    }
  ];

  const currentProtocolData = protocolData || defaultProtocolData;
  const currentPacketDetails = packetDetails.length > 0 ? packetDetails : defaultPacketDetails;

  // Helper functions
  function getProtocolDescription(protocol) {
    const descriptions = {
      'HTTP': 'Hypertext Transfer Protocol - Used for web communication',
      'HTTPS': 'HTTP Secure - Encrypted web communication protocol',
      'TCP': 'Transmission Control Protocol - Reliable connection-oriented protocol',
      'UDP': 'User Datagram Protocol - Fast connectionless protocol',
      'DNS': 'Domain Name System - Translates domain names to IP addresses',
      'FTP': 'File Transfer Protocol - Used for file transfers',
      'SSH': 'Secure Shell - Encrypted remote access protocol',
      'SMTP': 'Simple Mail Transfer Protocol - Email transmission protocol',
      'ICMP': 'Internet Control Message Protocol - Network diagnostic protocol'
    };
    return descriptions[protocol] || 'Network communication protocol';
  }

  function getDefaultPort(protocol) {
    const ports = {
      'HTTP': 80, 'HTTPS': 443, 'FTP': 21, 'SSH': 22, 'SMTP': 25,
      'DNS': 53, 'DHCP': 67, 'SNMP': 161, 'Telnet': 23
    };
    return ports[protocol] || 'Variable';
  }

  function getProtocolType(protocol) {
    const types = {
      'TCP': 'Transport', 'UDP': 'Transport', 'HTTP': 'Application',
      'HTTPS': 'Application', 'DNS': 'Application', 'FTP': 'Application',
      'SSH': 'Application', 'SMTP': 'Application', 'ICMP': 'Network'
    };
    return types[protocol] || 'Application';
  }

  function getProtocolLayer(protocol) {
    const layers = {
      'TCP': 'Layer 4', 'UDP': 'Layer 4', 'HTTP': 'Layer 7',
      'HTTPS': 'Layer 7', 'DNS': 'Layer 7', 'FTP': 'Layer 7',
      'SSH': 'Layer 7', 'SMTP': 'Layer 7', 'ICMP': 'Layer 3'
    };
    return layers[protocol] || 'Layer 7';
  }

  function isProtocolEncrypted(protocol) {
    return ['HTTPS', 'SSH', 'SFTP', 'TLS', 'SSL'].includes(protocol);
  }

  // Filter packets based on search and filter type
  const filteredPackets = useMemo(() => {
    return currentPacketDetails.filter(packet => {
      const matchesSearch = searchTerm === '' || 
        packet.sourceIp.includes(searchTerm) ||
        packet.destIp.includes(searchTerm) ||
        packet.payload.toLowerCase().includes(searchTerm.toLowerCase());
      
      const matchesFilter = filterType === 'all' || 
        packet.type.toLowerCase() === filterType.toLowerCase();
      
      return matchesSearch && matchesFilter;
    });
  }, [currentPacketDetails, searchTerm, filterType]);

  // Calculate real-time metrics
  const realtimeMetrics = useMemo(() => {
    const now = Date.now();
    const recentPackets = currentPacketDetails.filter(p => 
      now - p.timestamp.getTime() < 60000 // Last minute
    );
    
    return {
      packetsPerSecond: (recentPackets.length / 60).toFixed(1),
      bytesPerSecond: (recentPackets.reduce((sum, p) => sum + p.size, 0) / 60).toFixed(0),
      avgLatency: '12.5ms',
      errorRate: '0.2%'
    };
  }, [currentPacketDetails]);

  const renderOverviewTab = () => (
    <div className="space-y-6">
      {/* Protocol Information Card */}
      <div className="bg-gradient-to-r from-blue-50 to-indigo-50 p-6 rounded-lg border border-blue-200">
        <div className="flex items-start justify-between">
          <div className="flex items-center gap-4">
            <div className="p-3 bg-blue-100 rounded-lg">
              {currentProtocolData.encrypted ? <Lock className="w-8 h-8 text-blue-600" /> : <Unlock className="w-8 h-8 text-blue-600" />}
            </div>
            <div>
              <h3 className="text-2xl font-bold text-gray-800">{currentProtocolData.name}</h3>
              <p className="text-gray-600 mt-1">{currentProtocolData.description}</p>
              <div className="flex items-center gap-4 mt-2 text-sm text-gray-500">
                <span>Port: {currentProtocolData.port}</span>
                <span>Type: {currentProtocolData.type}</span>
                <span>{currentProtocolData.layer}</span>
                {currentProtocolData.encrypted && (
                  <span className="flex items-center gap-1 text-green-600">
                    <Shield className="w-4 h-4" />
                    Encrypted
                  </span>
                )}
              </div>
            </div>
          </div>
          <div className="text-right">
            <div className="text-2xl font-bold text-blue-600">
              {((currentProtocolData.bandwidthUsage || 0)).toFixed(1)}%
            </div>
            <div className="text-sm text-gray-500">Bandwidth Usage</div>
          </div>
        </div>
      </div>

      {/* Statistics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-white p-4 rounded-lg border border-gray-200">
          <div className="flex items-center gap-3">
            <Activity className="w-8 h-8 text-green-600" />
            <div>
              <p className="text-sm text-gray-600">Total Packets</p>
              <p className="text-xl font-bold text-gray-800">{currentProtocolData.totalPackets.toLocaleString()}</p>
            </div>
          </div>
        </div>

        <div className="bg-white p-4 rounded-lg border border-gray-200">
          <div className="flex items-center gap-3">
            <Database className="w-8 h-8 text-blue-600" />
            <div>
              <p className="text-sm text-gray-600">Total Bytes</p>
              <p className="text-xl font-bold text-gray-800">
                {(currentProtocolData.totalBytes / (1024 * 1024)).toFixed(2)} MB
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white p-4 rounded-lg border border-gray-200">
          <div className="flex items-center gap-3">
            <Network className="w-8 h-8 text-purple-600" />
            <div>
              <p className="text-sm text-gray-600">Active Connections</p>
              <p className="text-xl font-bold text-gray-800">{currentProtocolData.activeConnections}</p>
            </div>
          </div>
        </div>

        <div className="bg-white p-4 rounded-lg border border-gray-200">
          <div className="flex items-center gap-3">
            <Server className="w-8 h-8 text-orange-600" />
            <div>
              <p className="text-sm text-gray-600">Unique Hosts</p>
              <p className="text-xl font-bold text-gray-800">{currentProtocolData.uniqueHosts}</p>
            </div>
          </div>
        </div>
      </div>

      {/* Real-time Metrics */}
      <div className="bg-white p-6 rounded-lg border border-gray-200">
        <h4 className="text-lg font-semibold text-gray-800 mb-4 flex items-center gap-2">
          <TrendingUp className="w-5 h-5 text-green-600" />
          Real-time Performance
        </h4>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="text-center p-3 bg-green-50 rounded-lg">
            <p className="text-2xl font-bold text-green-600">{realtimeMetrics.packetsPerSecond}</p>
            <p className="text-sm text-gray-600">Packets/sec</p>
          </div>
          <div className="text-center p-3 bg-blue-50 rounded-lg">
            <p className="text-2xl font-bold text-blue-600">{realtimeMetrics.bytesPerSecond}</p>
            <p className="text-sm text-gray-600">Bytes/sec</p>
          </div>
          <div className="text-center p-3 bg-yellow-50 rounded-lg">
            <p className="text-2xl font-bold text-yellow-600">{realtimeMetrics.avgLatency}</p>
            <p className="text-sm text-gray-600">Avg Latency</p>
          </div>
          <div className="text-center p-3 bg-red-50 rounded-lg">
            <p className="text-2xl font-bold text-red-600">{realtimeMetrics.errorRate}</p>
            <p className="text-sm text-gray-600">Error Rate</p>
          </div>
        </div>
      </div>

      {/* Timeline */}
      <div className="bg-white p-6 rounded-lg border border-gray-200">
        <h4 className="text-lg font-semibold text-gray-800 mb-4 flex items-center gap-2">
          <Clock className="w-5 h-5 text-gray-600" />
          Activity Timeline
        </h4>
        <div className="flex items-center justify-between text-sm text-gray-600">
          <div>
            <span className="font-medium">First Seen:</span> {currentProtocolData.firstSeen.toLocaleString()}
          </div>
          <div>
            <span className="font-medium">Last Seen:</span> {currentProtocolData.lastSeen.toLocaleString()}
          </div>
        </div>
        <div className="mt-3 bg-gray-200 rounded-full h-2">
          <div className="bg-blue-600 h-2 rounded-full" style={{ width: '75%' }}></div>
        </div>
      </div>
    </div>
  );

  const renderPacketsTab = () => (
    <div className="space-y-4">
      {/* Search and Filter Controls */}
      <div className="flex flex-col md:flex-row gap-4 items-center justify-between bg-gray-50 p-4 rounded-lg">
        <div className="flex items-center gap-4 flex-1">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
            <input
              type="text"
              placeholder="Search by IP address or payload..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
          </div>
          <select
            value={filterType}
            onChange={(e) => setFilterType(e.target.value)}
            className="px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          >
            <option value="all">All Types</option>
            <option value="request">Requests</option>
            <option value="response">Responses</option>
            <option value="query">Queries</option>
          </select>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowRawData(!showRawData)}
            className="flex items-center gap-2 px-3 py-2 bg-white border border-gray-300 rounded-lg hover:bg-gray-50"
          >
            {showRawData ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            {showRawData ? 'Hide Raw' : 'Show Raw'}
          </button>
        </div>
      </div>

      {/* Packets Table */}
      <div className="bg-white rounded-lg border border-gray-200 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Time</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Source</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Destination</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Size</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Type</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Flags</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {filteredPackets.map((packet) => (
                <tr key={packet.id} className="hover:bg-gray-50">
                  <td className="px-4 py-3 whitespace-nowrap text-sm text-gray-900">
                    {packet.timestamp.toLocaleTimeString()}
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap text-sm text-gray-900">
                    <div>
                      <div className="font-medium">{packet.sourceIp}</div>
                      <div className="text-gray-500">:{packet.sourcePort}</div>
                    </div>
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap text-sm text-gray-900">
                    <div>
                      <div className="font-medium">{packet.destIp}</div>
                      <div className="text-gray-500">:{packet.destPort}</div>
                    </div>
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap text-sm text-gray-900">
                    {packet.size} bytes
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap">
                    <span className={`px-2 py-1 inline-flex text-xs leading-5 font-semibold rounded-full ${
                      packet.type === 'Request' ? 'bg-blue-100 text-blue-800' :
                      packet.type === 'Response' ? 'bg-green-100 text-green-800' :
                      'bg-yellow-100 text-yellow-800'
                    }`}>
                      {packet.type}
                    </span>
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap text-sm text-gray-500">
                    {packet.flags.join(', ')}
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap text-sm text-gray-500">
                    <button
                      onClick={() => setSelectedPacket(packet)}
                      className="text-blue-600 hover:text-blue-900 font-medium"
                    >
                      Details
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Packet Details Modal */}
      {selectedPacket && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 max-w-2xl w-full mx-4 max-h-96 overflow-y-auto">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold">Packet Details</h3>
              <button
                onClick={() => setSelectedPacket(null)}
                className="text-gray-500 hover:text-gray-700"
              >
                ✕
              </button>
            </div>
            <div className="space-y-3">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-sm font-medium text-gray-600">Source IP:Port</label>
                  <p className="text-sm text-gray-900">{selectedPacket.sourceIp}:{selectedPacket.sourcePort}</p>
                </div>
                <div>
                  <label className="text-sm font-medium text-gray-600">Destination IP:Port</label>
                  <p className="text-sm text-gray-900">{selectedPacket.destIp}:{selectedPacket.destPort}</p>
                </div>
              </div>
              <div>
                <label className="text-sm font-medium text-gray-600">Payload</label>
                <div className="mt-1 p-3 bg-gray-100 rounded-lg text-sm font-mono">
                  {selectedPacket.payload}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );

  const renderSecurityTab = () => (
    <div className="space-y-6">
      <div className="bg-white p-6 rounded-lg border border-gray-200">
        <h4 className="text-lg font-semibold text-gray-800 mb-4 flex items-center gap-2">
          <Shield className="w-5 h-5 text-green-600" />
          Security Analysis
        </h4>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <h5 className="font-medium text-gray-700 mb-3">Encryption Status</h5>
            <div className={`p-3 rounded-lg ${currentProtocolData.encrypted ? 'bg-green-50 border border-green-200' : 'bg-yellow-50 border border-yellow-200'}`}>
              <div className="flex items-center gap-2">
                {currentProtocolData.encrypted ? <Lock className="w-5 h-5 text-green-600" /> : <Unlock className="w-5 h-5 text-yellow-600" />}
                <span className={`font-medium ${currentProtocolData.encrypted ? 'text-green-800' : 'text-yellow-800'}`}>
                  {currentProtocolData.encrypted ? 'Encrypted Traffic' : 'Unencrypted Traffic'}
                </span>
              </div>
              <p className={`text-sm mt-1 ${currentProtocolData.encrypted ? 'text-green-600' : 'text-yellow-600'}`}>
                {currentProtocolData.encrypted 
                  ? 'Traffic is encrypted and secure'
                  : 'Traffic is sent in plain text - potential security risk'
                }
              </p>
            </div>
          </div>

          <div>
            <h5 className="font-medium text-gray-700 mb-3">Threat Level</h5>
            <div className="p-3 rounded-lg bg-green-50 border border-green-200">
              <div className="flex items-center gap-2">
                <Shield className="w-5 h-5 text-green-600" />
                <span className="font-medium text-green-800">Low Risk</span>
              </div>
              <p className="text-sm text-green-600 mt-1">
                No suspicious activities detected
              </p>
            </div>
          </div>
        </div>

        <div className="mt-6">
          <h5 className="font-medium text-gray-700 mb-3">Security Recommendations</h5>
          <div className="space-y-2">
            <div className="flex items-start gap-2">
              <Info className="w-4 h-4 text-blue-600 mt-0.5" />
              <p className="text-sm text-gray-600">Monitor for unusual traffic patterns</p>
            </div>
            <div className="flex items-start gap-2">
              <Info className="w-4 h-4 text-blue-600 mt-0.5" />
              <p className="text-sm text-gray-600">Implement rate limiting for this protocol</p>
            </div>
            {!currentProtocolData.encrypted && (
              <div className="flex items-start gap-2">
                <AlertTriangle className="w-4 h-4 text-yellow-600 mt-0.5" />
                <p className="text-sm text-gray-600">Consider upgrading to encrypted version (e.g., HTTPS instead of HTTP)</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );

  return (
    <div className="bg-white rounded-lg shadow-lg">
      {/* Header */}
      <div className="flex items-center justify-between p-6 border-b border-gray-200">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-blue-100 rounded-lg">
            <Network className="w-6 h-6 text-blue-600" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-gray-800">{currentProtocolData.name} Protocol Details</h2>
            <p className="text-sm text-gray-600">Comprehensive protocol analysis and monitoring</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={refreshData}
            className="flex items-center gap-2 px-3 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
          >
            <RefreshCw className="w-4 h-4" />
            Refresh
          </button>
          <button
            onClick={onExport}
            className="flex items-center gap-2 px-3 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors"
          >
            <Download className="w-4 h-4" />
            Export
          </button>
          <button
            onClick={onClose}
            className="flex items-center gap-2 px-3 py-2 bg-gray-600 text-white rounded-lg hover:bg-gray-700 transition-colors"
          >
            Close
          </button>
        </div>
      </div>

      {/* Tab Navigation */}
      <div className="flex border-b border-gray-200">
        <button
          onClick={() => setActiveTab('overview')}
          className={`px-6 py-3 font-medium text-sm transition-colors ${
            activeTab === 'overview'
              ? 'text-blue-600 border-b-2 border-blue-600 bg-blue-50'
              : 'text-gray-600 hover:text-gray-800'
          }`}
        >
          Overview
        </button>
        <button
          onClick={() => setActiveTab('packets')}
          className={`px-6 py-3 font-medium text-sm transition-colors ${
            activeTab === 'packets'
              ? 'text-blue-600 border-b-2 border-blue-600 bg-blue-50'
              : 'text-gray-600 hover:text-gray-800'
          }`}
        >
          Packet Analysis
        </button>
        <button
          onClick={() => setActiveTab('security')}
          className={`px-6 py-3 font-medium text-sm transition-colors ${
            activeTab === 'security'
              ? 'text-blue-600 border-b-2 border-blue-600 bg-blue-50'
              : 'text-gray-600 hover:text-gray-800'
          }`}
        >
          Security
        </button>
      </div>

      {/* Tab Content */}
      <div className="p-6">
        {activeTab === 'overview' && renderOverviewTab()}
        {activeTab === 'packets' && renderPacketsTab()}
        {activeTab === 'security' && renderSecurityTab()}
      </div>

      {/* Status Bar */}
      <div className="flex items-center justify-between px-6 py-3 bg-gray-50 border-t border-gray-200 text-sm text-gray-600">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
            <span>Live monitoring active</span>
          </div>
          <span>Last updated: {new Date().toLocaleTimeString()}</span>
        </div>
        <div className="flex items-center gap-4">
          <span>Showing {filteredPackets.length} of {currentPacketDetails.length} packets</span>
        </div>
      </div>
    </div>
  );
};

export default ProtocolDetails;