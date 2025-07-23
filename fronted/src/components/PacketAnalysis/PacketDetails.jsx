  import React, { useState, useEffect } from 'react';
  import { 
    Clock, 
    Network, 
    Shield, 
    Eye, 
    Copy, 
    Download, 
    ChevronDown, 
    ChevronRight,
    AlertTriangle,
    Info,
    Zap,
    Globe
  } from 'lucide-react';

  const PacketDetails = ({ packet, onClose }) => {
    const [expandedSections, setExpandedSections] = useState({
      headers: true,
      payload: false,
      analysis: true,
      flow: true
    });
    const [selectedTab, setSelectedTab] = useState('overview');

    // Toggle section expansion
    const toggleSection = (section) => {
      setExpandedSections(prev => ({
        ...prev,
        [section]: !prev[section]
      }));
    };

    // Copy to clipboard function
    const copyToClipboard = (text) => {
      navigator.clipboard.writeText(text);
      // Could add a toast notification here
    };

    // Format bytes to hex view
    const formatHexView = (data) => {
      if (!data) return '';
      const bytes = Array.from(data);
      let hexView = '';
      let asciiView = '';
      
      for (let i = 0; i < bytes.length; i += 16) {
        const hexLine = bytes.slice(i, i + 16)
          .map(b => b.toString(16).padStart(2, '0'))
          .join(' ');
        const asciiLine = bytes.slice(i, i + 16)
          .map(b => b >= 32 && b <= 126 ? String.fromCharCode(b) : '.')
          .join('');
        
        hexView += `${i.toString(16).padStart(4, '0')}: ${hexLine.padEnd(47, ' ')} | ${asciiLine}\n`;
      }
      
      return hexView;
    };

    // Get threat level color
    const getThreatLevelColor = (level) => {
      switch (level?.toLowerCase()) {
        case 'critical': return 'text-red-600 bg-red-100';
        case 'high': return 'text-orange-600 bg-orange-100';
        case 'medium': return 'text-yellow-600 bg-yellow-100';
        case 'low': return 'text-blue-600 bg-blue-100';
        default: return 'text-green-600 bg-green-100';
      }
    };

    if (!packet) {
      return (
        <div className="flex items-center justify-center h-64 text-gray-500">
          <div className="text-center">
            <Network className="h-12 w-12 mx-auto mb-4 opacity-50" />
            <p>Select a packet to view details</p>
          </div>
        </div>
      );
    }

    return (
      <div className="bg-white rounded-lg shadow-lg border border-gray-200 h-full flex flex-col">
        {/* Header */}
        <div className="border-b border-gray-200 p-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="p-2 bg-blue-100 rounded-lg">
                <Network className="h-5 w-5 text-blue-600" />
              </div>
              <div>
                <h3 className="text-lg font-semibold text-gray-900">
                  Packet #{packet.id || 'N/A'}
                </h3>
                <p className="text-sm text-gray-500">
                  {packet.protocol} • {packet.length} bytes
                </p>
              </div>
            </div>
            <div className="flex items-center space-x-2">
              <button
                onClick={() => copyToClipboard(JSON.stringify(packet, null, 2))}
                className="p-2 text-gray-400 hover:text-gray-600 hover:bg-gray-100 rounded-lg transition-colors"
              >
                <Copy className="h-4 w-4" />
              </button>
              <button
                onClick={() => {/* Download logic */}}
                className="p-2 text-gray-400 hover:text-gray-600 hover:bg-gray-100 rounded-lg transition-colors"
              >
                <Download className="h-4 w-4" />
              </button>
              {onClose && (
                <button
                  onClick={onClose}
                  className="p-2 text-gray-400 hover:text-gray-600 hover:bg-gray-100 rounded-lg transition-colors"
                >
                  ×
                </button>
              )}
            </div>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="border-b border-gray-200">
          <nav className="flex space-x-8 px-4">
            {[
              { id: 'overview', label: 'Overview', icon: Info },
              { id: 'headers', label: 'Headers', icon: Eye },
              { id: 'payload', label: 'Payload', icon: Zap },
              { id: 'analysis', label: 'Analysis', icon: Shield }
            ].map(tab => (
              <button
                key={tab.id}
                onClick={() => setSelectedTab(tab.id)}
                className={`py-3 px-1 border-b-2 font-medium text-sm transition-colors ${
                  selectedTab === tab.id
                    ? 'border-blue-500 text-blue-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700'
                }`}
              >
                <div className="flex items-center space-x-2">
                  <tab.icon className="h-4 w-4" />
                  <span>{tab.label}</span>
                </div>
              </button>
            ))}
          </nav>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-4">
          {selectedTab === 'overview' && (
            <div className="space-y-6">
              {/* Basic Info */}
              <div className="bg-gray-50 rounded-lg p-4">
                <h4 className="font-medium text-gray-900 mb-3">Basic Information</h4>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <span className="text-sm text-gray-500">Timestamp</span>
                    <p className="font-mono text-sm">
                      {packet.timestamp ? new Date(packet.timestamp).toLocaleString() : 'N/A'}
                    </p>
                  </div>
                  <div>
                    <span className="text-sm text-gray-500">Protocol</span>
                    <p className="font-mono text-sm">{packet.protocol || 'Unknown'}</p>
                  </div>
                  <div>
                    <span className="text-sm text-gray-500">Length</span>
                    <p className="font-mono text-sm">{packet.length || 0} bytes</p>
                  </div>
                  <div>
                    <span className="text-sm text-gray-500">TTL</span>
                    <p className="font-mono text-sm">{packet.ttl || 'N/A'}</p>
                  </div>
                </div>
              </div>

              {/* Network Info */}
              <div className="bg-gray-50 rounded-lg p-4">
                <h4 className="font-medium text-gray-900 mb-3 flex items-center">
                  <Globe className="h-4 w-4 mr-2" />
                  Network Information
                </h4>
                <div className="space-y-3">
                  <div className="flex items-center justify-between p-3 bg-white rounded border">
                    <div>
                      <span className="text-sm text-gray-500">Source</span>
                      <p className="font-mono text-sm font-medium">
                        {packet.src_ip || 'N/A'}:{packet.src_port || 'N/A'}
                      </p>
                    </div>
                    <div className="text-gray-400">→</div>
                    <div>
                      <span className="text-sm text-gray-500">Destination</span>
                      <p className="font-mono text-sm font-medium">
                        {packet.dst_ip || 'N/A'}:{packet.dst_port || 'N/A'}
                      </p>
                    </div>
                  </div>
                </div>
              </div>

              {/* Threat Analysis */}
              {packet.threat_level && (
                <div className="bg-gray-50 rounded-lg p-4">
                  <h4 className="font-medium text-gray-900 mb-3 flex items-center">
                    <AlertTriangle className="h-4 w-4 mr-2" />
                    Threat Analysis
                  </h4>
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-500">Threat Level</span>
                      <span className={`px-2 py-1 rounded-full text-xs font-medium ${getThreatLevelColor(packet.threat_level)}`}>
                        {packet.threat_level?.toUpperCase() || 'SAFE'}
                      </span>
                    </div>
                    {packet.threat_indicators && (
                      <div>
                        <span className="text-sm text-gray-500">Indicators</span>
                        <div className="mt-1 space-y-1">
                          {packet.threat_indicators.map((indicator, index) => (
                            <div key={index} className="text-sm bg-white p-2 rounded border">
                              {indicator}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}

          {selectedTab === 'headers' && (
            <div className="space-y-4">
              {/* Layer Headers */}
              {['ethernet', 'ip', 'tcp', 'udp', 'application'].map(layer => {
                if (!packet.headers?.[layer]) return null;
                
                return (
                  <div key={layer} className="border rounded-lg">
                    <button
                      onClick={() => toggleSection(`${layer}_header`)}
                      className="w-full px-4 py-3 text-left flex items-center justify-between hover:bg-gray-50"
                    >
                      <span className="font-medium capitalize">{layer} Header</span>
                      {expandedSections[`${layer}_header`] ? 
                        <ChevronDown className="h-4 w-4" /> : 
                        <ChevronRight className="h-4 w-4" />
                      }
                    </button>
                    {expandedSections[`${layer}_header`] && (
                      <div className="px-4 pb-4 border-t bg-gray-50">
                        <div className="grid grid-cols-2 gap-4 mt-3">
                          {Object.entries(packet.headers[layer]).map(([key, value]) => (
                            <div key={key} className="bg-white p-2 rounded border">
                              <span className="text-xs text-gray-500 uppercase">{key}</span>
                              <p className="font-mono text-sm">{String(value)}</p>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}

          {selectedTab === 'payload' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <h4 className="font-medium text-gray-900">Packet Payload</h4>
                <div className="flex items-center space-x-2">
                  <button
                    onClick={() => copyToClipboard(packet.payload || '')}
                    className="px-3 py-1 text-sm bg-blue-100 text-blue-700 rounded hover:bg-blue-200 transition-colors"
                  >
                    Copy Raw
                  </button>
                </div>
              </div>
              
              {packet.payload ? (
                <div className="space-y-4">
                  {/* Hex View */}
                  <div>
                    <h5 className="text-sm font-medium text-gray-700 mb-2">Hex View</h5>
                    <div className="bg-gray-900 text-green-400 p-4 rounded-lg font-mono text-xs overflow-x-auto">
                      <pre>{formatHexView(packet.payload)}</pre>
                    </div>
                  </div>
                  
                  {/* ASCII View */}
                  <div>
                    <h5 className="text-sm font-medium text-gray-700 mb-2">ASCII View</h5>
                    <div className="bg-gray-100 p-4 rounded-lg font-mono text-sm">
                      <pre>{packet.payload_ascii || 'No ASCII representation available'}</pre>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="text-center py-8 text-gray-500">
                  <Zap className="h-8 w-8 mx-auto mb-2 opacity-50" />
                  <p>No payload data available</p>
                </div>
              )}
            </div>
          )}

          {selectedTab === 'analysis' && (
            <div className="space-y-6">
              {/* Protocol Analysis */}
              <div className="bg-gray-50 rounded-lg p-4">
                <h4 className="font-medium text-gray-900 mb-3">Protocol Analysis</h4>
                <div className="space-y-3">
                  <div className="flex justify-between">
                    <span className="text-sm text-gray-500">Protocol Stack</span>
                    <span className="font-mono text-sm">
                      {packet.protocol_stack?.join(' → ') || packet.protocol}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-sm text-gray-500">Application</span>
                    <span className="font-mono text-sm">
                      {packet.application || 'Unknown'}
                    </span>
                  </div>
                  {packet.service && (
                    <div className="flex justify-between">
                      <span className="text-sm text-gray-500">Service</span>
                      <span className="font-mono text-sm">{packet.service}</span>
                    </div>
                  )}
                </div>
              </div>

              {/* Traffic Analysis */}
              <div className="bg-gray-50 rounded-lg p-4">
                <h4 className="font-medium text-gray-900 mb-3">Traffic Analysis</h4>
                <div className="grid grid-cols-2 gap-4">
                  <div className="bg-white p-3 rounded border">
                    <span className="text-sm text-gray-500">Bandwidth Usage</span>
                    <p className="font-mono text-sm">{packet.bandwidth || 'N/A'}</p>
                  </div>
                  <div className="bg-white p-3 rounded border">
                    <span className="text-sm text-gray-500">Latency</span>
                    <p className="font-mono text-sm">{packet.latency || 'N/A'}</p>
                  </div>
                  <div className="bg-white p-3 rounded border">
                    <span className="text-sm text-gray-500">Flow ID</span>
                    <p className="font-mono text-sm">{packet.flow_id || 'N/A'}</p>
                  </div>
                  <div className="bg-white p-3 rounded border">
                    <span className="text-sm text-gray-500">Session ID</span>
                    <p className="font-mono text-sm">{packet.session_id || 'N/A'}</p>
                  </div>
                </div>
              </div>

              {/* Anomaly Detection */}
              {packet.anomalies && packet.anomalies.length > 0 && (
                <div className="bg-red-50 rounded-lg p-4 border border-red-200">
                  <h4 className="font-medium text-red-900 mb-3 flex items-center">
                    <AlertTriangle className="h-4 w-4 mr-2" />
                    Detected Anomalies
                  </h4>
                  <div className="space-y-2">
                    {packet.anomalies.map((anomaly, index) => (
                      <div key={index} className="bg-white p-3 rounded border border-red-200">
                        <div className="flex justify-between items-start">
                          <div>
                            <p className="font-medium text-sm text-red-900">{anomaly.type}</p>
                            <p className="text-sm text-red-700">{anomaly.description}</p>
                          </div>
                          <span className="text-xs text-red-600 bg-red-100 px-2 py-1 rounded">
                            {anomaly.severity}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    );
  };

  export default PacketDetails;