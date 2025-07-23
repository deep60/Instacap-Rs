import React, { useState, useEffect } from 'react';
import { 
  ArrowLeft, 
  Shield, 
  AlertTriangle, 
  Clock, 
  MapPin, 
  Network, 
  Eye, 
  Download,
  Ban,
  CheckCircle,
  XCircle,
  Info,
  Activity,
  Globe,
  Server,
  FileText,
  Hash,
  Target,
  Zap,
  Copy,
  ExternalLink
} from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar } from 'recharts';

// Mock threat details data
const generateThreatDetails = (threatId) => ({
  id: threatId,
  type: 'Advanced Persistent Threat (APT)',
  severity: 'Critical',
  status: 'Active',
  title: 'Suspicious Network Activity from Foreign IP',
  description: 'Detected multiple failed authentication attempts followed by successful login and data exfiltration patterns.',
  detectedAt: '2024-01-15T14:30:22Z',
  lastActivity: '2024-01-15T15:45:18Z',
  sourceIp: '198.51.100.42',
  targetIp: '10.0.0.25',
  sourcePort: 4433,
  targetPort: 22,
  protocol: 'TCP',
  country: 'Unknown',
  asn: 'AS15169',
  organization: 'Suspicious Network Corp',
  confidence: 95,
  riskScore: 8.7,
  totalPackets: 15847,
  totalBytes: 2456789,
  duration: '1h 15m 32s',
  classification: {
    category: 'Intrusion Attempt',
    subcategory: 'Brute Force Attack',
    malwareFamily: 'N/A',
    attackVector: 'Network'
  },
  indicators: [
    { type: 'IP Address', value: '198.51.100.42', severity: 'High' },
    { type: 'Domain', value: 'suspicious-domain.com', severity: 'Medium' },
    { type: 'Hash', value: 'a1b2c3d4e5f6...', severity: 'Critical' },
    { type: 'User Agent', value: 'Mozilla/5.0 (Malicious)', severity: 'Low' }
  ],
  timeline: [
    { time: '14:30:22', event: 'Initial connection detected', severity: 'Info' },
    { time: '14:32:15', event: 'Multiple failed login attempts', severity: 'Warning' },
    { time: '14:35:48', event: 'Successful authentication', severity: 'High' },
    { time: '14:42:11', event: 'Unusual data transfer patterns', severity: 'Critical' },
    { time: '15:15:33', event: 'Data exfiltration detected', severity: 'Critical' },
    { time: '15:45:18', event: 'Connection terminated', severity: 'Info' }
  ],
  networkFlow: [
    { time: '14:30', inbound: 1200, outbound: 800 },
    { time: '14:35', inbound: 2400, outbound: 1600 },
    { time: '14:40', inbound: 3200, outbound: 2800 },
    { time: '14:45', inbound: 1800, outbound: 4200 },
    { time: '14:50', inbound: 1000, outbound: 3500 },
    { time: '14:55', inbound: 800, outbound: 2100 }
  ],
  relatedThreats: [
    { id: 2, type: 'Port Scan', severity: 'Medium', time: '13:45:22' },
    { id: 3, type: 'Malware', severity: 'High', time: '12:30:15' }
  ],
  mitigation: {
    autoActions: ['IP Blocked', 'Port Closed', 'User Account Suspended'],
    recommendations: [
      'Review and strengthen authentication policies',
      'Implement IP whitelisting for SSH access',
      'Enable multi-factor authentication',
      'Monitor for similar attack patterns'
    ]
  }
});

const ThreatDetails = ({ threatId, onBack }) => {
  const [threatDetails, setThreatDetails] = useState(null);
  const [activeTab, setActiveTab] = useState('overview');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Simulate API call
    const fetchThreatDetails = async () => {
      setLoading(true);
      setTimeout(() => {
        setThreatDetails(generateThreatDetails(threatId));
        setLoading(false);
      }, 1000);
    };

    fetchThreatDetails();
  }, [threatId]);

  const getSeverityColor = (severity) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'text-red-600 bg-red-100 border-red-200';
      case 'high': return 'text-orange-600 bg-orange-100 border-orange-200';
      case 'medium': return 'text-yellow-600 bg-yellow-100 border-yellow-200';
      case 'low': return 'text-green-600 bg-green-100 border-green-200';
      case 'info': return 'text-blue-600 bg-blue-100 border-blue-200';
      case 'warning': return 'text-yellow-600 bg-yellow-100 border-yellow-200';
      default: return 'text-gray-600 bg-gray-100 border-gray-200';
    }
  };

  const getStatusColor = (status) => {
    switch (status.toLowerCase()) {
      case 'active': return 'text-red-600 bg-red-100';
      case 'resolved': return 'text-green-600 bg-green-100';
      case 'investigating': return 'text-yellow-600 bg-yellow-100';
      case 'blocked': return 'text-blue-600 bg-blue-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    // You could add a toast notification here
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  if (!threatDetails) {
    return (
      <div className="text-center py-12">
        <AlertTriangle className="h-12 w-12 text-gray-400 mx-auto mb-4" />
        <p className="text-gray-500">Threat details not found</p>
      </div>
    );
  }

  return (
    <div className="bg-gray-50 min-h-screen">
      {/* Header */}
      <div className="bg-white border-b sticky top-0 z-10">
        <div className="p-6">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center">
              <button
                onClick={onBack}
                className="mr-4 p-2 hover:bg-gray-100 rounded-lg"
              >
                <ArrowLeft className="h-5 w-5" />
              </button>
              <div>
                <h1 className="text-2xl font-bold text-gray-900">
                  Threat #{threatDetails.id}
                </h1>
                <p className="text-gray-600">{threatDetails.title}</p>
              </div>
            </div>
            <div className="flex items-center space-x-3">
              <span className={`px-3 py-1 rounded-full text-sm font-semibold ${getSeverityColor(threatDetails.severity)}`}>
                {threatDetails.severity}
              </span>
              <span className={`px-3 py-1 rounded-full text-sm font-semibold ${getStatusColor(threatDetails.status)}`}>
                {threatDetails.status}
              </span>
            </div>
          </div>

          {/* Action Buttons */}
          <div className="flex space-x-3">
            <button className="flex items-center px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700">
              <Ban className="h-4 w-4 mr-2" />
              Block IP
            </button>
            <button className="flex items-center px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">
              <Shield className="h-4 w-4 mr-2" />
              Apply Rule
            </button>
            <button className="flex items-center px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700">
              <CheckCircle className="h-4 w-4 mr-2" />
              Mark Resolved
            </button>
            <button className="flex items-center px-4 py-2 bg-gray-600 text-white rounded-lg hover:bg-gray-700">
              <Download className="h-4 w-4 mr-2" />
              Export Report
            </button>
          </div>
        </div>

        {/* Tabs */}
        <div className="border-t">
          <nav className="flex px-6">
            {[
              { id: 'overview', label: 'Overview' },
              { id: 'timeline', label: 'Timeline' },
              { id: 'network', label: 'Network Analysis' },
              { id: 'indicators', label: 'IOCs' },
              { id: 'mitigation', label: 'Mitigation' }
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`py-3 px-4 border-b-2 font-medium text-sm ${
                  activeTab === tab.id
                    ? 'border-blue-500 text-blue-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </nav>
        </div>
      </div>

      <div className="p-6">
        {/* Overview Tab */}
        {activeTab === 'overview' && (
          <div className="space-y-6">
            {/* Summary Cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
              <div className="bg-white p-6 rounded-lg shadow-sm border">
                <div className="flex items-center">
                  <Target className="h-8 w-8 text-red-500 mr-3" />
                  <div>
                    <p className="text-sm text-gray-600">Risk Score</p>
                    <p className="text-2xl font-bold text-red-600">{threatDetails.riskScore}/10</p>
                  </div>
                </div>
              </div>
              <div className="bg-white p-6 rounded-lg shadow-sm border">
                <div className="flex items-center">
                  <Zap className="h-8 w-8 text-orange-500 mr-3" />
                  <div>
                    <p className="text-sm text-gray-600">Confidence</p>
                    <p className="text-2xl font-bold text-orange-600">{threatDetails.confidence}%</p>
                  </div>
                </div>
              </div>
              <div className="bg-white p-6 rounded-lg shadow-sm border">
                <div className="flex items-center">
                  <Network className="h-8 w-8 text-blue-500 mr-3" />
                  <div>
                    <p className="text-sm text-gray-600">Total Packets</p>
                    <p className="text-2xl font-bold text-blue-600">{threatDetails.totalPackets.toLocaleString()}</p>
                  </div>
                </div>
              </div>
              <div className="bg-white p-6 rounded-lg shadow-sm border">
                <div className="flex items-center">
                  <Clock className="h-8 w-8 text-purple-500 mr-3" />
                  <div>
                    <p className="text-sm text-gray-600">Duration</p>
                    <p className="text-2xl font-bold text-purple-600">{threatDetails.duration}</p>
                  </div>
                </div>
              </div>
            </div>

            {/* Threat Information */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div className="bg-white p-6 rounded-lg shadow-sm border">
                <h3 className="text-lg font-semibold text-gray-900 mb-4">Threat Information</h3>
                <div className="space-y-3">
                  <div className="flex justify-between">
                    <span className="text-gray-600">Type:</span>
                    <span className="font-medium">{threatDetails.type}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-600">Category:</span>
                    <span className="font-medium">{threatDetails.classification.category}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-600">Attack Vector:</span>
                    <span className="font-medium">{threatDetails.classification.attackVector}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-600">Detected:</span>
                    <span className="font-medium">{new Date(threatDetails.detectedAt).toLocaleString()}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-600">Last Activity:</span>
                    <span className="font-medium">{new Date(threatDetails.lastActivity).toLocaleString()}</span>
                  </div>
                </div>
              </div>

              <div className="bg-white p-6 rounded-lg shadow-sm border">
                <h3 className="text-lg font-semibold text-gray-900 mb-4">Network Details</h3>
                <div className="space-y-3">
                  <div className="flex justify-between items-center">
                    <span className="text-gray-600">Source IP:</span>
                    <div className="flex items-center">
                      <span className="font-medium mr-2">{threatDetails.sourceIp}</span>
                      <button
                        onClick={() => copyToClipboard(threatDetails.sourceIp)}
                        className="p-1 hover:bg-gray-100 rounded"
                      >
                        <Copy className="h-4 w-4 text-gray-500" />
                      </button>
                    </div>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-gray-600">Target IP:</span>
                    <div className="flex items-center">
                      <span className="font-medium mr-2">{threatDetails.targetIp}</span>
                      <button
                        onClick={() => copyToClipboard(threatDetails.targetIp)}
                        className="p-1 hover:bg-gray-100 rounded"
                      >
                        <Copy className="h-4 w-4 text-gray-500" />
                      </button>
                    </div>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-600">Protocol:</span>
                    <span className="font-medium">{threatDetails.protocol}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-600">Source Port:</span>
                    <span className="font-medium">{threatDetails.sourcePort}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-600">Target Port:</span>
                    <span className="font-medium">{threatDetails.targetPort}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-600">Organization:</span>
                    <span className="font-medium">{threatDetails.organization}</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Description */}
            <div className="bg-white p-6 rounded-lg shadow-sm border">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Description</h3>
              <p className="text-gray-700 leading-relaxed">{threatDetails.description}</p>
            </div>
          </div>
        )}

        {/* Timeline Tab */}
        {activeTab === 'timeline' && (
          <div className="bg-white p-6 rounded-lg shadow-sm border">
            <h3 className="text-lg font-semibold text-gray-900 mb-6">Attack Timeline</h3>
            <div className="space-y-4">
              {threatDetails.timeline.map((item, index) => (
                <div key={index} className="flex items-start">
                  <div className={`flex-shrink-0 w-3 h-3 rounded-full mt-2 mr-4 ${
                    item.severity === 'Critical' ? 'bg-red-500' :
                    item.severity === 'High' ? 'bg-orange-500' :
                    item.severity === 'Warning' ? 'bg-yellow-500' :
                    'bg-blue-500'
                  }`}></div>
                  <div className="flex-1">
                    <div className="flex items-center justify-between">
                      <h4 className="font-medium text-gray-900">{item.event}</h4>
                      <span className={`px-2 py-1 text-xs font-semibold rounded-full ${getSeverityColor(item.severity)}`}>
                        {item.severity}
                      </span>
                    </div>
                    <p className="text-sm text-gray-500 mt-1">{item.time}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Network Analysis Tab */}
        {activeTab === 'network' && (
          <div className="space-y-6">
            <div className="bg-white p-6 rounded-lg shadow-sm border">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Network Traffic Flow</h3>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={threatDetails.networkFlow}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="time" />
                  <YAxis />
                  <Tooltip />
                  <Bar dataKey="inbound" fill="#3b82f6" name="Inbound (KB)" />
                  <Bar dataKey="outbound" fill="#ef4444" name="Outbound (KB)" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        )}

        {/* Indicators Tab */}
        {activeTab === 'indicators' && (
          <div className="bg-white p-6 rounded-lg shadow-sm border">
            <h3 className="text-lg font-semibold text-gray-900 mb-6">Indicators of Compromise (IOCs)</h3>
            <div className="space-y-4">
              {threatDetails.indicators.map((indicator, index) => (
                <div key={index} className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                  <div className="flex items-center">
                    <Hash className="h-5 w-5 text-gray-500 mr-3" />
                    <div>
                      <p className="font-medium text-gray-900">{indicator.type}</p>
                      <p className="text-sm text-gray-600">{indicator.value}</p>
                    </div>
                  </div>
                  <div className="flex items-center space-x-3">
                    <span className={`px-2 py-1 text-xs font-semibold rounded-full ${getSeverityColor(indicator.severity)}`}>
                      {indicator.severity}
                    </span>
                    <button
                      onClick={() => copyToClipboard(indicator.value)}
                      className="p-2 hover:bg-gray-200 rounded"
                    >
                      <Copy className="h-4 w-4 text-gray-500" />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Mitigation Tab */}
        {activeTab === 'mitigation' && (
          <div className="space-y-6">
            <div className="bg-white p-6 rounded-lg shadow-sm border">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Automated Actions Taken</h3>
              <div className="space-y-2">
                {threatDetails.mitigation.autoActions.map((action, index) => (
                  <div key={index} className="flex items-center">
                    <CheckCircle className="h-5 w-5 text-green-500 mr-3" />
                    <span className="text-gray-700">{action}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="bg-white p-6 rounded-lg shadow-sm border">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Recommended Actions</h3>
              <div className="space-y-2">
                {threatDetails.mitigation.recommendations.map((recommendation, index) => (
                  <div key={index} className="flex items-start">
                    <Info className="h-5 w-5 text-blue-500 mr-3 mt-0.5" />
                    <span className="text-gray-700">{recommendation}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default ThreatDetails;