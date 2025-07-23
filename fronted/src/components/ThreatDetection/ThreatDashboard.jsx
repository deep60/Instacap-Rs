import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  AlertTriangle, 
  Eye, 
  Activity, 
  Users, 
  Globe, 
  Clock,
  TrendingUp,
  Filter,
  RefreshCw,
  Download,
  Search
} from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, BarChart, Bar } from 'recharts';

// Mock data - replace with actual API calls
const generateMockThreatData = () => ({
  totalThreats: 1247,
  activeThreat: 23,
  resolvedThreats: 1224,
  criticalThreats: 8,
  highThreats: 15,
  mediumThreats: 45,
  lowThreats: 67,
  blockedIPs: 342,
  suspiciousActivities: 89
});

const generateTimeSeriesData = () => {
  const data = [];
  const now = new Date();
  for (let i = 23; i >= 0; i--) {
    const time = new Date(now.getTime() - i * 60 * 60 * 1000);
    data.push({
      time: time.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }),
      threats: Math.floor(Math.random() * 20) + 5,
      blocked: Math.floor(Math.random() * 15) + 2,
      suspicious: Math.floor(Math.random() * 10) + 1
    });
  }
  return data;
};

const generateThreatTypes = () => [
  { name: 'Malware', value: 35, color: '#ef4444' },
  { name: 'DDoS', value: 25, color: '#f97316' },
  { name: 'Port Scan', value: 20, color: '#eab308' },
  { name: 'Intrusion', value: 15, color: '#8b5cf6' },
  { name: 'Data Exfil', value: 5, color: '#06b6d4' }
];

const generateRecentThreats = () => [
  {
    id: 1,
    type: 'Malware Detection',
    source: '192.168.1.45',
    target: '10.0.0.12',
    severity: 'Critical',
    time: '2 minutes ago',
    status: 'Active'
  },
  {
    id: 2,
    type: 'DDoS Attack',
    source: '203.45.67.89',
    target: '10.0.0.15',
    severity: 'High',
    time: '5 minutes ago',
    status: 'Blocked'
  },
  {
    id: 3,
    type: 'Port Scanning',
    source: '172.16.0.23',
    target: '10.0.0.8',
    severity: 'Medium',
    time: '8 minutes ago',
    status: 'Monitoring'
  },
  {
    id: 4,
    type: 'Suspicious Traffic',
    source: '198.51.100.42',
    target: '10.0.0.20',
    severity: 'Low',
    time: '12 minutes ago',
    status: 'Investigated'
  }
];

const ThreatDashboard = () => {
  const [threatData, setThreatData] = useState(generateMockThreatData());
  const [timeSeriesData, setTimeSeriesData] = useState(generateTimeSeriesData());
  const [threatTypes, setThreatTypes] = useState(generateThreatTypes());
  const [recentThreats, setRecentThreats] = useState(generateRecentThreats());
  const [selectedTimeRange, setSelectedTimeRange] = useState('24h');
  const [searchTerm, setSearchTerm] = useState('');
  const [isRefreshing, setIsRefreshing] = useState(false);

  // Simulate real-time updates
  useEffect(() => {
    const interval = setInterval(() => {
      setThreatData(generateMockThreatData());
      setTimeSeriesData(generateTimeSeriesData());
      setRecentThreats(generateRecentThreats());
    }, 30000); // Update every 30 seconds

    return () => clearInterval(interval);
  }, []);

  const handleRefresh = async () => {
    setIsRefreshing(true);
    // Simulate API call
    setTimeout(() => {
      setThreatData(generateMockThreatData());
      setTimeSeriesData(generateTimeSeriesData());
      setRecentThreats(generateRecentThreats());
      setIsRefreshing(false);
    }, 1000);
  };

  const getSeverityColor = (severity) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'text-red-600 bg-red-100';
      case 'high': return 'text-orange-600 bg-orange-100';
      case 'medium': return 'text-yellow-600 bg-yellow-100';
      case 'low': return 'text-green-600 bg-green-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  const getStatusColor = (status) => {
    switch (status.toLowerCase()) {
      case 'active': return 'text-red-600 bg-red-100';
      case 'blocked': return 'text-blue-600 bg-blue-100';
      case 'monitoring': return 'text-yellow-600 bg-yellow-100';
      case 'investigated': return 'text-green-600 bg-green-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  const StatCard = ({ icon: Icon, title, value, change, color }) => (
    <div className="bg-white p-6 rounded-lg shadow-sm border">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm font-medium text-gray-600">{title}</p>
          <p className="text-2xl font-bold text-gray-900">{value}</p>
          {change && (
            <p className={`text-sm ${change.startsWith('+') ? 'text-red-600' : 'text-green-600'}`}>
              {change} from last hour
            </p>
          )}
        </div>
        <div className={`p-3 rounded-full ${color}`}>
          <Icon className="h-6 w-6 text-white" />
        </div>
      </div>
    </div>
  );

  return (
    <div className="p-6 bg-gray-50 min-h-screen">
      {/* Header */}
      <div className="mb-6">
        <div className="flex justify-between items-center mb-4">
          <h1 className="text-3xl font-bold text-gray-900">Threat Detection Dashboard</h1>
          <div className="flex space-x-3">
            <button
              onClick={handleRefresh}
              disabled={isRefreshing}
              className="flex items-center px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
            >
              <RefreshCw className={`h-4 w-4 mr-2 ${isRefreshing ? 'animate-spin' : ''}`} />
              Refresh
            </button>
            <button className="flex items-center px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700">
              <Download className="h-4 w-4 mr-2" />
              Export
            </button>
          </div>
        </div>

        {/* Controls */}
        <div className="flex flex-wrap gap-4 items-center">
          <div className="flex items-center space-x-2">
            <Filter className="h-4 w-4 text-gray-500" />
            <select
              value={selectedTimeRange}
              onChange={(e) => setSelectedTimeRange(e.target.value)}
              className="border rounded-lg px-3 py-2"
            >
              <option value="1h">Last Hour</option>
              <option value="24h">Last 24 Hours</option>
              <option value="7d">Last 7 Days</option>
              <option value="30d">Last 30 Days</option>
            </select>
          </div>
          <div className="flex items-center space-x-2">
            <Search className="h-4 w-4 text-gray-500" />
            <input
              type="text"
              placeholder="Search threats..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="border rounded-lg px-3 py-2 w-64"
            />
          </div>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-6">
        <StatCard
          icon={Shield}
          title="Total Threats"
          value={threatData.totalThreats.toLocaleString()}
          change="+12"
          color="bg-red-500"
        />
        <StatCard
          icon={AlertTriangle}
          title="Active Threats"
          value={threatData.activeThreat}
          change="+3"
          color="bg-orange-500"
        />
        <StatCard
          icon={Eye}
          title="Blocked IPs"
          value={threatData.blockedIPs}
          change="+8"
          color="bg-blue-500"
        />
        <StatCard
          icon={Activity}
          title="Suspicious Activities"
          value={threatData.suspiciousActivities}
          change="-2"
          color="bg-purple-500"
        />
      </div>

      {/* Threat Severity Breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6 mb-6">
        <div className="bg-white p-4 rounded-lg shadow-sm border">
          <h3 className="text-lg font-semibold text-gray-900 mb-2">Critical</h3>
          <p className="text-3xl font-bold text-red-600">{threatData.criticalThreats}</p>
        </div>
        <div className="bg-white p-4 rounded-lg shadow-sm border">
          <h3 className="text-lg font-semibold text-gray-900 mb-2">High</h3>
          <p className="text-3xl font-bold text-orange-600">{threatData.highThreats}</p>
        </div>
        <div className="bg-white p-4 rounded-lg shadow-sm border">
          <h3 className="text-lg font-semibold text-gray-900 mb-2">Medium</h3>
          <p className="text-3xl font-bold text-yellow-600">{threatData.mediumThreats}</p>
        </div>
        <div className="bg-white p-4 rounded-lg shadow-sm border">
          <h3 className="text-lg font-semibold text-gray-900 mb-2">Low</h3>
          <p className="text-3xl font-bold text-green-600">{threatData.lowThreats}</p>
        </div>
      </div>

      {/* Charts Section */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        {/* Threat Timeline */}
        <div className="bg-white p-6 rounded-lg shadow-sm border">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Threat Activity Timeline</h3>
          <ResponsiveContainer width="100%" height={300}>
            <LineChart data={timeSeriesData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="time" />
              <YAxis />
              <Tooltip />
              <Line type="monotone" dataKey="threats" stroke="#ef4444" strokeWidth={2} />
              <Line type="monotone" dataKey="blocked" stroke="#3b82f6" strokeWidth={2} />
              <Line type="monotone" dataKey="suspicious" stroke="#f59e0b" strokeWidth={2} />
            </LineChart>
          </ResponsiveContainer>
        </div>

        {/* Threat Types Distribution */}
        <div className="bg-white p-6 rounded-lg shadow-sm border">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Threat Types Distribution</h3>
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={threatTypes}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                outerRadius={80}
                fill="#8884d8"
                dataKey="value"
              >
                {threatTypes.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Recent Threats Table */}
      <div className="bg-white rounded-lg shadow-sm border">
        <div className="p-6 border-b">
          <h3 className="text-lg font-semibold text-gray-900">Recent Threats</h3>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Threat Type
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Source IP
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Target IP
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Severity
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Status
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Time
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {recentThreats.map((threat) => (
                <tr key={threat.id} className="hover:bg-gray-50">
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="flex items-center">
                      <AlertTriangle className="h-4 w-4 text-red-500 mr-2" />
                      <span className="text-sm font-medium text-gray-900">{threat.type}</span>
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    {threat.source}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    {threat.target}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getSeverityColor(threat.severity)}`}>
                      {threat.severity}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getStatusColor(threat.status)}`}>
                      {threat.status}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    <div className="flex items-center">
                      <Clock className="h-4 w-4 mr-1" />
                      {threat.time}
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                    <button className="text-blue-600 hover:text-blue-900 mr-3">View</button>
                    <button className="text-red-600 hover:text-red-900">Block</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default ThreatDashboard;