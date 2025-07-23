import React, { useState, useEffect } from 'react';
import { AlertTriangle, Shield, Activity, Clock, Eye, X, Filter } from 'lucide-react';
import AlertItem from '../Common/AlertItem';
import LoadingSpinner from '../Common/LoadingSpinner';

const AlertsPanel = ({ className = '', maxHeight = '400px' }) => {
  const [alerts, setAlerts] = useState([]);
  const [filteredAlerts, setFilteredAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('all');
  const [showFilters, setShowFilters] = useState(false);
  const [selectedAlert, setSelectedAlert] = useState(null);

  // Mock alert data - replace with actual API call
  useEffect(() => {
    const fetchAlerts = async () => {
      setLoading(true);
      try {
        // Simulate API call
        setTimeout(() => {
          const mockAlerts = [
            {
              id: '1',
              type: 'threat',
              severity: 'high',
              title: 'Potential DDoS Attack Detected',
              description: 'Unusual traffic pattern detected from multiple IPs',
              timestamp: new Date(Date.now() - 1000 * 60 * 5), // 5 minutes ago
              source: '192.168.1.100',
              protocol: 'TCP',
              count: 1247,
              status: 'active'
            },
            {
              id: '2',
              type: 'anomaly',
              severity: 'medium',
              title: 'Port Scanning Activity',
              description: 'Sequential port scanning detected from external IP',
              timestamp: new Date(Date.now() - 1000 * 60 * 12), // 12 minutes ago
              source: '203.45.67.89',
              protocol: 'TCP',
              count: 234,
              status: 'investigating'
            },
            {
              id: '3',
              type: 'performance',
              severity: 'low',
              title: 'High Latency Detected',
              description: 'Network latency exceeding normal thresholds',
              timestamp: new Date(Date.now() - 1000 * 60 * 20), // 20 minutes ago
              source: 'Network Gateway',
              protocol: 'ICMP',
              count: 45,
              status: 'resolved'
            },
            {
              id: '4',
              type: 'threat',
              severity: 'critical',
              title: 'Malware Communication Detected',
              description: 'Suspicious outbound traffic to known C&C server',
              timestamp: new Date(Date.now() - 1000 * 60 * 35), // 35 minutes ago
              source: '192.168.1.150',
              protocol: 'HTTPS',
              count: 89,
              status: 'blocked'
            },
            {
              id: '5',
              type: 'anomaly',
              severity: 'medium',
              title: 'Unusual Protocol Usage',
              description: 'Unexpected P2P traffic during business hours',
              timestamp: new Date(Date.now() - 1000 * 60 * 45), // 45 minutes ago
              source: '192.168.1.75',
              protocol: 'UDP',
              count: 567,
              status: 'monitoring'
            }
          ];
          setAlerts(mockAlerts);
          setLoading(false);
        }, 1000);
      } catch (error) {
        console.error('Error fetching alerts:', error);
        setLoading(false);
      }
    };

    fetchAlerts();
    
    // Set up real-time updates (WebSocket would be used in production)
    const interval = setInterval(fetchAlerts, 30000); // Refresh every 30 seconds
    
    return () => clearInterval(interval);
  }, []);

  // Filter alerts based on selected filter
  useEffect(() => {
    let filtered = alerts;
    
    switch (filter) {
      case 'critical':
        filtered = alerts.filter(alert => alert.severity === 'critical');
        break;
      case 'high':
        filtered = alerts.filter(alert => alert.severity === 'high');
        break;
      case 'medium':
        filtered = alerts.filter(alert => alert.severity === 'medium');
        break;
      case 'low':
        filtered = alerts.filter(alert => alert.severity === 'low');
        break;
      case 'threat':
        filtered = alerts.filter(alert => alert.type === 'threat');
        break;
      case 'anomaly':
        filtered = alerts.filter(alert => alert.type === 'anomaly');
        break;
      case 'performance':
        filtered = alerts.filter(alert => alert.type === 'performance');
        break;
      case 'active':
        filtered = alerts.filter(alert => alert.status === 'active');
        break;
      default:
        filtered = alerts;
    }
    
    setFilteredAlerts(filtered);
  }, [alerts, filter]);

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'critical': return 'text-red-600 bg-red-50 border-red-200';
      case 'high': return 'text-orange-600 bg-orange-50 border-orange-200';
      case 'medium': return 'text-yellow-600 bg-yellow-50 border-yellow-200';
      case 'low': return 'text-blue-600 bg-blue-50 border-blue-200';
      default: return 'text-gray-600 bg-gray-50 border-gray-200';
    }
  };

  const getTypeIcon = (type) => {
    switch (type) {
      case 'threat': return <AlertTriangle className="h-4 w-4" />;
      case 'anomaly': return <Activity className="h-4 w-4" />;
      case 'performance': return <Shield className="h-4 w-4" />;
      default: return <AlertTriangle className="h-4 w-4" />;
    }
  };

  const formatTimestamp = (timestamp) => {
    const now = new Date();
    const diff = now - timestamp;
    const minutes = Math.floor(diff / (1000 * 60));
    const hours = Math.floor(diff / (1000 * 60 * 60));
    
    if (minutes < 1) return 'Just now';
    if (minutes < 60) return `${minutes}m ago`;
    if (hours < 24) return `${hours}h ago`;
    return timestamp.toLocaleDateString();
  };

  const handleAlertClick = (alert) => {
    setSelectedAlert(alert);
  };

  const handleCloseDetails = () => {
    setSelectedAlert(null);
  };

  const getFilterCount = (filterType) => {
    switch (filterType) {
      case 'critical':
        return alerts.filter(alert => alert.severity === 'critical').length;
      case 'high':
        return alerts.filter(alert => alert.severity === 'high').length;
      case 'medium':
        return alerts.filter(alert => alert.severity === 'medium').length;
      case 'active':
        return alerts.filter(alert => alert.status === 'active').length;
      default:
        return alerts.length;
    }
  };

  if (loading) {
    return (
      <div className={`bg-white rounded-lg shadow-md p-4 ${className}`}>
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-gray-800">Security Alerts</h3>
        </div>
        <div className="flex justify-center items-center h-32">
          <LoadingSpinner />
        </div>
      </div>
    );
  }

  return (
    <div className={`bg-white rounded-lg shadow-md ${className}`}>
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b border-gray-200">
        <div className="flex items-center space-x-2">
          <AlertTriangle className="h-5 w-5 text-red-500" />
          <h3 className="text-lg font-semibold text-gray-800">Security Alerts</h3>
          <span className="bg-red-100 text-red-800 text-xs font-medium px-2 py-1 rounded-full">
            {filteredAlerts.length}
          </span>
        </div>
        <div className="flex items-center space-x-2">
          <button
            onClick={() => setShowFilters(!showFilters)}
            className="p-2 text-gray-500 hover:text-gray-700 hover:bg-gray-100 rounded-md transition-colors"
            title="Filter alerts"
          >
            <Filter className="h-4 w-4" />
          </button>
        </div>
      </div>

      {/* Filters */}
      {showFilters && (
        <div className="p-4 bg-gray-50 border-b border-gray-200">
          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => setFilter('all')}
              className={`px-3 py-1 text-xs font-medium rounded-full transition-colors ${
                filter === 'all' 
                  ? 'bg-blue-100 text-blue-800' 
                  : 'bg-white text-gray-600 hover:bg-gray-100'
              }`}
            >
              All ({alerts.length})
            </button>
            <button
              onClick={() => setFilter('critical')}
              className={`px-3 py-1 text-xs font-medium rounded-full transition-colors ${
                filter === 'critical' 
                  ? 'bg-red-100 text-red-800' 
                  : 'bg-white text-gray-600 hover:bg-gray-100'
              }`}
            >
              Critical ({getFilterCount('critical')})
            </button>
            <button
              onClick={() => setFilter('high')}
              className={`px-3 py-1 text-xs font-medium rounded-full transition-colors ${
                filter === 'high' 
                  ? 'bg-orange-100 text-orange-800' 
                  : 'bg-white text-gray-600 hover:bg-gray-100'
              }`}
            >
              High ({getFilterCount('high')})
            </button>
            <button
              onClick={() => setFilter('active')}
              className={`px-3 py-1 text-xs font-medium rounded-full transition-colors ${
                filter === 'active' 
                  ? 'bg-green-100 text-green-800' 
                  : 'bg-white text-gray-600 hover:bg-gray-100'
              }`}
            >
              Active ({getFilterCount('active')})
            </button>
          </div>
        </div>
      )}

      {/* Alerts List */}
      <div className="overflow-y-auto" style={{ maxHeight }}>
        {filteredAlerts.length === 0 ? (
          <div className="p-8 text-center text-gray-500">
            <Shield className="h-12 w-12 mx-auto mb-3 text-gray-300" />
            <p className="text-sm">No alerts match your current filter</p>
          </div>
        ) : (
          <div className="divide-y divide-gray-100">
            {filteredAlerts.map((alert) => (
              <div
                key={alert.id}
                onClick={() => handleAlertClick(alert)}
                className="p-4 hover:bg-gray-50 cursor-pointer transition-colors"
              >
                <div className="flex items-start space-x-3">
                  <div className={`flex-shrink-0 p-1 rounded-full ${getSeverityColor(alert.severity)}`}>
                    {getTypeIcon(alert.type)}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between">
                      <p className="text-sm font-medium text-gray-900 truncate">
                        {alert.title}
                      </p>
                      <div className="flex items-center space-x-2 text-xs text-gray-500">
                        <Clock className="h-3 w-3" />
                        <span>{formatTimestamp(alert.timestamp)}</span>
                      </div>
                    </div>
                    <p className="text-sm text-gray-600 mt-1 line-clamp-2">
                      {alert.description}
                    </p>
                    <div className="flex items-center justify-between mt-2">
                      <div className="flex items-center space-x-4 text-xs text-gray-500">
                        <span>Source: {alert.source}</span>
                        <span>Protocol: {alert.protocol}</span>
                        <span>Count: {alert.count}</span>
                      </div>
                      <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${
                        alert.status === 'active' ? 'bg-red-100 text-red-800' :
                        alert.status === 'investigating' ? 'bg-yellow-100 text-yellow-800' :
                        alert.status === 'resolved' ? 'bg-green-100 text-green-800' :
                        alert.status === 'blocked' ? 'bg-gray-100 text-gray-800' :
                        'bg-blue-100 text-blue-800'
                      }`}>
                        {alert.status}
                      </span>
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Alert Details Modal */}
      {selectedAlert && (
        <div className="fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-4">
          <div className="bg-white rounded-lg shadow-xl max-w-2xl w-full max-h-screen overflow-y-auto">
            <div className="flex items-center justify-between p-4 border-b border-gray-200">
              <h3 className="text-lg font-semibold text-gray-900">Alert Details</h3>
              <button
                onClick={handleCloseDetails}
                className="p-2 text-gray-400 hover:text-gray-600 hover:bg-gray-100 rounded-md"
              >
                <X className="h-5 w-5" />
              </button>
            </div>
            <div className="p-6">
              <div className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-medium mb-4 ${getSeverityColor(selectedAlert.severity)}`}>
                {getTypeIcon(selectedAlert.type)}
                <span className="ml-2 capitalize">{selectedAlert.severity} {selectedAlert.type}</span>
              </div>
              <h4 className="text-xl font-semibold text-gray-900 mb-2">{selectedAlert.title}</h4>
              <p className="text-gray-600 mb-6">{selectedAlert.description}</p>
              
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <label className="font-medium text-gray-700">Timestamp:</label>
                  <p className="text-gray-600">{selectedAlert.timestamp.toLocaleString()}</p>
                </div>
                <div>
                  <label className="font-medium text-gray-700">Source:</label>
                  <p className="text-gray-600">{selectedAlert.source}</p>
                </div>
                <div>
                  <label className="font-medium text-gray-700">Protocol:</label>
                  <p className="text-gray-600">{selectedAlert.protocol}</p>
                </div>
                <div>
                  <label className="font-medium text-gray-700">Event Count:</label>
                  <p className="text-gray-600">{selectedAlert.count}</p>
                </div>
                <div>
                  <label className="font-medium text-gray-700">Status:</label>
                  <p className="text-gray-600 capitalize">{selectedAlert.status}</p>
                </div>
                <div>
                  <label className="font-medium text-gray-700">Severity:</label>
                  <p className="text-gray-600 capitalize">{selectedAlert.severity}</p>
                </div>
              </div>
              
              <div className="mt-6 flex space-x-3">
                <button className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors">
                  Investigate
                </button>
                <button className="px-4 py-2 bg-green-600 text-white rounded-md hover:bg-green-700 transition-colors">
                  Mark as Resolved
                </button>
                <button className="px-4 py-2 bg-red-600 text-white rounded-md hover:bg-red-700 transition-colors">
                  Block Source
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default AlertsPanel;