import React, { useState, useEffect } from 'react';
import StatsGrid from './StatsGrid';
import TrafficChart from './TrafficChart';
import AlertsPanel from './AlertsPanel';
import LoadingSpinner from '../Common/LoadingSpinner';
import { useWebSocket } from '../../hooks/useWebSocket';
import { usePacketData } from '../../hooks/usePacketData';
import { useThreatDetection } from '../../hooks/useThreatDetection';

const Dashboard = () => {
  const [selectedTimeRange, setSelectedTimeRange] = useState('1h');
  const [isLiveMode, setIsLiveMode] = useState(true);
  const [dashboardData, setDashboardData] = useState({
    overview: null,
    recentActivity: [],
    systemHealth: null
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Custom hooks for real-time data
  const { isConnected, connectionStatus } = useWebSocket();
  const { packetStats, isPacketDataLoading } = usePacketData();
  const { threatAlerts, activeThreatCount } = useThreatDetection();

  useEffect(() => {
    initializeDashboard();
  }, []);

  useEffect(() => {
    if (isLiveMode) {
      const interval = setInterval(refreshDashboardData, 5000);
      return () => clearInterval(interval);
    }
  }, [isLiveMode, selectedTimeRange]);

  const initializeDashboard = async () => {
    try {
      setLoading(true);
      await Promise.all([
        fetchOverviewData(),
        fetchRecentActivity(),
        fetchSystemHealth()
      ]);
      setError(null);
    } catch (err) {
      setError('Failed to initialize dashboard');
      console.error('Dashboard initialization error:', err);
    } finally {
      setLoading(false);
    }
  };

  const fetchOverviewData = async () => {
    try {
      const response = await fetch(`/api/dashboard/overview?timeRange=${selectedTimeRange}`);
      const data = await response.json();
      setDashboardData(prev => ({ ...prev, overview: data }));
    } catch (error) {
      console.error('Error fetching overview data:', error);
    }
  };

  const fetchRecentActivity = async () => {
    try {
      const response = await fetch('/api/dashboard/recent-activity?limit=10');
      const data = await response.json();
      setDashboardData(prev => ({ ...prev, recentActivity: data }));
    } catch (error) {
      console.error('Error fetching recent activity:', error);
    }
  };

  const fetchSystemHealth = async () => {
    try {
      const response = await fetch('/api/dashboard/system-health');
      const data = await response.json();
      setDashboardData(prev => ({ ...prev, systemHealth: data }));
    } catch (error) {
      console.error('Error fetching system health:', error);
    }
  };

  const refreshDashboardData = async () => {
    if (!isLiveMode) return;
    
    try {
      await Promise.all([
        fetchOverviewData(),
        fetchRecentActivity(),
        fetchSystemHealth()
      ]);
    } catch (error) {
      console.error('Error refreshing dashboard:', error);
    }
  };

  const handleTimeRangeChange = (timeRange) => {
    setSelectedTimeRange(timeRange);
    setIsLiveMode(timeRange === '1h' || timeRange === '15m');
    refreshDashboardData();
  };

  const handleRefresh = () => {
    refreshDashboardData();
  };

  const handleExportData = async () => {
    try {
      const response = await fetch(`/api/dashboard/export?timeRange=${selectedTimeRange}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      });
      
      if (response.ok) {
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `network-report-${new Date().toISOString().split('T')[0]}.csv`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
      }
    } catch (error) {
      console.error('Error exporting data:', error);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <LoadingSpinner size="lg" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-red-50 border border-red-200 rounded-lg p-6 m-4">
        <div className="flex items-center">
          <span className="text-2xl mr-3">❌</span>
          <div>
            <h3 className="text-lg font-semibold text-red-800">Dashboard Error</h3>
            <p className="text-red-600">{error}</p>
            <button 
              onClick={initializeDashboard}
              className="mt-2 px-4 py-2 bg-red-600 text-white rounded hover:bg-red-700 transition-colors"
            >
              Retry
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Dashboard Header */}
      <div className="flex flex-col lg:flex-row justify-between items-start lg:items-center space-y-4 lg:space-y-0">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Network Monitor Dashboard</h1>
          <p className="text-gray-600 mt-1">Real-time network analysis and monitoring</p>
        </div>
        
        <div className="flex flex-col sm:flex-row items-start sm:items-center space-y-2 sm:space-y-0 sm:space-x-4">
          {/* Connection Status */}
          <div className="flex items-center space-x-2">
            <div className={`w-3 h-3 rounded-full ${isConnected ? 'bg-green-500' : 'bg-red-500'}`}></div>
            <span className={`text-sm font-medium ${isConnected ? 'text-green-600' : 'text-red-600'}`}>
              {connectionStatus}
            </span>
          </div>

          {/* Live Mode Toggle */}
          <div className="flex items-center space-x-2">
            <input
              type="checkbox"
              id="liveMode"
              checked={isLiveMode}
              onChange={(e) => setIsLiveMode(e.target.checked)}
              className="w-4 h-4 text-blue-600 bg-gray-100 border-gray-300 rounded focus:ring-blue-500"
            />
            <label htmlFor="liveMode" className="text-sm font-medium text-gray-700">
              Live Mode
            </label>
          </div>

          {/* Time Range Selector */}
          <select
            value={selectedTimeRange}
            onChange={(e) => handleTimeRangeChange(e.target.value)}
            className="px-3 py-2 border border-gray-300 rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <option value="15m">Last 15 minutes</option>
            <option value="1h">Last hour</option>
            <option value="6h">Last 6 hours</option>
            <option value="24h">Last 24 hours</option>
            <option value="7d">Last 7 days</option>
          </select>

          {/* Action Buttons */}
          <div className="flex space-x-2">
            <button
              onClick={handleRefresh}
              className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors text-sm flex items-center space-x-1"
            >
              <span>🔄</span>
              <span>Refresh</span>
            </button>
            
            <button
              onClick={handleExportData}
              className="px-4 py-2 bg-gray-600 text-white rounded-md hover:bg-gray-700 transition-colors text-sm flex items-center space-x-1"
            >
              <span>📊</span>
              <span>Export</span>
            </button>
          </div>
        </div>
      </div>

      {/* Active Threats Alert */}
      {activeThreatCount > 0 && (
        <div className="bg-red-50 border-l-4 border-red-400 p-4 rounded-r-lg">
          <div className="flex items-center">
            <span className="text-2xl mr-3">🚨</span>
            <div>
              <p className="text-red-800 font-semibold">
                {activeThreatCount} Active Threat{activeThreatCount > 1 ? 's' : ''} Detected
              </p>
              <p className="text-red-700 text-sm">
                Immediate attention required. Check the threats panel for details.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* System Health Status */}
      {dashboardData.systemHealth && dashboardData.systemHealth.status !== 'healthy' && (
        <div className="bg-yellow-50 border-l-4 border-yellow-400 p-4 rounded-r-lg">
          <div className="flex items-center">
            <span className="text-2xl mr-3">⚠️</span>
            <div>
              <p className="text-yellow-800 font-semibold">System Health Warning</p>
              <p className="text-yellow-700 text-sm">
                {dashboardData.systemHealth.message}
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Statistics Grid */}
      <StatsGrid refreshInterval={isLiveMode ? 5000 : 30000} />

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Traffic Chart - Takes 2/3 width on xl screens */}
        <div className="xl:col-span-2">
          <TrafficChart 
            timeRange={selectedTimeRange}
            isLiveMode={isLiveMode}
            height={400}
          />
        </div>

        {/* Alerts Panel - Takes 1/3 width on xl screens */}
        <div className="xl:col-span-1">
          <AlertsPanel 
            alerts={threatAlerts}
            maxAlerts={10}
            showAll={false}
          />
        </div>
      </div>

      {/* Recent Activity Section */}
      <div className="bg-white rounded-lg shadow-md">
        <div className="px-6 py-4 border-b border-gray-200">
          <h3 className="text-lg font-semibold text-gray-900">Recent Network Activity</h3>
        </div>
        <div className="p-6">
          {dashboardData.recentActivity.length > 0 ? (
            <div className="space-y-3">
              {dashboardData.recentActivity.map((activity, index) => (
                <div key={index} className="flex items-center justify-between py-2 border-b border-gray-100 last:border-b-0">
                  <div className="flex items-center space-x-3">
                    <span className="text-lg">
                      {activity.type === 'threat' ? '🚨' : 
                       activity.type === 'anomaly' ? '⚠️' : 
                       activity.type === 'connection' ? '🔗' : '📊'}
                    </span>
                    <div>
                      <p className="text-sm font-medium text-gray-900">{activity.description}</p>
                      <p className="text-xs text-gray-500">{activity.source}</p>
                    </div>
                  </div>
                  <div className="text-right">
                    <p className="text-xs text-gray-500">{activity.timestamp}</p>
                    <span className={`inline-flex px-2 py-1 text-xs rounded-full ${
                      activity.severity === 'high' ? 'bg-red-100 text-red-800' :
                      activity.severity === 'medium' ? 'bg-yellow-100 text-yellow-800' :
                      'bg-green-100 text-green-800'
                    }`}>
                      {activity.severity}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-8 text-gray-500">
              <span className="text-4xl mb-2 block">📊</span>
              <p>No recent activity to display</p>
            </div>
          )}
        </div>
      </div>

      {/* Footer Stats */}
      <div className="text-center text-sm text-gray-500 py-4 border-t border-gray-200">
        Last updated: {new Date().toLocaleTimeString()} | 
        Monitoring {dashboardData.overview?.totalInterfaces || 0} interfaces | 
        Uptime: {dashboardData.systemHealth?.uptime || 'Unknown'}
      </div>
    </div>
  );
};

export default Dashboard;