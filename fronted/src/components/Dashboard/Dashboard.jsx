import React from 'react';
import StatsGrid from './StatsGrid';
import TrafficChart from './TrafficChart';
import AlertsPanel from './AlertsPanel';
import { Activity, Shield, Network, TrendingUp } from 'lucide-react';

const Dashboard = () => {
  const quickStats = [
    {
      title: 'Total Packets',
      value: '2.4M',
      change: '+12.5%',
      trend: 'up',
      icon: Network,
      color: 'blue'
    },
    {
      title: 'Active Threats',
      value: '3',
      change: '-2',
      trend: 'down',
      icon: Shield,
      color: 'red'
    },
    {
      title: 'Bandwidth Usage',
      value: '847 MB/s',
      change: '+8.2%',
      trend: 'up',
      icon: Activity,
      color: 'green'
    },
    {
      title: 'Performance Score',
      value: '94%',
      change: '+1.2%',
      trend: 'up',
      icon: TrendingUp,
      color: 'purple'
    }
  ];

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Network Dashboard</h1>
          <p className="text-gray-600 mt-1">Real-time network monitoring and analysis</p>
        </div>
        <div className="flex space-x-3">
          <button className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors">
            Export Report
          </button>
          <button className="px-4 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50 transition-colors">
            Settings
          </button>
        </div>
      </div>

      {/* Stats Grid */}
      <StatsGrid stats={quickStats} />

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Traffic Chart - Takes 2/3 width */}
        <div className="lg:col-span-2">
          <TrafficChart />
        </div>
        
        {/* Alerts Panel - Takes 1/3 width */}
        <div className="lg:col-span-1">
          <AlertsPanel />
        </div>
      </div>

      {/* Protocol Distribution and Top Connections */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Protocol Distribution */}
        <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Protocol Distribution</h3>
          <div className="space-y-3">
            {[
              { protocol: 'HTTP/HTTPS', percentage: 45, packets: '1.08M', color: 'bg-blue-500' },
              { protocol: 'TCP', percentage: 25, packets: '600K', color: 'bg-green-500' },
              { protocol: 'UDP', percentage: 15, packets: '360K', color: 'bg-yellow-500' },
              { protocol: 'DNS', percentage: 10, packets: '240K', color: 'bg-purple-500' },
              { protocol: 'Other', percentage: 5, packets: '120K', color: 'bg-gray-400' }
            ].map((item) => (
              <div key={item.protocol} className="flex items-center justify-between">
                <div className="flex items-center space-x-3">
                  <div className={`w-3 h-3 rounded-full ${item.color}`}></div>
                  <span className="text-gray-700">{item.protocol}</span>
                </div>
                <div className="flex items-center space-x-4">
                  <div className="w-24 bg-gray-200 rounded-full h-2">
                    <div 
                      className={`h-2 rounded-full ${item.color}`}
                      style={{ width: `${item.percentage}%` }}
                    ></div>
                  </div>
                  <span className="text-sm text-gray-600 w-16">{item.percentage}%</span>
                  <span className="text-sm text-gray-500 w-20">{item.packets}</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Top Connections */}
        <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Top Connections</h3>
          <div className="space-y-4">
            {[
              { 
                source: '192.168.1.100', 
                destination: '8.8.8.8', 
                protocol: 'DNS', 
                packets: '15,247',
                status: 'active'
              },
              { 
                source: '192.168.1.45', 
                destination: '173.252.74.22', 
                protocol: 'HTTPS', 
                packets: '8,924',
                status: 'active'
              },
              { 
                source: '192.168.1.78', 
                destination: '142.250.191.14', 
                protocol: 'HTTP', 
                packets: '6,752',
                status: 'suspicious'
              },
              { 
                source: '192.168.1.200', 
                destination: '10.0.0.1', 
                protocol: 'TCP', 
                packets: '4,123',
                status: 'active'
              }
            ].map((conn, index) => (
              <div key={index} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                <div className="flex-1">
                  <div className="flex items-center space-x-2">
                    <span className="text-sm font-mono text-gray-800">{conn.source}</span>
                    <span className="text-gray-400">→</span>
                    <span className="text-sm font-mono text-gray-800">{conn.destination}</span>
                  </div>
                  <div className="flex items-center space-x-2 mt-1">
                    <span className="px-2 py-1 bg-blue-100 text-blue-700 text-xs rounded-full">
                      {conn.protocol}
                    </span>
                    <span className="text-xs text-gray-500">{conn.packets} packets</span>
                  </div>
                </div>
                <div className={`w-2 h-2 rounded-full ${
                  conn.status === 'active' ? 'bg-green-500' : 'bg-yellow-500'
                }`}></div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;