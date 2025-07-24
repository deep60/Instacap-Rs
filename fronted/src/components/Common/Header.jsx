import React, { useState, useEffect } from 'react';
import { Bell, Settings, Search, Activity, Shield, Zap, AlertTriangle } from 'lucide-react';

const Header = () => {
  const [currentTime, setCurrentTime] = useState(new Date());
  const [connectionStatus, setConnectionStatus] = useState('connected');
  const [activeAlerts, setActiveAlerts] = useState(3);
  const [captureStatus, setCaptureStatus] = useState('active');

  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentTime(new Date());
    }, 1000);

    return () => clearInterval(timer);
  }, []);

  const getStatusColor = (status) => {
    switch (status) {
      case 'connected':
        return 'text-green-500';
      case 'disconnected':
        return 'text-red-500';
      case 'connecting':
        return 'text-yellow-500';
      default:
        return 'text-gray-500';
    }
  };

  const getCaptureStatusColor = (status) => {
    switch (status) {
      case 'active':
        return 'text-green-500 bg-green-500/10';
      case 'paused':
        return 'text-yellow-500 bg-yellow-500/10';
      case 'stopped':
        return 'text-red-500 bg-red-500/10';
      default:
        return 'text-gray-500 bg-gray-500/10';
    }
  };

  return (
    <header className="bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700 shadow-sm">
      <div className="px-6 py-4">
        <div className="flex items-center justify-between">
          {/* Left Section - Logo and Title */}
          <div className="flex items-center space-x-4">
            <div className="flex items-center space-x-3">
              <div className="p-2 bg-blue-600 rounded-lg">
                <Activity className="w-6 h-6 text-white" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-gray-900 dark:text-white">
                  Packet Analyzer
                </h1>
                <p className="text-sm text-gray-500 dark:text-gray-400">
                  Network Traffic Monitor
                </p>
              </div>
            </div>
          </div>

          {/* Center Section - Status Indicators */}
          <div className="hidden md:flex items-center space-x-6">
            {/* Connection Status */}
            <div className="flex items-center space-x-2">
              <div className={`w-2 h-2 rounded-full ${connectionStatus === 'connected' ? 'bg-green-500' : 'bg-red-500'} animate-pulse`}></div>
              <span className={`text-sm font-medium ${getStatusColor(connectionStatus)}`}>
                {connectionStatus.charAt(0).toUpperCase() + connectionStatus.slice(1)}
              </span>
            </div>

            {/* Capture Status */}
            <div className={`flex items-center space-x-2 px-3 py-1 rounded-full ${getCaptureStatusColor(captureStatus)}`}>
              <Zap className="w-4 h-4" />
              <span className="text-sm font-medium">
                Capture {captureStatus.charAt(0).toUpperCase() + captureStatus.slice(1)}
              </span>
            </div>

            {/* Current Time */}
            <div className="text-sm text-gray-600 dark:text-gray-300 font-mono">
              {currentTime.toLocaleTimeString()}
            </div>
          </div>

          {/* Right Section - Actions */}
          <div className="flex items-center space-x-4">
            {/* Search */}
            <div className="relative">
              <input
                type="text"
                placeholder="Search packets..."
                className="w-64 pl-10 pr-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-500 dark:placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
              <Search className="absolute left-3 top-2.5 w-5 h-5 text-gray-400" />
            </div>

            {/* Alerts */}
            <div className="relative">
              <button className="p-2 text-gray-600 dark:text-gray-300 hover:text-gray-900 dark:hover:text-white hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors">
                <Bell className="w-5 h-5" />
                {activeAlerts > 0 && (
                  <span className="absolute -top-1 -right-1 bg-red-500 text-white text-xs rounded-full w-5 h-5 flex items-center justify-center">
                    {activeAlerts}
                  </span>
                )}
              </button>
            </div>

            {/* Threat Status */}
            <div className="flex items-center space-x-2 px-3 py-1 bg-yellow-100 dark:bg-yellow-900/30 text-yellow-800 dark:text-yellow-200 rounded-lg">
              <Shield className="w-4 h-4" />
              <span className="text-sm font-medium">Protected</span>
            </div>

            {/* Settings */}
            <button className="p-2 text-gray-600 dark:text-gray-300 hover:text-gray-900 dark:hover:text-white hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors">
              <Settings className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Mobile Status Row */}
        <div className="md:hidden mt-3 flex items-center justify-between text-sm">
          <div className="flex items-center space-x-4">
            <div className="flex items-center space-x-2">
              <div className={`w-2 h-2 rounded-full ${connectionStatus === 'connected' ? 'bg-green-500' : 'bg-red-500'} animate-pulse`}></div>
              <span className={getStatusColor(connectionStatus)}>
                {connectionStatus}
              </span>
            </div>
            <div className={`flex items-center space-x-1 px-2 py-1 rounded ${getCaptureStatusColor(captureStatus)}`}>
              <Zap className="w-3 h-3" />
              <span>{captureStatus}</span>
            </div>
          </div>
          <div className="text-gray-600 dark:text-gray-300 font-mono">
            {currentTime.toLocaleTimeString()}
          </div>
        </div>
      </div>
    </header>
  );
};

export default Header;