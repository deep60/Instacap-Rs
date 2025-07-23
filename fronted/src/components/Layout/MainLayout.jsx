import React, { useState, useEffect } from 'react';
import { Menu, X, Bell, Settings, User, Activity, Shield, Network, BarChart3 } from 'lucide-react';
import Sidebar from './Sidebar';
import Header from '../Common/Header';

const MainLayout = ({ children, currentView, onViewChange }) => {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [isMobile, setIsMobile] = useState(false);
  const [notifications, setNotifications] = useState([]);
  const [systemStatus, setSystemStatus] = useState({
    captureActive: true,
    threatsDetected: 0,
    packetsProcessed: 0,
    systemHealth: 'healthy'
  });

  // Check for mobile viewport
  useEffect(() => {
    const checkMobile = () => {
      setIsMobile(window.innerWidth < 768);
      if (window.innerWidth >= 768) {
        setSidebarOpen(false);
      }
    };

    checkMobile();
    window.addEventListener('resize', checkMobile);
    return () => window.removeEventListener('resize', checkMobile);
  }, []);

  // Mock system status updates
  useEffect(() => {
    const interval = setInterval(() => {
      setSystemStatus(prev => ({
        ...prev,
        packetsProcessed: prev.packetsProcessed + Math.floor(Math.random() * 100),
        threatsDetected: prev.threatsDetected + (Math.random() > 0.95 ? 1 : 0)
      }));
    }, 5000);

    return () => clearInterval(interval);
  }, []);

  // Mock notifications
  useEffect(() => {
    const mockNotifications = [
      {
        id: 1,
        type: 'warning',
        title: 'Unusual Traffic Detected',
        message: 'High volume of traffic from 192.168.1.100',
        timestamp: new Date(Date.now() - 5 * 60 * 1000),
        read: false
      },
      {
        id: 2,
        type: 'info',
        title: 'System Update',
        message: 'Threat detection rules updated successfully',
        timestamp: new Date(Date.now() - 15 * 60 * 1000),
        read: true
      },
      {
        id: 3,
        type: 'error',
        title: 'Connection Lost',
        message: 'Lost connection to network interface eth0',
        timestamp: new Date(Date.now() - 30 * 60 * 1000),
        read: false
      }
    ];
    setNotifications(mockNotifications);
  }, []);

  const navigationItems = [
    {
      id: 'dashboard',
      label: 'Dashboard',
      icon: BarChart3,
      path: '/dashboard'
    },
    {
      id: 'packets',
      label: 'Packet Analysis',
      icon: Network,
      path: '/packets'
    },
    {
      id: 'threats',
      label: 'Threat Detection',
      icon: Shield,
      path: '/threats'
    },
    {
      id: 'performance',
      label: 'Performance',
      icon: Activity,
      path: '/performance'
    },
    {
      id: 'protocols',
      label: 'Protocol Analysis',
      icon: Network,
      path: '/protocols'
    }
  ];

  const toggleSidebar = () => {
    setSidebarOpen(!sidebarOpen);
  };

  const closeSidebar = () => {
    setSidebarOpen(false);
  };

  const handleNotificationRead = (notificationId) => {
    setNotifications(prev =>
      prev.map(notification =>
        notification.id === notificationId
          ? { ...notification, read: true }
          : notification
      )
    );
  };

  const unreadNotifications = notifications.filter(n => !n.read).length;

  const getStatusColor = (status) => {
    switch (status) {
      case 'healthy': return 'text-green-600';
      case 'warning': return 'text-yellow-600';
      case 'critical': return 'text-red-600';
      default: return 'text-gray-600';
    }
  };

  const getStatusBgColor = (status) => {
    switch (status) {
      case 'healthy': return 'bg-green-100';
      case 'warning': return 'bg-yellow-100';
      case 'critical': return 'bg-red-100';
      default: return 'bg-gray-100';
    }
  };

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Mobile sidebar overlay */}
      {sidebarOpen && isMobile && (
        <div
          className="fixed inset-0 z-40 bg-black bg-opacity-50 md:hidden"
          onClick={closeSidebar}
        />
      )}

      {/* Sidebar */}
      <div className={`
        fixed inset-y-0 left-0 z-50 w-64 bg-white shadow-lg transform transition-transform duration-300 ease-in-out
        ${sidebarOpen ? 'translate-x-0' : '-translate-x-full'}
        md:translate-x-0 md:static md:inset-0
      `}>
        <Sidebar
          navigationItems={navigationItems}
          currentView={currentView}
          onViewChange={onViewChange}
          onClose={closeSidebar}
          systemStatus={systemStatus}
        />
      </div>

      {/* Main content */}
      <div className="md:ml-64 flex flex-col min-h-screen">
        {/* Top Header */}
        <header className="bg-white shadow-sm border-b border-gray-200 sticky top-0 z-30">
          <div className="px-4 sm:px-6 lg:px-8">
            <div className="flex items-center justify-between h-16">
              {/* Mobile menu button */}
              <div className="flex items-center">
                <button
                  onClick={toggleSidebar}
                  className="md:hidden p-2 rounded-md text-gray-400 hover:text-gray-500 hover:bg-gray-100 focus:outline-none focus:ring-2 focus:ring-inset focus:ring-blue-500"
                >
                  {sidebarOpen ? (
                    <X className="h-6 w-6" />
                  ) : (
                    <Menu className="h-6 w-6" />
                  )}
                </button>

                {/* Page title */}
                <div className="ml-4 md:ml-0">
                  <h1 className="text-lg font-semibold text-gray-900 capitalize">
                    {currentView === 'packets' ? 'Packet Analysis' : 
                     currentView === 'threats' ? 'Threat Detection' :
                     currentView === 'performance' ? 'Performance Monitoring' :
                     currentView === 'protocols' ? 'Protocol Analysis' :
                     'Network Dashboard'}
                  </h1>
                </div>
              </div>

              {/* System status indicators */}
              <div className="hidden sm:flex items-center space-x-4">
                <div className="flex items-center space-x-2">
                  <div className={`w-3 h-3 rounded-full ${
                    systemStatus.captureActive ? 'bg-green-500' : 'bg-red-500'
                  }`} />
                  <span className="text-sm text-gray-600">
                    {systemStatus.captureActive ? 'Capturing' : 'Stopped'}
                  </span>
                </div>
                
                <div className="text-sm text-gray-600">
                  <span className="font-medium">{systemStatus.packetsProcessed.toLocaleString()}</span> packets
                </div>

                {systemStatus.threatsDetected > 0 && (
                  <div className="flex items-center space-x-1 text-sm text-red-600">
                    <Shield className="w-4 h-4" />
                    <span className="font-medium">{systemStatus.threatsDetected}</span> threats
                  </div>
                )}
              </div>

              {/* Right side actions */}
              <div className="flex items-center space-x-4">
                {/* Notifications */}
                <div className="relative">
                  <button className="p-2 text-gray-400 hover:text-gray-500 hover:bg-gray-100 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500">
                    <Bell className="h-6 w-6" />
                    {unreadNotifications > 0 && (
                      <span className="absolute -top-1 -right-1 h-5 w-5 bg-red-500 text-white text-xs rounded-full flex items-center justify-center">
                        {unreadNotifications}
                      </span>
                    )}
                  </button>
                </div>

                {/* Settings */}
                <button className="p-2 text-gray-400 hover:text-gray-500 hover:bg-gray-100 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500">
                  <Settings className="h-6 w-6" />
                </button>

                {/* User menu */}
                <div className="relative">
                  <button className="flex items-center space-x-2 p-2 text-gray-400 hover:text-gray-500 hover:bg-gray-100 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500">
                    <User className="h-6 w-6" />
                    <span className="hidden sm:block text-sm font-medium text-gray-700">
                      Admin
                    </span>
                  </button>
                </div>
              </div>
            </div>
          </div>

          {/* Secondary header with breadcrumbs/status */}
          <div className="px-4 sm:px-6 lg:px-8 py-2 bg-gray-50 border-t border-gray-200">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-4 text-sm text-gray-600">
                <span>Network Packet Analyzer</span>
                <span>•</span>
                <span className="capitalize">{currentView || 'dashboard'}</span>
              </div>
              
              <div className="flex items-center space-x-2">
                <div className={`px-2 py-1 rounded-full text-xs font-medium ${getStatusBgColor(systemStatus.systemHealth)} ${getStatusColor(systemStatus.systemHealth)}`}>
                  System {systemStatus.systemHealth}
                </div>
                <span className="text-xs text-gray-500">
                  Last updated: {new Date().toLocaleTimeString()}
                </span>
              </div>
            </div>
          </div>
        </header>

        {/* Main content area */}
        <main className="flex-1 overflow-x-hidden overflow-y-auto">
          <div className="container mx-auto px-4 sm:px-6 lg:px-8 py-6">
            {/* Emergency alerts */}
            {systemStatus.threatsDetected > 5 && (
              <div className="mb-6 bg-red-50 border border-red-200 rounded-md p-4">
                <div className="flex items-center">
                  <Shield className="h-5 w-5 text-red-400 mr-2" />
                  <div className="text-sm text-red-800">
                    <strong>Security Alert:</strong> Multiple threats detected. Immediate attention required.
                  </div>
                </div>
              </div>
            )}

            {/* Page content */}
            <div className="space-y-6">
              {children}
            </div>
          </div>
        </main>

        {/* Footer */}
        <footer className="bg-white border-t border-gray-200 px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex items-center justify-between text-sm text-gray-500">
            <div>
              © 2024 Network Packet Analyzer. All rights reserved.
            </div>
            <div className="flex items-center space-x-4">
              <span>Version 1.0.0</span>
              <span>•</span>
              <button className="hover:text-gray-700 transition-colors">
                Documentation
              </button>
              <span>•</span>
              <button className="hover:text-gray-700 transition-colors">
                Support
              </button>
            </div>
          </div>
        </footer>
      </div>

      {/* Notification panel (hidden by default, can be toggled) */}
      <div className="hidden fixed inset-y-0 right-0 w-96 bg-white shadow-lg border-l border-gray-200 z-50">
        <div className="p-4 border-b border-gray-200">
          <h3 className="text-lg font-semibold text-gray-900">Notifications</h3>
        </div>
        <div className="overflow-y-auto h-full pb-20">
          {notifications.map((notification) => (
            <div
              key={notification.id}
              className={`p-4 border-b border-gray-100 cursor-pointer hover:bg-gray-50 ${
                !notification.read ? 'bg-blue-50' : ''
              }`}
              onClick={() => handleNotificationRead(notification.id)}
            >
              <div className="flex items-start space-x-3">
                <div className={`w-2 h-2 rounded-full mt-2 ${
                  notification.type === 'error' ? 'bg-red-500' :
                  notification.type === 'warning' ? 'bg-yellow-500' :
                  'bg-blue-500'
                }`} />
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-gray-900">
                    {notification.title}
                  </p>
                  <p className="text-sm text-gray-600 mt-1">
                    {notification.message}
                  </p>
                  <p className="text-xs text-gray-400 mt-2">
                    {notification.timestamp.toLocaleString()}
                  </p>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

  export default MainLayout;