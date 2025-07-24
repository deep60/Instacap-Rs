import React, { useState } from 'react';
import { 
  BarChart3, 
  Network, 
  Shield, 
  Activity, 
  Settings, 
  FileText,
  AlertTriangle,
  TrendingUp,
  Database,
  Filter,
  Eye,
  Target,
  Globe,
  Zap,
  Lock,
  ChevronDown,
  ChevronRight
} from 'lucide-react';

const Navigation = ({ activeItem, onItemClick }) => {
  const [expandedSections, setExpandedSections] = useState({
    analysis: true,
    security: true,
    monitoring: true
  });

  const toggleSection = (section) => {
    setExpandedSections(prev => ({
      ...prev,
      [section]: !prev[section]
    }));
  };

  const navigationItems = [
    {
      id: 'dashboard',
      label: 'Dashboard',
      icon: BarChart3,
      path: '/dashboard',
      badge: null
    },
    {
      id: 'analysis',
      label: 'Traffic Analysis',
      icon: Network,
      isSection: true,
      children: [
        {
          id: 'packet-analysis',
          label: 'Packet Analysis',
          icon: Database,
          path: '/packets',
          badge: null
        },
        {
          id: 'protocol-analysis',
          label: 'Protocol Analysis',
          icon: Globe,
          path: '/protocols',
          badge: null
        },
        {
          id: 'traffic-flows',
          label: 'Traffic Flows',
          icon: TrendingUp,
          path: '/flows',
          badge: null
        }
      ]
    },
    {
      id: 'security',
      label: 'Security & Threats',
      icon: Shield,
      isSection: true,
      children: [
        {
          id: 'threat-detection',
          label: 'Threat Detection',
          icon: Target,
          path: '/threats',
          badge: { count: 3, type: 'warning' }
        },
        {
          id: 'anomaly-detection',
          label: 'Anomaly Detection',
          icon: AlertTriangle,
          path: '/anomalies',
          badge: { count: 1, type: 'danger' }
        },
        {
          id: 'intrusion-detection',
          label: 'Intrusion Detection',
          icon: Lock,
          path: '/intrusions',
          badge: null
        }
      ]
    },
    {
      id: 'monitoring',
      label: 'Performance',
      icon: Activity,
      isSection: true,
      children: [
        {
          id: 'performance-metrics',
          label: 'Performance Metrics',
          icon: Zap,
          path: '/performance',
          badge: null
        },
        {
          id: 'bandwidth-analysis',
          label: 'Bandwidth Analysis',
          icon: TrendingUp,
          path: '/bandwidth',
          badge: null
        },
        {
          id: 'latency-monitoring',
          label: 'Latency Monitoring',
          icon: Activity,
          path: '/latency',
          badge: null
        }
      ]
    },
    {
      id: 'filters',
      label: 'Capture Filters',
      icon: Filter,
      path: '/filters',
      badge: null
    },
    {
      id: 'reports',
      label: 'Reports',
      icon: FileText,
      path: '/reports',
      badge: null
    },
    {
      id: 'settings',
      label: 'Settings',
      icon: Settings,
      path: '/settings',
      badge: null
    }
  ];

  const renderBadge = (badge) => {
    if (!badge) return null;
    
    const badgeClasses = {
      danger: 'bg-red-500 text-white',
      warning: 'bg-yellow-500 text-white',
      info: 'bg-blue-500 text-white',
      success: 'bg-green-500 text-white'
    };

    return (
      <span className={`ml-auto px-2 py-1 text-xs rounded-full ${badgeClasses[badge.type] || badgeClasses.info}`}>
        {badge.count}
      </span>
    );
  };

  const renderNavItem = (item, isChild = false) => {
    const isActive = activeItem === item.id;
    const Icon = item.icon;
    
    const baseClasses = `
      flex items-center w-full px-3 py-2 text-sm font-medium rounded-lg transition-all duration-200
      ${isChild ? 'ml-6 pl-3' : ''}
    `;
    
    const activeClasses = isActive 
      ? 'bg-blue-600 text-white shadow-lg' 
      : 'text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 hover:text-gray-900 dark:hover:text-white';

    if (item.isSection) {
      const isExpanded = expandedSections[item.id];
      return (
        <div key={item.id} className="mb-2">
          <button
            onClick={() => toggleSection(item.id)}
            className={`${baseClasses} ${activeClasses} justify-between`}
          >
            <div className="flex items-center">
              <Icon className="w-5 h-5 mr-3" />
              <span>{item.label}</span>
            </div>
            {isExpanded ? (
              <ChevronDown className="w-4 h-4" />
            ) : (
              <ChevronRight className="w-4 h-4" />
            )}
          </button>
          {isExpanded && (
            <div className="mt-1 space-y-1">
              {item.children.map(child => renderNavItem(child, true))}
            </div>
          )}
        </div>
      );
    }

    return (
      <button
        key={item.id}
        onClick={() => onItemClick(item.id, item.path)}
        className={`${baseClasses} ${activeClasses}`}
      >
        <Icon className="w-5 h-5 mr-3" />
        <span className="flex-1 text-left">{item.label}</span>
        {renderBadge(item.badge)}
      </button>
    );
  };

  return (
    <nav className="bg-white dark:bg-gray-800 border-r border-gray-200 dark:border-gray-700 w-64 h-full flex flex-col">
      {/* Navigation Header */}
      <div className="p-4 border-b border-gray-200 dark:border-gray-700">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
            Navigation
          </h2>
          <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
        </div>
      </div>

      {/* Quick Stats */}
      <div className="p-4 border-b border-gray-200 dark:border-gray-700">
        <div className="grid grid-cols-2 gap-3">
          <div className="bg-blue-50 dark:bg-blue-900/20 p-3 rounded-lg">
            <div className="text-xs text-blue-600 dark:text-blue-400 font-medium">
              Active Captures
            </div>
            <div className="text-lg font-bold text-blue-700 dark:text-blue-300">
              2
            </div>
          </div>
          <div className="bg-red-50 dark:bg-red-900/20 p-3 rounded-lg">
            <div className="text-xs text-red-600 dark:text-red-400 font-medium">
              Threats Detected
            </div>
            <div className="text-lg font-bold text-red-700 dark:text-red-300">
              4
            </div>
          </div>
        </div>
      </div>

      {/* Navigation Items */}
      <div className="flex-1 overflow-y-auto p-4">
        <div className="space-y-1">
          {navigationItems.map(item => renderNavItem(item))}
        </div>
      </div>

      {/* Footer */}
      <div className="p-4 border-t border-gray-200 dark:border-gray-700">
        <div className="flex items-center justify-between text-xs text-gray-500 dark:text-gray-400">
          <span>System Status</span>
          <div className="flex items-center space-x-2">
            <div className="w-2 h-2 bg-green-500 rounded-full"></div>
            <span>Online</span>
          </div>
        </div>
        <div className="mt-2 text-xs text-gray-400 dark:text-gray-500">
          Last update: {new Date().toLocaleTimeString()}
        </div>
      </div>
    </nav>
  );
};

export default Navigation;