import React, { useState } from 'react';
import { 
  BarChart3, 
  Network, 
  Shield, 
  Activity, 
  Settings, 
  HelpCircle, 
  ChevronDown, 
  ChevronRight,
  X,
  Wifi,
  WifiOff,
  AlertTriangle,
  CheckCircle,
  Database,
  Filter,
  Download,
  Upload,
  Globe,
  Lock,
  Zap,
  Eye,
  FileText,
  TrendingUp
} from 'lucide-react';

const Sidebar = ({ 
  navigationItems = [], 
  currentView, 
  onViewChange, 
  onClose, 
  systemStatus 
}) => {
  const [expandedSections, setExpandedSections] = useState({
    analysis: true,
    monitoring: true,
    tools: false,
    settings: false
  });

  const toggleSection = (section) => {
    setExpandedSections(prev => ({
      ...prev,
      [section]: !prev[section]
    }));
  };

  const handleNavigation = (itemId) => {
    onViewChange(itemId);
    if (onClose) onClose(); // Close sidebar on mobile after navigation
  };

  const menuSections = [
    {
      id: 'overview',
      title: 'Overview',
      items: [
        {
          id: 'dashboard',
          label: 'Dashboard',
          icon: BarChart3,
          path: '/dashboard',
          badge: null
        }
      ]
    },
    {
      id: 'analysis',
      title: 'Network Analysis',
      expandable: true,
      items: [
        {
          id: 'packets',
          label: 'Packet Analysis',
          icon: Network,
          path: '/packets',
          badge: systemStatus?.packetsProcessed > 0 ? `${Math.floor(systemStatus.packetsProcessed / 1000)}K` : null
        },
        {
          id: 'protocols',
          label: 'Protocol Analysis',
          icon: Globe,
          path: '/protocols',
          badge: null
        },
        {
          id: 'deep-inspection',
          label: 'Deep Inspection',
          icon: Eye,
          path: '/deep-inspection',
          badge: null
        },
        {
          id: 'traffic-flow',
          label: 'Traffic Flow',
          icon: TrendingUp,
          path: '/traffic-flow',
          badge: null
        }
      ]
    },
    {
      id: 'monitoring',
      title: 'Security & Monitoring',
      expandable: true,
      items: [
        {
          id: 'threats',
          label: 'Threat Detection',
          icon: Shield,
          path: '/threats',
          badge: systemStatus?.threatsDetected > 0 ? systemStatus.threatsDetected.toString() : null,
          badgeColor: 'bg-red-500'
        },
        {
          id: 'anomalies',
          label: 'Anomaly Detection',
          icon: AlertTriangle,
          path: '/anomalies',
          badge: null
        },
        {
          id: 'alerts',
          label: 'Security Alerts',
          icon: Lock,
          path: '/alerts',
          badge: '3',
          badgeColor: 'bg-yellow-500'
        }
      ]
    },
    {
      id: 'performance',
      title: 'Performance',
      expandable: true,
      items: [
        {
          id: 'performance',
          label: 'Performance Metrics',
          icon: Activity,
          path: '/performance',
          badge: null
        },
        {
          id: 'bandwidth',
          label: 'Bandwidth Usage',
          icon: Zap,
          path: '/bandwidth',
          badge: null
        },
        {
          id: 'latency',
          label: 'Latency Analysis',
          icon: Activity,
          path: '/latency',
          badge: null
        }
      ]
    },
    {
      id: 'tools',
      title: 'Tools & Utilities',
      expandable: true,
      items: [
        {
          id: 'capture',
          label: 'Packet Capture',
          icon: Database,
          path: '/capture',
          badge: systemStatus?.captureActive ? 'ON' : 'OFF',
          badgeColor: systemStatus?.captureActive ? 'bg-green-500' : 'bg-gray-500'
        },
        {
          id: 'filters',
          label: 'Custom Filters',
          icon: Filter,
          path: '/filters',
          badge: null
        },
        {
          id: 'export',
          label: 'Export Data',
          icon: Download,
          path: '/export',
          badge: null
        },
        {
          id: 'import',
          label: 'Import PCAP',
          icon: Upload,
          path: '/import',
          badge: null
        },
        {
          id: 'reports',
          label: 'Reports',
          icon: FileText,
          path: '/reports',
          badge: null
        }
      ]
    },
    {
      id: 'settings',
      title: 'Configuration',
      expandable: true,
      items: [
        {
          id: 'settings',
          label: 'System Settings',
          icon: Settings,
          path: '/settings',
          badge: null
        },
        {
          id: 'help',
          label: 'Help & Support',
          icon: HelpCircle,
          path: '/help',
          badge: null
        }
      ]
    }
  ];

  const getConnectionStatusIcon = () => {
    if (systemStatus?.captureActive) {
      return <Wifi className="w-4 h-4 text-green-500" />;
    }
    return <WifiOff className="w-4 h-4 text-red-500" />;
  };

  const getSystemHealthIcon = () => {
    switch (systemStatus?.systemHealth) {
      case 'healthy':
        return <CheckCircle className="w-4 h-4 text-green-500" />;
      case 'warning':
        return <AlertTriangle className="w-4 h-4 text-yellow-500" />;
      case 'critical':
        return <AlertTriangle className="w-4 h-4 text-red-500" />;
      default:
        return <CheckCircle className="w-4 h-4 text-gray-500" />;
    }
  };

  const NavItem = ({ item, isActive }) => (
    <button
      onClick={() => handleNavigation(item.id)}
      className={`w-full flex items-center justify-between px-3 py-2 text-sm rounded-lg transition-all duration-200 group ${
        isActive
          ? 'bg-blue-50 text-blue-700 border-r-2 border-blue-500'
          : 'text-gray-700 hover:bg-gray-50 hover:text-gray-900'
      }`}
    >
      <div className="flex items-center space-x-3">
        <item.icon className={`w-5 h-5 ${
          isActive ? 'text-blue-600' : 'text-gray-400 group-hover:text-gray-600'
        }`} />
        <span className="font-medium">{item.label}</span>
      </div>
      {item.badge && (
        <span className={`px-2 py-1 text-xs font-semibold rounded-full text-white ${
          item.badgeColor || 'bg-blue-500'
        }`}>
          {item.badge}
        </span>
      )}
    </button>
  );

  const SectionHeader = ({ section }) => (
    <button
      onClick={() => section.expandable && toggleSection(section.id)}
      className="w-full flex items-center justify-between px-3 py-2 text-xs font-semibold text-gray-500 uppercase tracking-wider hover:text-gray-700 transition-colors"
    >
      <span>{section.title}</span>
      {section.expandable && (
        expandedSections[section.id] ? 
          <ChevronDown className="w-4 h-4" /> : 
          <ChevronRight className="w-4 h-4" />
      )}
    </button>
  );

  return (
    <div className="flex flex-col h-full bg-white">
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b border-gray-200">
        <div className="flex items-center space-x-2">
          <div className="w-8 h-8 bg-blue-600 rounded-lg flex items-center justify-center">
            <Network className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="text-lg font-bold text-gray-900">PacketLyzer</h1>
            <p className="text-xs text-gray-500">Network Analyzer</p>
          </div>
        </div>
        {onClose && (
          <button
            onClick={onClose}
            className="md:hidden p-1 rounded-md text-gray-400 hover:text-gray-500 hover:bg-gray-100"
          >
            <X className="w-5 h-5" />
          </button>
        )}
      </div>

      {/* System Status */}
      <div className="p-4 border-b border-gray-200">
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              {getConnectionStatusIcon()}
              <span className="text-sm font-medium text-gray-700">
                Network Status
              </span>
            </div>
            <span className={`text-xs px-2 py-1 rounded-full ${
              systemStatus?.captureActive 
                ? 'bg-green-100 text-green-800' 
                : 'bg-red-100 text-red-800'
            }`}>
              {systemStatus?.captureActive ? 'Active' : 'Inactive'}
            </span>
          </div>

          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              {getSystemHealthIcon()}
              <span className="text-sm font-medium text-gray-700">
                System Health
              </span>
            </div>
            <span className={`text-xs px-2 py-1 rounded-full capitalize ${
              systemStatus?.systemHealth === 'healthy' ? 'bg-green-100 text-green-800' :
              systemStatus?.systemHealth === 'warning' ? 'bg-yellow-100 text-yellow-800' :
              'bg-red-100 text-red-800'
            }`}>
              {systemStatus?.systemHealth || 'Unknown'}
            </span>
          </div>

          {/* Quick Stats */}
          <div className="grid grid-cols-2 gap-2 mt-3 pt-3 border-t border-gray-100">
            <div className="text-center">
              <div className="text-lg font-bold text-gray-900">
                {systemStatus?.packetsProcessed?.toLocaleString() || '0'}
              </div>
              <div className="text-xs text-gray-500">Packets</div>
            </div>
            <div className="text-center">
              <div className="text-lg font-bold text-red-600">
                {systemStatus?.threatsDetected || '0'}
              </div>
              <div className="text-xs text-gray-500">Threats</div>
            </div>
          </div>
        </div>
      </div>

      {/* Navigation Menu */}
      <nav className="flex-1 overflow-y-auto p-4">
        <div className="space-y-1">
          {menuSections.map((section) => (
            <div key={section.id}>
              <SectionHeader section={section} />
              {(!section.expandable || expandedSections[section.id]) && (
                <div className="ml-2 space-y-1 mb-4">
                  {section.items.map((item) => (
                    <NavItem
                      key={item.id}
                      item={item}
                      isActive={currentView === item.id}
                    />
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      </nav>

      {/* Footer */}
      <div className="p-4 border-t border-gray-200">
        <div className="text-xs text-gray-500 text-center">
          <div>Version 1.0.0</div>
          <div className="mt-1">
            Last updated: {new Date().toLocaleTimeString()}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Sidebar;