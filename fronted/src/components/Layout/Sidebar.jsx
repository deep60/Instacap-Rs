import React from 'react';
import { useLocation, Link } from 'react-router-dom';
import { 
  Home, 
  Network, 
  Shield, 
  Activity, 
  Globe,
  AlertTriangle
} from 'lucide-react';

const Sidebar = ({ isOpen }) => {
  const location = useLocation();
  
  const menuItems = [
    { path: '/', icon: Home, label: 'Dashboard', color: 'text-blue-600' },
    { path: '/packets', icon: Network, label: 'Packet Analysis', color: 'text-green-600' },
    { path: '/threats', icon: Shield, label: 'Threat Detection', color: 'text-red-600' },
    { path: '/performance', icon: Activity, label: 'Performance', color: 'text-purple-600' },
    { path: '/protocols', icon: Globe, label: 'Protocol Analysis', color: 'text-orange-600' },
  ];

  return (
    <aside className={`${isOpen ? 'w-64' : 'w-20'} transition-all duration-300 bg-white shadow-lg flex flex-col`}>
      <div className="p-6">
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 bg-blue-600 rounded-lg flex items-center justify-center">
            <Network className="w-6 h-6 text-white" />
          </div>
          {isOpen && (
            <div>
              <h1 className="text-xl font-bold text-gray-800">PacketAnalyzer</h1>
              <p className="text-sm text-gray-500">Network Monitor</p>
            </div>
          )}
        </div>
      </div>

      <nav className="flex-1 px-4">
        <ul className="space-y-2">
          {menuItems.map((item) => {
            const Icon = item.icon;
            const isActive = location.pathname === item.path;
            
            return (
              <li key={item.path}>
                <Link
                  to={item.path}
                  className={`flex items-center space-x-3 px-4 py-3 rounded-lg transition-colors ${
                    isActive
                      ? 'bg-blue-50 text-blue-700 border-r-4 border-blue-700'
                      : 'text-gray-600 hover:bg-gray-50'
                  }`}
                >
                  <Icon className={`w-5 h-5 ${isActive ? 'text-blue-700' : item.color}`} />
                  {isOpen && <span className="font-medium">{item.label}</span>}
                </Link>
              </li>
            );
          })}
        </ul>
      </nav>

      {isOpen && (
        <div className="p-4 border-t">
          <div className="flex items-center space-x-2 p-3 bg-red-50 rounded-lg">
            <AlertTriangle className="w-4 h-4 text-red-600" />
            <div className="text-sm">
              <p className="font-medium text-red-800">System Status</p>
              <p className="text-red-600">3 Active Threats</p>
            </div>
          </div>
        </div>
      )}
    </aside>
  );
};

export default Sidebar;