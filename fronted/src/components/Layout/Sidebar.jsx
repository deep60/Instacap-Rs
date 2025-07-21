import React from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { 
  BarChart3, 
  Activity, 
  Shield, 
  TrendingUp, 
  Network 
} from 'lucide-react';

const Sidebar = () => {
  const location = useLocation();
  const navigate = useNavigate();

  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: BarChart3, path: '/dashboard' },
    { id: 'packets', label: 'Packet Analysis', icon: Activity, path: '/packets' },
    { id: 'threats', label: 'Threat Detection', icon: Shield, path: '/threats' },
    { id: 'performance', label: 'Performance', icon: TrendingUp, path: '/performance' },
    { id: 'protocols', label: 'Protocol Analysis', icon: Network, path: '/protocols' }
  ];

  const isActive = (path) => {
    return location.pathname === path || (location.pathname === '/' && path === '/dashboard');
  };

  return (
    <nav className="w-64 bg-slate-900 text-white h-full p-4">
      <div className="space-y-2">
        {navItems.map(item => {
          const Icon = item.icon;
          return (
            <button
              key={item.id}
              onClick={() => navigate(item.path)}
              className={`w-full flex items-center space-x-3 p-3 rounded-lg transition-colors ${
                isActive(item.path)
                  ? 'bg-blue-600 text-white' 
                  : 'text-slate-300 hover:bg-slate-800'
              }`}
            >
              <Icon className="w-5 h-5" />
              <span>{item.label}</span>
            </button>
          );
        })}
      </div>
    </nav>
  );
};

export default Sidebar;