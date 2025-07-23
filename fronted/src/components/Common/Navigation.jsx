import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { 
  Home, 
  Network, 
  Shield, 
  Activity, 
  Globe,
  ChevronRight
} from 'lucide-react';

const Navigation = ({ className = '' }) => {
  const location = useLocation();
  
  const getPageName = (pathname) => {
    const routes = {
      '/': 'Dashboard',
      '/dashboard': 'Dashboard',
      '/packets': 'Packet Analysis',
      '/threats': 'Threat Detection',
      '/performance': 'Performance Metrics',
      '/protocols': 'Protocol Analysis'
    };
    return routes[pathname] || 'Unknown';
  };

  const getIcon = (pathname) => {
    const icons = {
      '/': Home,
      '/dashboard': Home,
      '/packets': Network,
      '/threats': Shield,
      '/performance': Activity,
      '/protocols': Globe
    };
    return icons[pathname] || Home;
  };

  const Icon = getIcon(location.pathname);

  return (
    <nav className={`flex items-center space-x-2 text-sm text-gray-500 ${className}`}>
      <Link 
        to="/" 
        className="flex items-center space-x-1 hover:text-gray-700 transition-colors"
      >
        <Home className="w-4 h-4" />
        <span>Home</span>
      </Link>
      
      {location.pathname !== '/' && (
        <>
          <ChevronRight className="w-4 h-4" />
          <div className="flex items-center space-x-1 text-gray-700 font-medium">
            <Icon className="w-4 h-4" />
            <span>{getPageName(location.pathname)}</span>
          </div>
        </>
      )}
    </nav>
  );
};

export default Navigation;