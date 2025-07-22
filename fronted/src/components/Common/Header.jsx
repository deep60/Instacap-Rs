import React from 'react';
import { 
  Menu, 
  Search, 
  Bell, 
  Settings, 
  User,
  Wifi,
  WifiOff 
} from 'lucide-react';

const Header = ({ onMenuClick }) => {
  const [isConnected, setIsConnected] = React.useState(true);
  const [notifications, setNotifications] = React.useState(5);

  return (
    <header className="bg-white shadow-sm border-b border-gray-200 px-6 py-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-4">
          <button
            onClick={onMenuClick}
            className="p-2 rounded-lg hover:bg-gray-100 transition-colors"
          >
            <Menu className="w-5 h-5 text-gray-600" />
          </button>
          
          <div className="relative">
            <Search className="w-5 h-5 text-gray-400 absolute left-3 top-1/2 transform -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search packets, IPs, protocols..."
              className="pl-10 pr-4 py-2 w-96 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
          </div>
        </div>

        <div className="flex items-center space-x-4">
          {/* Connection Status */}
          <div className="flex items-center space-x-2 px-3 py-1 rounded-full bg-green-100">
            {isConnected ? (
              <>
                <Wifi className="w-4 h-4 text-green-600" />
                <span className="text-sm text-green-700 font-medium">Connected</span>
              </>
            ) : (
              <>
                <WifiOff className="w-4 h-4 text-red-600" />
                <span className="text-sm text-red-700 font-medium">Disconnected</span>
              </>
            )}
          </div>

          {/* Live Stats */}
          <div className="flex items-center space-x-4 px-4 py-2 bg-gray-50 rounded-lg">
            <div className="text-center">
              <p className="text-xs text-gray-500">Packets/sec</p>
              <p className="text-sm font-bold text-gray-800">1,247</p>
            </div>
            <div className="text-center">
              <p className="text-xs text-gray-500">Bandwidth</p>
              <p className="text-sm font-bold text-gray-800">45.2 MB/s</p>
            </div>
          </div>

          {/* Notifications */}
          <button className="relative p-2 rounded-lg hover:bg-gray-100 transition-colors">
            <Bell className="w-5 h-5 text-gray-600" />
            {notifications > 0 && (
              <span className="absolute -top-1 -right-1 w-5 h-5 bg-red-500 text-white text-xs rounded-full flex items-center justify-center">
                {notifications}
              </span>
            )}
          </button>

          {/* Settings */}
          <button className="p-2 rounded-lg hover:bg-gray-100 transition-colors">
            <Settings className="w-5 h-5 text-gray-600" />
          </button>

          {/* User Profile */}
          <button className="flex items-center space-x-2 p-2 rounded-lg hover:bg-gray-100 transition-colors">
            <div className="w-8 h-8 bg-blue-600 rounded-full flex items-center justify-center">
              <User className="w-4 h-4 text-white" />
            </div>
            <span className="text-sm font-medium text-gray-700">Admin</span>
          </button>
        </div>
      </div>
    </header>
  );
};

export default Header;