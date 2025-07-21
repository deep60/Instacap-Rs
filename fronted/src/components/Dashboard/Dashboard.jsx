import React from 'react';
import { RefreshCw } from 'lucide-react';
import StatsGrid from './StatsGrid';
import TrafficChart from './TrafficChart';
import AlertsPanel from './AlertsPanel';
import { usePacketData } from '../../hooks/usePacketData';
import { useThreatDetection } from '../../hooks/useThreatDetection';

const Dashboard = () => {
  const { packets, loading: packetsLoading } = usePacketData();
  const { threats, loading: threatsLoading } = useThreatDetection();

  const handleRefresh = () => {
    window.location.reload();
  };

  if (packetsLoading || threatsLoading) {
    return (
      <div className="p-6 flex items-center justify-center h-full">
        <div className="text-center">
          <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-blue-600"></div>
          <p className="mt-4 text-slate-600">Loading dashboard...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-3xl font-bold text-slate-800">Network Dashboard</h2>
        <button 
          onClick={handleRefresh}
          className="flex items-center space-x-2 bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors"
        >
          <RefreshCw className="w-4 h-4" />
          <span>Refresh</span>
        </button>
      </div>

      <StatsGrid packets={packets} threats={threats} />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <TrafficChart packets={packets} />
        <AlertsPanel threats={threats} />
      </div>
    </div>
  );
};

export default Dashboard;