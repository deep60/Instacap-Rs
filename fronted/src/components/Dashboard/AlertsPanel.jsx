import React from 'react';
import AlertItem from '../Common/AlertItem';

const AlertsPanel = ({ threats }) => {
  const recentThreats = threats.slice(0, 5);

  return (
    <div className="bg-white rounded-lg shadow-lg p-6">
      <h3 className="text-lg font-semibold text-slate-800 mb-4">Recent Alerts</h3>
      <div className="space-y-3">
        {recentThreats.map(threat => (
          <AlertItem key={threat.id} threat={threat} />
        ))}
        {recentThreats.length === 0 && (
          <div className="text-center py-8 text-slate-500">
            <p>No recent alerts</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default AlertsPanel;