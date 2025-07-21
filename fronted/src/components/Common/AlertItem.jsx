import React from 'react';

const AlertItem = ({ threat }) => {
  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'critical': return 'bg-red-500';
      case 'high': return 'bg-orange-500';
      case 'medium': return 'bg-yellow-500';
      default: return 'bg-slate-500';
    }
  };

  return (
    <div className="flex items-center space-x-3 p-3 bg-slate-50 rounded-lg hover:bg-slate-100 transition-colors">
      <div className={`w-3 h-3 rounded-full ${getSeverityColor(threat.severity)}`}></div>
      <div className="flex-1">
        <div className="flex items-center justify-between">
          <p className="font-medium text-slate-800">{threat.type}</p>
          <span className="text-xs text-slate-500">
            {new Date(threat.timestamp).toLocaleTimeString()}
          </span>
        </div>
        <p className="text-sm text-slate-600">{threat.description}</p>
        <p className="text-xs text-slate-500">Source: {threat.source}</p>
      </div>
    </div>
  );
};

export default AlertItem;