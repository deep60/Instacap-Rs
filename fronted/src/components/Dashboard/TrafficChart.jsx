import React from 'react';

const TrafficChart = ({ packets }) => {
  // Calculate protocol distribution
  const protocolStats = packets.reduce((acc, packet) => {
    acc[packet.protocol] = (acc[packet.protocol] || 0) + 1;
    return acc;
  }, {});

  const totalPackets = packets.length;
  const trafficData = [
    {
      name: 'HTTP',
      count: protocolStats['HTTP'] || 0,
      percentage: totalPackets > 0 ? ((protocolStats['HTTP'] || 0) / totalPackets * 100).toFixed(1) : 0,
      color: 'bg-blue-500'
    },
    {
      name: 'HTTPS',
      count: protocolStats['HTTPS'] || 0,
      percentage: totalPackets > 0 ? ((protocolStats['HTTPS'] || 0) / totalPackets * 100).toFixed(1) : 0,
      color: 'bg-green-500'
    },
    {
      name: 'DNS',
      count: protocolStats['DNS'] || 0,
      percentage: totalPackets > 0 ? ((protocolStats['DNS'] || 0) / totalPackets * 100).toFixed(1) : 0,
      color: 'bg-purple-500'
    },
    {
      name: 'SSH',
      count: protocolStats['SSH'] || 0,
      percentage: totalPackets > 0 ? ((protocolStats['SSH'] || 0) / totalPackets * 100).toFixed(1) : 0,
      color: 'bg-yellow-500'
    },
    {
      name: 'Other',
      count: Object.entries(protocolStats).reduce((acc, [protocol, count]) => {
        return !['HTTP', 'HTTPS', 'DNS', 'SSH'].includes(protocol) ? acc + count : acc;
      }, 0),
      percentage: totalPackets > 0 ? (Object.entries(protocolStats).reduce((acc, [protocol, count]) => {
        return !['HTTP', 'HTTPS', 'DNS', 'SSH'].includes(protocol) ? acc + count : acc;
      }, 0) / totalPackets * 100).toFixed(1) : 0,
      color: 'bg-slate-500'
    }
  ].filter(item => item.count > 0);

  return (
    <div className="bg-white rounded-lg shadow-lg p-6">
      <h3 className="text-lg font-semibold text-slate-800 mb-4">Traffic Overview</h3>
      <div className="space-y-4">
        {trafficData.map(item => (
          <div key={item.name} className="flex items-center justify-between">
            <span className="text-slate-600 font-medium">{item.name}</span>
            <div className="flex items-center space-x-2">
              <div className="w-24 bg-slate-200 rounded-full h-2">
                <div 
                  className={`${item.color} h-2 rounded-full transition-all duration-500`}
                  style={{width: `${item.percentage}%`}}
                ></div>
              </div>
              <span className="text-sm text-slate-600 w-12">{item.percentage}%</span>
              <span className="text-sm text-slate-500 w-8">{item.count}</span>
            </div>
          </div>
        ))}
      </div>
      {trafficData.length === 0 && (
        <div className="text-center py-8 text-slate-500">
          <p>No traffic data available</p>
        </div>
      )}
    </div>
  );
};

export default TrafficChart;