import React from 'react';
import { Activity, AlertTriangle, Shield, BarChart3 } from 'lucide-react';
import StatCard from '../Common/StatCard';

const StatsGrid = ({ packets, threats }) => {
  const totalPackets = packets.length;
  const suspiciousPackets = packets.filter(p => p.status === 'suspicious').length;
  const activeThreats = threats.filter(t => t.severity === 'critical' || t.severity === 'high').length;
  const avgPacketSize = Math.round(packets.reduce((sum, p) => sum + p.size, 0) / packets.length) || 0;

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
      <StatCard
        title="Total Packets"
        value={totalPackets.toLocaleString()}
        icon={Activity}
        trend={12}
        color="blue"
      />
      <StatCard
        title="Suspicious Activity"
        value={suspiciousPackets}
        icon={AlertTriangle}
        trend={-5}
        color="yellow"
      />
      <StatCard
        title="Active Threats"
        value={activeThreats}
        icon={Shield}
        trend={0}
        color="red"
      />
      <StatCard
        title="Avg Packet Size"
        value={`${avgPacketSize} bytes`}
        icon={BarChart3}
        trend={3}
        color="green"
      />
    </div>
  );
};

export default StatsGrid;


// import React from 'react';
// import StatCard from '../Common/StatCard';

// const StatsGrid = ({ stats }) => {
//   return (
//     <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
//       {stats.map((stat, index) => (
//         <StatCard key={index} {...stat} />
//       ))}
//     </div>
//   );
// };

// export default StatsGrid;