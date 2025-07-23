import React, { useState, useEffect } from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, AreaChart, Area } from 'recharts';
import { useRealTimeUpdates } from '../../hooks/useRealTimeUpdates';

const TrafficChart = ({ timeRange = '1h', chartType = 'line' }) => {
  const [data, setData] = useState([]);
  const [loading, setLoading] = useState(true);
  const { subscribe, unsubscribe } = useRealTimeUpdates();

  useEffect(() => {
    // Generate initial data
    generateInitialData();

    // Subscribe to real-time updates
    const handleTrafficUpdate = (newData) => {
      setData(prevData => {
        const updatedData = [...prevData, newData];
        // Keep only last 50 data points for performance
        return updatedData.slice(-50);
      });
    };

    subscribe('traffic-data', handleTrafficUpdate);

    return () => {
      unsubscribe('traffic-data', handleTrafficUpdate);
    };
  }, [timeRange, subscribe, unsubscribe]);

  const generateInitialData = () => {
    const now = new Date();
    const initialData = [];
    
    for (let i = 49; i >= 0; i--) {
      const time = new Date(now.getTime() - i * 60000); // 1 minute intervals
      initialData.push({
        timestamp: time.toLocaleTimeString('en-US', { 
          hour12: false,
          hour: '2-digit',
          minute: '2-digit'
        }),
        inbound: Math.floor(Math.random() * 1000) + 200,
        outbound: Math.floor(Math.random() * 800) + 150,
        total: 0
      });
    }
    
    // Calculate total
    initialData.forEach(item => {
      item.total = item.inbound + item.outbound;
    });
    
    setData(initialData);
    setLoading(false);
  };

  const formatBytes = (bytes) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const CustomTooltip = ({ active, payload, label }) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-gray-800 border border-gray-600 rounded-lg p-3 shadow-lg">
          <p className="text-gray-300 text-sm">{`Time: ${label}`}</p>
          {payload.map((entry, index) => (
            <p key={index} className="text-sm" style={{ color: entry.color }}>
              {`${entry.dataKey.charAt(0).toUpperCase() + entry.dataKey.slice(1)}: ${formatBytes(entry.value * 1024)}/s`}
            </p>
          ))}
        </div>
      );
    }
    return null;
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64 bg-gray-900 rounded-lg">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
        <span className="ml-3 text-gray-300">Loading traffic data...</span>
      </div>
    );
  }

  const ChartComponent = chartType === 'area' ? AreaChart : LineChart;
  const DataComponent = chartType === 'area' ? Area : Line;

  return (
    <div className="bg-gray-900 rounded-lg p-6 border border-gray-700">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-xl font-semibold text-white">Network Traffic</h3>
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2">
            <div className="w-3 h-3 bg-blue-500 rounded-full"></div>
            <span className="text-sm text-gray-300">Inbound</span>
          </div>
          <div className="flex items-center space-x-2">
            <div className="w-3 h-3 bg-green-500 rounded-full"></div>
            <span className="text-sm text-gray-300">Outbound</span>
          </div>
          <div className="flex items-center space-x-2">
            <div className="w-3 h-3 bg-purple-500 rounded-full"></div>
            <span className="text-sm text-gray-300">Total</span>
          </div>
        </div>
      </div>
      
      <ResponsiveContainer width="100%" height={300}>
        <ChartComponent data={data} margin={{ top: 5, right: 30, left: 20, bottom: 5 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
          <XAxis 
            dataKey="timestamp" 
            stroke="#9CA3AF"
            fontSize={12}
            interval="preserveStartEnd"
          />
          <YAxis 
            stroke="#9CA3AF"
            fontSize={12}
            tickFormatter={(value) => formatBytes(value * 1024)}
          />
          <Tooltip content={<CustomTooltip />} />
          <Legend />
          
          {chartType === 'area' ? (
            <>
              <Area
                type="monotone"
                dataKey="total"
                stackId="1"
                stroke="#8B5CF6"
                fill="#8B5CF6"
                fillOpacity={0.3}
                name="Total"
              />
              <Area
                type="monotone"
                dataKey="inbound"
                stackId="2"
                stroke="#3B82F6"
                fill="#3B82F6"
                fillOpacity={0.3}
                name="Inbound"
              />
              <Area
                type="monotone"
                dataKey="outbound"
                stackId="3"
                stroke="#10B981"
                fill="#10B981"
                fillOpacity={0.3}
                name="Outbound"
              />
            </>
          ) : (
            <>
              <Line
                type="monotone"
                dataKey="inbound"
                stroke="#3B82F6"
                strokeWidth={2}
                dot={false}
                name="Inbound"
              />
              <Line
                type="monotone"
                dataKey="outbound"
                stroke="#10B981"
                strokeWidth={2}
                dot={false}
                name="Outbound"
              />
              <Line
                type="monotone"
                dataKey="total"
                stroke="#8B5CF6"
                strokeWidth={2}
                dot={false}
                name="Total"
              />
            </>
          )}
        </ChartComponent>
      </ResponsiveContainer>
      
      <div className="mt-4 grid grid-cols-3 gap-4 text-sm">
        <div className="text-center">
          <div className="text-blue-400 font-medium">
            {data.length > 0 ? formatBytes(data[data.length - 1]?.inbound * 1024) + '/s' : '0 B/s'}
          </div>
          <div className="text-gray-400">Current Inbound</div>
        </div>
        <div className="text-center">
          <div className="text-green-400 font-medium">
            {data.length > 0 ? formatBytes(data[data.length - 1]?.outbound * 1024) + '/s' : '0 B/s'}
          </div>
          <div className="text-gray-400">Current Outbound</div>
        </div>
        <div className="text-center">
          <div className="text-purple-400 font-medium">
            {data.length > 0 ? formatBytes(data[data.length - 1]?.total * 1024) + '/s' : '0 B/s'}
          </div>
          <div className="text-gray-400">Current Total</div>
        </div>
      </div>
    </div>
  );
};

export default TrafficChart;