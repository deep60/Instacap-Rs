import React, { useState, useEffect } from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';

const TrafficChart = () => {
  const [timeRange, setTimeRange] = useState('1h');
  const [data, setData] = useState([]);

  // Generate sample data
  useEffect(() => {
    const generateData = () => {
      const points = timeRange === '1h' ? 12 : timeRange === '6h' ? 24 : 48;
      const newData = [];
      
      for (let i = 0; i < points; i++) {
        const time = new Date();
        time.setMinutes(time.getMinutes() - (points - i) * (timeRange === '1h' ? 5 : timeRange === '6h' ? 15 : 30));
        
        newData.push({
          time: time.toLocaleTimeString('en-US', { 
            hour: '2-digit', 
            minute: '2-digit' 
          }),
          packets: Math.floor(Math.random() * 1000) + 500,
          bytes: Math.floor(Math.random() * 50000) + 20000,
          threats: Math.floor(Math.random() * 5),
        });
      }
      
      setData(newData);
    };

    generateData();
    const interval = setInterval(generateData, 30000); // Update every 30 seconds
    
    return () => clearInterval(interval);
  }, [timeRange]);

  const timeRanges = [
    { value: '1h', label: '1 Hour' },
    { value: '6h', label: '6 Hours' },
    { value: '24h', label: '24 Hours' }
  ];

  return (
    <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
      <div className="flex justify-between items-center mb-6">
        <div>
          <h3 className="text-lg font-semibold text-gray-900">Network Traffic</h3>
          <p className="text-gray-600">Real-time traffic monitoring</p>
        </div>
        
        <div className="flex space-x-2">
          {timeRanges.map((range) => (
            <button
              key={range.value}
              onClick={() => setTimeRange(range.value)}
              className={`px-3 py-1 rounded-lg text-sm font-medium transition-colors ${
                timeRange === range.value
                  ? 'bg-blue-600 text-white'
                  : 'text-gray-600 hover:bg-gray-100'
              }`}
            >
              {range.label}
            </button>
          ))}
        </div>
      </div>

      <div className="h-80">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={data} margin={{ top: 5, right: 30, left: 20, bottom: 5 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
            <XAxis 
              dataKey="time" 
              stroke="#6b7280"
              fontSize={12}
            />
            <YAxis 
              yAxisId="left"
              stroke="#6b7280"
              fontSize={12}
            />
            <YAxis 
              yAxisId="right"
              orientation="right"
              stroke="#6b7280"
              fontSize={12}
            />
            <Tooltip 
              contentStyle={{
                backgroundColor: 'white',
                border: '1px solid #e5e7eb',
                borderRadius: '8px',
                boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)'
              }}
            />
            <Legend />
            <Line
              yAxisId="left"
              type="monotone"
              dataKey="packets"
              stroke="#3b82f6"
              strokeWidth={2}
              dot={false}
              name="Packets/sec"
            />
            <Line
              yAxisId="right"
              type="monotone"
              dataKey="bytes"
              stroke="#10b981"
              strokeWidth={2}
              dot={false}
              name="Bytes/sec"
            />
            <Line
              yAxisId="left"
              type="monotone"
              dataKey="threats"
              stroke="#ef4444"
              strokeWidth={2}
              dot={false}
              name="Threats"
            />
          </LineChart>
        </ResponsiveContainer>
      </div>

      <div className="flex justify-around mt-6 pt-6 border-t border-gray-200">
        <div className="text-center">
          <p className="text-2xl font-bold text-blue-600">
            {data.length > 0 ? data[data.length - 1]?.packets : '0'}
          </p>
          <p className="text-sm text-gray-600">Current Packets/sec</p>
        </div>
        <div className="text-center">
          <p className="text-2xl font-bold text-green-600">
            {data.length > 0 ? Math.round(data[data.length - 1]?.bytes / 1024) : '0'}KB/s
          </p>
          <p className="text-sm text-gray-600">Current Bandwidth</p>
        </div>
        <div className="text-center">
          <p className="text-2xl font-bold text-red-600">
            {data.length > 0 ? data[data.length - 1]?.threats : '0'}
          </p>
          <p className="text-sm text-gray-600">Active Threats</p>