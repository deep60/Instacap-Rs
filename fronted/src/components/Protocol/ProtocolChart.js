import React, { useState, useEffect, useMemo } from 'react';
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  Area,
  AreaChart
} from 'recharts';
import { Activity, Globe, Shield, TrendingUp, Wifi, Database } from 'lucide-react';

const ProtocolChart = ({ 
  protocolData = [],
  timeSeriesData = [],
  chartType = 'pie',
  showLegend = true,
  height = 400,
  refreshInterval = 5000,
  title = "Protocol Distribution"
}) => {
  const [selectedProtocol, setSelectedProtocol] = useState(null);
  const [animationKey, setAnimationKey] = useState(0);
  const [activeChart, setActiveChart] = useState(chartType);

  // Protocol color mapping for consistent visualization
  const protocolColors = {
    'HTTP': '#3B82F6',    // Blue
    'HTTPS': '#10B981',   // Green
    'TCP': '#8B5CF6',     // Purple
    'UDP': '#F59E0B',     // Amber
    'DNS': '#EF4444',     // Red
    'FTP': '#06B6D4',     // Cyan
    'SSH': '#84CC16',     // Lime
    'SMTP': '#F97316',    // Orange
    'ICMP': '#EC4899',    // Pink
    'ARP': '#6366F1',     // Indigo
    'DHCP': '#14B8A6',    // Teal
    'SNMP': '#A855F7',    // Violet
    'Telnet': '#DC2626',  // Red-600
    'POP3': '#059669',    // Emerald-600
    'IMAP': '#7C3AED',    // Violet-600
    'Other': '#6B7280'    // Gray
  };

  // Default protocol data if none provided
  const defaultProtocolData = [
    { name: 'HTTP', value: 35, packets: 1250, bytes: 2048576 },
    { name: 'HTTPS', value: 28, packets: 980, bytes: 1638400 },
    { name: 'TCP', value: 15, packets: 525, bytes: 851968 },
    { name: 'UDP', value: 8, packets: 280, bytes: 458752 },
    { name: 'DNS', value: 6, packets: 210, bytes: 344064 },
    { name: 'SSH', value: 4, packets: 140, bytes: 229376 },
    { name: 'FTP', value: 2, packets: 70, bytes: 114688 },
    { name: 'Other', value: 2, packets: 70, bytes: 114688 }
  ];

  // Default time series data
  const defaultTimeSeriesData = [
    { time: '00:00', HTTP: 120, HTTPS: 95, TCP: 45, UDP: 25, DNS: 18, SSH: 12 },
    { time: '01:00', HTTP: 98, HTTPS: 87, TCP: 52, UDP: 28, DNS: 22, SSH: 15 },
    { time: '02:00', HTTP: 145, HTTPS: 112, TCP: 38, UDP: 31, DNS: 19, SSH: 11 },
    { time: '03:00', HTTP: 132, HTTPS: 98, TCP: 41, UDP: 24, DNS: 16, SSH: 9 },
    { time: '04:00', HTTP: 167, HTTPS: 134, TCP: 55, UDP: 35, DNS: 24, SSH: 18 },
    { time: '05:00', HTTP: 189, HTTPS: 145, TCP: 48, UDP: 29, DNS: 21, SSH: 14 }
  ];

  const currentProtocolData = protocolData.length > 0 ? protocolData : defaultProtocolData;
  const currentTimeSeriesData = timeSeriesData.length > 0 ? timeSeriesData : defaultTimeSeriesData;

  // Refresh animation periodically
  useEffect(() => {
    const interval = setInterval(() => {
      setAnimationKey(prev => prev + 1);
    }, refreshInterval);

    return () => clearInterval(interval);
  }, [refreshInterval]);

  // Calculate total traffic metrics
  const totalMetrics = useMemo(() => {
    const total = currentProtocolData.reduce((acc, item) => ({
      packets: acc.packets + (item.packets || 0),
      bytes: acc.bytes + (item.bytes || 0),
      protocols: acc.protocols + 1
    }), { packets: 0, bytes: 0, protocols: 0 });

    return {
      ...total,
      mbytes: (total.bytes / (1024 * 1024)).toFixed(2)
    };
  }, [currentProtocolData]);

  // Custom tooltip for charts
  const CustomTooltip = ({ active, payload, label }) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-white p-3 border border-gray-200 rounded-lg shadow-lg">
          <p className="font-semibold text-gray-800">{label}</p>
          {payload.map((entry, index) => (
            <p key={index} style={{ color: entry.color }} className="text-sm">
              {`${entry.dataKey}: ${entry.value}${entry.dataKey === 'value' ? '%' : ' packets'}`}
            </p>
          ))}
        </div>
      );
    }
    return null;
  };

  // Pie chart with protocol distribution
  const renderPieChart = () => (
    <ResponsiveContainer width="100%" height={height}>
      <PieChart key={animationKey}>
        <Pie
          data={currentProtocolData}
          cx="50%"
          cy="50%"
          labelLine={false}
          label={({ name, value }) => `${name}: ${value}%`}
          outerRadius={120}
          fill="#8884d8"
          dataKey="value"
          animationBegin={0}
          animationDuration={800}
        >
          {currentProtocolData.map((entry, index) => (
            <Cell 
              key={`cell-${index}`} 
              fill={protocolColors[entry.name] || protocolColors['Other']}
              onClick={() => setSelectedProtocol(entry)}
              style={{ cursor: 'pointer' }}
            />
          ))}
        </Pie>
        {showLegend && <Legend />}
        <Tooltip content={<CustomTooltip />} />
      </PieChart>
    </ResponsiveContainer>
  );

  // Bar chart for protocol comparison
  const renderBarChart = () => (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart key={animationKey} data={currentProtocolData} margin={{ top: 20, right: 30, left: 20, bottom: 5 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
        <XAxis dataKey="name" tick={{ fontSize: 12 }} />
        <YAxis tick={{ fontSize: 12 }} />
        <Tooltip content={<CustomTooltip />} />
        {showLegend && <Legend />}
        <Bar 
          dataKey="packets" 
          fill="#3B82F6"
          animationBegin={0}
          animationDuration={800}
          radius={[4, 4, 0, 0]}
        />
      </BarChart>
    </ResponsiveContainer>
  );

  // Time series line chart
  const renderTimeSeriesChart = () => (
    <ResponsiveContainer width="100%" height={height}>
      <LineChart key={animationKey} data={currentTimeSeriesData} margin={{ top: 5, right: 30, left: 20, bottom: 5 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
        <XAxis dataKey="time" tick={{ fontSize: 12 }} />
        <YAxis tick={{ fontSize: 12 }} />
        <Tooltip content={<CustomTooltip />} />
        {showLegend && <Legend />}
        <Line type="monotone" dataKey="HTTP" stroke="#3B82F6" strokeWidth={2} dot={{ r: 4 }} />
        <Line type="monotone" dataKey="HTTPS" stroke="#10B981" strokeWidth={2} dot={{ r: 4 }} />
        <Line type="monotone" dataKey="TCP" stroke="#8B5CF6" strokeWidth={2} dot={{ r: 4 }} />
        <Line type="monotone" dataKey="UDP" stroke="#F59E0B" strokeWidth={2} dot={{ r: 4 }} />
        <Line type="monotone" dataKey="DNS" stroke="#EF4444" strokeWidth={2} dot={{ r: 4 }} />
        <Line type="monotone" dataKey="SSH" stroke="#84CC16" strokeWidth={2} dot={{ r: 4 }} />
      </LineChart>
    </ResponsiveContainer>
  );

  // Area chart for stacked protocol view
  const renderAreaChart = () => (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart key={animationKey} data={currentTimeSeriesData} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
        <XAxis dataKey="time" tick={{ fontSize: 12 }} />
        <YAxis tick={{ fontSize: 12 }} />
        <Tooltip content={<CustomTooltip />} />
        {showLegend && <Legend />}
        <Area type="monotone" dataKey="HTTP" stackId="1" stroke="#3B82F6" fill="#3B82F6" fillOpacity={0.6} />
        <Area type="monotone" dataKey="HTTPS" stackId="1" stroke="#10B981" fill="#10B981" fillOpacity={0.6} />
        <Area type="monotone" dataKey="TCP" stackId="1" stroke="#8B5CF6" fill="#8B5CF6" fillOpacity={0.6} />
        <Area type="monotone" dataKey="UDP" stackId="1" stroke="#F59E0B" fill="#F59E0B" fillOpacity={0.6} />
        <Area type="monotone" dataKey="DNS" stackId="1" stroke="#EF4444" fill="#EF4444" fillOpacity={0.6} />
        <Area type="monotone" dataKey="SSH" stackId="1" stroke="#84CC16" fill="#84CC16" fillOpacity={0.6} />
      </AreaChart>
    </ResponsiveContainer>
  );

  const renderChart = () => {
    switch (activeChart) {
      case 'pie':
        return renderPieChart();
      case 'bar':
        return renderBarChart();
      case 'line':
        return renderTimeSeriesChart();
      case 'area':
        return renderAreaChart();
      default:
        return renderPieChart();
    }
  };

  return (
    <div className="bg-white rounded-lg shadow-lg p-6">
      {/* Header with metrics and controls */}
      <div className="flex flex-col lg:flex-row justify-between items-start lg:items-center mb-6">
        <div className="flex items-center gap-3 mb-4 lg:mb-0">
          <div className="p-2 bg-blue-100 rounded-lg">
            <Globe className="w-6 h-6 text-blue-600" />
          </div>
          <div>
            <h3 className="text-xl font-bold text-gray-800">{title}</h3>
            <p className="text-sm text-gray-600">Real-time protocol analysis</p>
          </div>
        </div>

        {/* Chart type selector */}
        <div className="flex bg-gray-100 rounded-lg p-1">
          <button
            onClick={() => setActiveChart('pie')}
            className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
              activeChart === 'pie' 
                ? 'bg-white text-blue-600 shadow-sm' 
                : 'text-gray-600 hover:text-gray-800'
            }`}
          >
            Distribution
          </button>
          <button
            onClick={() => setActiveChart('bar')}
            className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
              activeChart === 'bar' 
                ? 'bg-white text-blue-600 shadow-sm' 
                : 'text-gray-600 hover:text-gray-800'
            }`}
          >
            Comparison
          </button>
          <button
            onClick={() => setActiveChart('line')}
            className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
              activeChart === 'line' 
                ? 'bg-white text-blue-600 shadow-sm' 
                : 'text-gray-600 hover:text-gray-800'
            }`}
          >
            Timeline
          </button>
          <button
            onClick={() => setActiveChart('area')}
            className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
              activeChart === 'area' 
                ? 'bg-white text-blue-600 shadow-sm' 
                : 'text-gray-600 hover:text-gray-800'
            }`}
          >
            Stacked
          </button>
        </div>
      </div>

      {/* Metrics cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <div className="bg-gradient-to-r from-blue-50 to-blue-100 p-4 rounded-lg">
          <div className="flex items-center gap-3">
            <Activity className="w-8 h-8 text-blue-600" />
            <div>
              <p className="text-sm text-blue-600 font-medium">Total Packets</p>
              <p className="text-2xl font-bold text-blue-800">{totalMetrics.packets.toLocaleString()}</p>
            </div>
          </div>
        </div>
        
        <div className="bg-gradient-to-r from-green-50 to-green-100 p-4 rounded-lg">
          <div className="flex items-center gap-3">
            <Database className="w-8 h-8 text-green-600" />
            <div>
              <p className="text-sm text-green-600 font-medium">Data Volume</p>
              <p className="text-2xl font-bold text-green-800">{totalMetrics.mbytes} MB</p>
            </div>
          </div>
        </div>
        
        <div className="bg-gradient-to-r from-purple-50 to-purple-100 p-4 rounded-lg">
          <div className="flex items-center gap-3">
            <Wifi className="w-8 h-8 text-purple-600" />
            <div>
              <p className="text-sm text-purple-600 font-medium">Active Protocols</p>
              <p className="text-2xl font-bold text-purple-800">{totalMetrics.protocols}</p>
            </div>
          </div>
        </div>
        
        <div className="bg-gradient-to-r from-orange-50 to-orange-100 p-4 rounded-lg">
          <div className="flex items-center gap-3">
            <TrendingUp className="w-8 h-8 text-orange-600" />
            <div>
              <p className="text-sm text-orange-600 font-medium">Avg Rate</p>
              <p className="text-2xl font-bold text-orange-800">{Math.round(totalMetrics.packets / 6)}/min</p>
            </div>
          </div>
        </div>
      </div>

      {/* Chart container */}
      <div className="bg-gray-50 rounded-lg p-4">
        {renderChart()}
      </div>

      {/* Selected protocol details */}
      {selectedProtocol && (
        <div className="mt-6 p-4 bg-blue-50 border border-blue-200 rounded-lg">
          <div className="flex items-center justify-between">
            <h4 className="text-lg font-semibold text-blue-800">
              {selectedProtocol.name} Protocol Details
            </h4>
            <button
              onClick={() => setSelectedProtocol(null)}
              className="text-blue-600 hover:text-blue-800 font-medium"
            >
              ✕
            </button>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-3">
            <div>
              <p className="text-sm text-blue-600">Percentage</p>
              <p className="text-xl font-bold text-blue-800">{selectedProtocol.value}%</p>
            </div>
            <div>
              <p className="text-sm text-blue-600">Packets</p>
              <p className="text-xl font-bold text-blue-800">{selectedProtocol.packets?.toLocaleString()}</p>
            </div>
            <div>
              <p className="text-sm text-blue-600">Data Size</p>
              <p className="text-xl font-bold text-blue-800">
                {((selectedProtocol.bytes || 0) / (1024 * 1024)).toFixed(2)} MB
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Status indicator */}
      <div className="flex items-center justify-between mt-4 text-sm text-gray-500">
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
          <span>Live data • Updated every {refreshInterval / 1000}s</span>
        </div>
        <div className="flex items-center gap-4">
          <span>Last update: {new Date().toLocaleTimeString()}</span>
        </div>
      </div>
    </div>
  );
};

export default ProtocolChart;