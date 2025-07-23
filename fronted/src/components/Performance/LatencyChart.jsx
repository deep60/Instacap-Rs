import React, { useState, useEffect, useRef, useMemo } from 'react';
import {
  LineChart,
  Line,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  ScatterChart,
  Scatter,
  ReferenceLine,
  ComposedChart,
  Bar
} from 'recharts';
import { 
  Clock, 
  Zap, 
  TrendingUp, 
  TrendingDown, 
  AlertTriangle,
  CheckCircle,
  XCircle,
  Activity,
  Maximize2,
  Minimize2,
  RefreshCw,
  Settings,
  Target,
  BarChart3
} from 'lucide-react';
import analyticsService from '../../services/analyticsService';
import { useRealTimeUpdates } from '../../hooks/useRealTimeUpdates';
import { formatLatency, formatNumber } from '../../utils/formatters';
import { TIME_RANGES, CHART_COLORS, LATENCY_THRESHOLDS } from '../../utils/constants';
import LoadingSpinner from '../Common/LoadingSpinner';

const LatencyChart = ({ 
  timeRange = TIME_RANGES.LAST_HOUR,
  showJitter = true,
  showPacketLoss = false,
  height = 400,
  thresholds = LATENCY_THRESHOLDS,
  onAlertThreshold,
  className = ''
}) => {
  const [performanceData, setPerformanceData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [isExpanded, setIsExpanded] = useState(false);
  const [chartType, setChartType] = useState('line'); // 'line', 'area', 'scatter', 'composed'
  const [showSettings, setShowSettings] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [selectedMetrics, setSelectedMetrics] = useState({
    latency: true,
    jitter: showJitter,
    packetLoss: showPacketLoss
  });
  const [alertsEnabled, setAlertsEnabled] = useState(true);
  
  const chartRef = useRef(null);
  const updateInterval = useRef(null);
  const previousData = useRef(null);

  // Real-time updates hook
  const { isConnected, lastUpdate } = useRealTimeUpdates(['performance', 'latency', 'network_health']);

  // Fetch performance data
  const fetchPerformanceData = async () => {
    try {
      setLoading(true);
      const data = await analyticsService.getPerformanceMetrics(timeRange, 'all');
      setPerformanceData(data);
      
      // Check for threshold alerts
      if (alertsEnabled && data.latency.current > thresholds.HIGH && onAlertThreshold) {
        onAlertThreshold({
          type: 'latency',
          value: data.latency.current,
          threshold: thresholds.HIGH,
          severity: 'high',
          timestamp: new Date()
        });
      }
      
      previousData.current = data;
      setError(null);
    } catch (err) {
      setError(err.message);
      console.error('Error fetching performance data:', err);
    } finally {
      setLoading(false);
    }
  };

  // Initial load
  useEffect(() => {
    fetchPerformanceData();
  }, [timeRange]);

  // Auto-refresh mechanism
  useEffect(() => {
    if (autoRefresh) {
      updateInterval.current = setInterval(fetchPerformanceData, 15000); // 15 seconds
      return () => {
        if (updateInterval.current) {
          clearInterval(updateInterval.current);
        }
      };
    }
  }, [autoRefresh, timeRange]);

  // Real-time updates
  useEffect(() => {
    if (isConnected && lastUpdate && autoRefresh) {
      fetchPerformanceData();
    }
  }, [lastUpdate, isConnected]);

  // Process chart data
  const chartData = useMemo(() => {
    if (!performanceData) return [];

    const latencyData = performanceData.latency.timeline || [];
    const jitterData = performanceData.jitter.timeline || [];
    const packetLossData = performanceData.packetLoss.timeline || [];

    // Merge all timelines
    const timeMap = new Map();

    latencyData.forEach(point => {
      const time = point.timestamp.getTime();
      timeMap.set(time, {
        timestamp: time,
        time: point.timestamp.toLocaleTimeString(),
        fullTime: point.timestamp.toLocaleString(),
        latency: point.value || 0
      });
    });

    jitterData.forEach(point => {
      const time = point.timestamp.getTime();
      const existing = timeMap.get(time) || {
        timestamp: time,
        time: point.timestamp.toLocaleTimeString(),
        fullTime: point.timestamp.toLocaleString()
      };
      existing.jitter = point.value || 0;
      timeMap.set(time, existing);
    });

    packetLossData.forEach(point => {
      const time = point.timestamp.getTime();
      const existing = timeMap.get(time) || {
        timestamp: time,
        time: point.timestamp.toLocaleTimeString(),
        fullTime: point.timestamp.toLocaleString()
      };
      existing.packetLoss = point.value || 0;
      timeMap.set(time, existing);
    });

    return Array.from(timeMap.values()).sort((a, b) => a.timestamp - b.timestamp);
  }, [performanceData]);

  // Calculate statistics and health status
  const stats = useMemo(() => {
    if (!performanceData) return null;

    const { latency, jitter, packetLoss } = performanceData;
    
    // Determine latency status
    let latencyStatus = 'excellent';
    let latencyColor = 'text-green-600';
    let latencyIcon = CheckCircle;
    
    if (latency.current > thresholds.HIGH) {
      latencyStatus = 'poor';
      latencyColor = 'text-red-600';
      latencyIcon = XCircle;
    } else if (latency.current > thresholds.MEDIUM) {
      latencyStatus = 'fair';
      latencyColor = 'text-yellow-600';
      latencyIcon = AlertTriangle;
    }

    // Calculate trend
    const latencyTrend = latency.current > latency.avg ? 'up' : 'down';
    const jitterTrend = jitter.current > jitter.avg ? 'up' : 'down';

    // Calculate performance score (0-100)
    const latencyScore = Math.max(0, 100 - (latency.current / thresholds.HIGH) * 100);
    const jitterScore = Math.max(0, 100 - (jitter.current / 10) * 100); // Assuming 10ms is max acceptable jitter
    const packetLossScore = Math.max(0, 100 - packetLoss.current * 10); // 10% loss = 0 score
    
    const overallScore = (latencyScore + jitterScore + packetLossScore) / 3;

    return {
      latency: {
        current: latency.current,
        avg: latency.avg,
        min: latency.min,
        max: latency.max,
        p95: latency.p95,
        status: latencyStatus,
        color: latencyColor,
        icon: latencyIcon,
        trend: latencyTrend
      },
      jitter: {
        current: jitter.current,
        avg: jitter.avg,
        trend: jitterTrend
      },
      packetLoss: {
        current: packetLoss.current,
        avg: packetLoss.avg
      },
      overallScore: Math.round(overallScore),
      healthStatus: overallScore > 80 ? 'excellent' : overallScore > 60 ? 'good' : overallScore > 40 ? 'fair' : 'poor'
    };
  }, [performanceData, thresholds]);

  // Custom tooltip
  const CustomTooltip = ({ active, payload, label }) => {
    if (!active || !payload || !payload.length) return null;

    const data = payload[0].payload;
    
    return (
      <div className="bg-white dark:bg-gray-800 p-4 border border-gray-200 dark:border-gray-700 rounded-lg shadow-lg">
        <p className="text-sm font-medium text-gray-900 dark:text-white mb-2">
          {data.fullTime}
        </p>
        
        <div className="space-y-1">
          {data.latency !== undefined && (
            <div className="flex items-center justify-between">
              <span className="flex items-center text-sm text-blue-600">
                <Clock className="w-3 h-3 mr-1" />
                Latency:
              </span>
              <span className="text-sm font-medium">
                {formatLatency(data.latency)}
              </span>
            </div>
          )}
          
          {data.jitter !== undefined && selectedMetrics.jitter && (
            <div className="flex items-center justify-between">
              <span className="flex items-center text-sm text-orange-600">
                <Zap className="w-3 h-3 mr-1" />
                Jitter:
              </span>
              <span className="text-sm font-medium">
                {formatLatency(data.jitter)}
              </span>
            </div>
          )}
          
          {data.packetLoss !== undefined && selectedMetrics.packetLoss && (
            <div className="flex items-center justify-between">
              <span className="flex items-center text-sm text-red-600">
                <XCircle className="w-3 h-3 mr-1" />
                Packet Loss:
              </span>
              <span className="text-sm font-medium">
                {data.packetLoss.toFixed(2)}%
              </span>
            </div>
          )}
        </div>
      </div>
    );
  };

  // Render chart based on type
  const renderChart = () => {
    const commonProps = {
      data: chartData,
      margin: { top: 20, right: 30, left: 20, bottom: 5 }
    };

    switch (chartType) {
      case 'line':
        return (
          <LineChart {...commonProps}>
            <CartesianGrid strokeDasharray="3 3" className="opacity-30" />
            <XAxis 
              dataKey="time" 
              tick={{ fontSize: 12 }}
              tickLine={{ stroke: '#6B7280' }}
            />
            <YAxis 
              tick={{ fontSize: 12 }}
              tickLine={{ stroke: '#6B7280' }}
              label={{ value: 'ms', angle: -90, position: 'insideLeft' }}
            />
            <Tooltip content={<CustomTooltip />} />
            <Legend />
            
            {/* Threshold lines */}
            <ReferenceLine 
              y={thresholds.HIGH} 
              stroke="#ef4444" 
              strokeDasharray="5 5" 
              label="High Threshold"
            />
            <ReferenceLine 
              y={thresholds.MEDIUM} 
              stroke="#f59e0b" 
              strokeDasharray="3 3" 
              label="Medium Threshold"
            />
            
            {selectedMetrics.latency && (
              <Line
                type="monotone"
                dataKey="latency"
                stroke={CHART_COLORS.PRIMARY}
                strokeWidth={2}
                name="Latency"
                dot={false}
                connectNulls={false}
              />
            )}
            
            {selectedMetrics.jitter && (
              <Line
                type="monotone"
                dataKey="jitter"
                stroke={CHART_COLORS.WARNING}
                strokeWidth={2}
                name="Jitter"
                dot={false}
                connectNulls={false}
              />
            )}
            
            {selectedMetrics.packetLoss && (
              <Line
                type="monotone"
                dataKey="packetLoss"
                stroke={CHART_COLORS.DANGER}
                strokeWidth={2}
                name="Packet Loss %"
                yAxisId="right"
                dot={false}
                connectNulls={false}
              />
            )}
          </LineChart>
        );

      case 'area':
        return (
          <AreaChart {...commonProps}>
            <CartesianGrid strokeDasharray="3 3" className="opacity-30" />
            <XAxis 
              dataKey="time" 
              tick={{ fontSize: 12 }}
              tickLine={{ stroke: '#6B7280' }}
            />
            <YAxis 
              tick={{ fontSize: 12 }}
              tickLine={{ stroke: '#6B7280' }}
              label={{ value: 'ms', angle: -90, position: 'insideLeft' }}
            />
            <Tooltip content={<CustomTooltip />} />
            <Legend />
            
            {/* Threshold lines */}
            <ReferenceLine y={thresholds.HIGH} stroke="#ef4444" strokeDasharray="5 5" />
            <ReferenceLine y={thresholds.MEDIUM} stroke="#f59e0b" strokeDasharray="3 3" />
            
            {selectedMetrics.latency && (
              <Area
                type="monotone"
                dataKey="latency"
                stroke={CHART_COLORS.PRIMARY}
                fill={CHART_COLORS.PRIMARY}
                fillOpacity={0.3}
                name="Latency"
                connectNulls={false}
              />
            )}
            
            {selectedMetrics.jitter && (
              <Area
                type="monotone"
                dataKey="jitter"
                stroke={CHART_COLORS.WARNING}
                fill={CHART_COLORS.WARNING}
                fillOpacity={0.2}
                name="Jitter"
                connectNulls={false}
              />
            )}
          </AreaChart>
        );

      case 'scatter':
        return (
          <ScatterChart {...commonProps}>
            <CartesianGrid strokeDasharray="3 3" className="opacity-30" />
            <XAxis 
              type="number"
              dataKey="timestamp"
              domain={['dataMin', 'dataMax']}
              tickFormatter={(value) => new Date(value).toLocaleTimeString()}
              tick={{ fontSize: 12 }}
            />
            <YAxis 
              tick={{ fontSize: 12 }}
              label={{ value: 'ms', angle: -90, position: 'insideLeft' }}
            />
            <Tooltip content={<CustomTooltip />} />
            <Legend />
            
            {selectedMetrics.latency && (
              <Scatter
                dataKey="latency"
                fill={CHART_COLORS.PRIMARY}
                name="Latency"
              />
            )}
            
            {selectedMetrics.jitter && (
              <Scatter
                dataKey="jitter"
                fill={CHART_COLORS.WARNING}
                name="Jitter"
              />
            )}
          </ScatterChart>
        );

      case 'composed':
        return (
          <ComposedChart {...commonProps}>
            <CartesianGrid strokeDasharray="3 3" className="opacity-30" />
            <XAxis 
              dataKey="time" 
              tick={{ fontSize: 12 }}
              tickLine={{ stroke: '#6B7280' }}
            />
            <YAxis 
              tick={{ fontSize: 12 }}
              tickLine={{ stroke: '#6B7280' }}
              label={{ value: 'ms', angle: -90, position: 'insideLeft' }}
            />
            <YAxis 
              yAxisId="right"
              orientation="right"
              tick={{ fontSize: 12 }}
              tickLine={{ stroke: '#6B7280' }}
              label={{ value: 'Loss %', angle: 90, position: 'insideRight' }}
            />
            <Tooltip content={<CustomTooltip />} />
            <Legend />
            
            {selectedMetrics.latency && (
              <Line
                type="monotone"
                dataKey="latency"
                stroke={CHART_COLORS.PRIMARY}
                strokeWidth={3}
                name="Latency"
                dot={{ fill: CHART_COLORS.PRIMARY, strokeWidth: 2, r: 3 }}
              />
            )}
            
            {selectedMetrics.jitter && (
              <Area
                type="monotone"
                dataKey="jitter"
                stroke={CHART_COLORS.WARNING}
                fill={CHART_COLORS.WARNING}
                fillOpacity={0.2}
                name="Jitter"
              />
            )}
            
            {selectedMetrics.packetLoss && (
              <Bar
                dataKey="packetLoss"
                yAxisId="right"
                fill={CHART_COLORS.DANGER}
                name="Packet Loss %"
                opacity={0.7}
              />
            )}
          </ComposedChart>
        );

      default:
        return null;
    }
  };

  if (loading && !performanceData) {
    return (
      <div className={`bg-white dark:bg-gray-800 rounded-lg shadow-sm p-6 ${className}`}>
        <div className="flex items-center justify-center h-64">
          <LoadingSpinner size="lg" />
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className={`bg-white dark:bg-gray-800 rounded-lg shadow-sm p-6 ${className}`}>
        <div className="flex items-center justify-center h-64 text-red-600">
          <AlertTriangle className="w-6 h-6 mr-2" />
          <span>Error loading latency data: {error}</span>
        </div>
      </div>
    );
  }

  return (
    <div className={`bg-white dark:bg-gray-800 rounded-lg shadow-sm ${className}`}>
      {/* Header */}
      <div className="p-4 border-b border-gray-200 dark:border-gray-700">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="flex items-center space-x-2">
              <Clock className="w-5 h-5 text-blue-600" />
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                Network Latency
              </h3>
            </div>
            
            {stats && (
              <div className="flex items-center space-x-2">
                <stats.latency.icon className={`w-4 h-4 ${stats.latency.color}`} />
                <span className={`text-sm font-medium ${stats.latency.color}`}>
                  {formatLatency(stats.latency.current)}
                </span>
                {stats.latency.trend === 'up' ? (
                  <TrendingUp className="w-4 h-4 text-red-500" />
                ) : (
                  <TrendingDown className="w-4 h-4 text-green-500" />
                )}
              </div>
            )}
          </div>

          <div className="flex items-center space-x-2">
            {/* Chart Type Selector */}
            <select
              value={chartType}
              onChange={(e) => setChartType(e.target.value)}
              className="text-sm border border-gray-300 dark:border-gray-600 rounded px-2 py-1 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
            >
              <option value="line">Line</option>
              <option value="area">Area</option>
              <option value="scatter">Scatter</option>
              <option value="composed">Composed</option>
            </select>

            {/* Control Buttons */}
            <button
              onClick={() => setAutoRefresh(!autoRefresh)}
              className={`p-1 rounded ${autoRefresh ? 'text-green-600' : 'text-gray-400'}`}
              title={autoRefresh ? 'Disable auto-refresh' : 'Enable auto-refresh'}
            >
              <RefreshCw className={`w-4 h-4 ${autoRefresh ? 'animate-spin' : ''}`} />
            </button>

            <button
              onClick={() => setIsExpanded(!isExpanded)}
              className="p-1 text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white"
              title={isExpanded ? 'Minimize' : 'Expand'}
            >
              {isExpanded ? <Minimize2 className="w-4 h-4" /> : <Maximize2 className="w-4 h-4" />}
            </button>

            <button
              onClick={() => setShowSettings(!showSettings)}
              className="p-1 text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white"
            >
              <Settings className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Statistics Row */}
        {stats && (
          <div className="mt-3 grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
            <div className="flex flex-col">
              <span className="text-gray-500">Current</span>
              <span className={`font-medium ${stats.latency.color}`}>
                {formatLatency(stats.latency.current)}
              </span>
            </div>
            <div className="flex flex-col">
              <span className="text-gray-500">Average</span>
              <span className="font-medium text-gray-900 dark:text-white">
                {formatLatency(stats.latency.avg)}
              </span>
            </div>
            <div className="flex flex-col">
              <span className="text-gray-500">95th Percentile</span>
              <span className="font-medium text-orange-600">
                {formatLatency(stats.latency.p95)}
              </span>
            </div>
            <div className="flex flex-col">
              <span className="text-gray-500">Health Score</span>
              <div className="flex items-center space-x-1">
                <span className={`font-medium ${
                  stats.overallScore > 80 ? 'text-green-600' : 
                  stats.overallScore > 60 ? 'text-yellow-600' : 'text-red-600'
                }`}>
                  {stats.overallScore}%
                </span>
                <Activity className="w-3 h-3 text-gray-400" />
              </div>
            </div>
          </div>
        )}

        {/* Settings Panel */}
        {showSettings && (
          <div className="mt-3 p-3 bg-gray-50 dark:bg-gray-700 rounded border">
            <div className="grid grid-cols-2 gap-4 text-sm">
              <div className="space-y-2">
                <h4 className="font-medium">Metrics</h4>
                <label className="flex items-center space-x-2">
                  <input
                    type="checkbox"
                    checked={selectedMetrics.latency}
                    onChange={(e) => setSelectedMetrics(prev => ({
                      ...prev, latency: e.target.checked
                    }))}
                    className="rounded"
                  />
                  <span>Latency</span>
                </label>
                <label className="flex items-center space-x-2">
                  <input
                    type="checkbox"
                    checked={selectedMetrics.jitter}
                    onChange={(e) => setSelectedMetrics(prev => ({
                      ...prev, jitter: e.target.checked
                    }))}
                    className="rounded"
                  />
                  <span>Jitter</span>
                </label>
                <label className="flex items-center space-x-2">
                  <input
                    type="checkbox"
                    checked={selectedMetrics.packetLoss}
                    onChange={(e) => setSelectedMetrics(prev => ({
                      ...prev, packetLoss: e.target.checked
                    }))}
                    className="rounded"
                  />
                  <span>Packet Loss</span>
                </label>
              </div>
              <div className="space-y-2">
                <h4 className="font-medium">Alerts</h4>
                <label className="flex items-center space-x-2">
                  <input
                    type="checkbox"
                    checked={alertsEnabled}
                    onChange={(e) => setAlertsEnabled(e.target.checked)}
                    className="rounded"
                  />
                  <span>Enable Threshold Alerts</span>
                </label>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Chart */}
      <div className="p-4">
        <div 
          ref={chartRef}
          style={{ height: isExpanded ? height * 1.5 : height }}
        >
          <ResponsiveContainer width="100%" height="100%">
            {renderChart()}
          </ResponsiveContainer>
        </div>
      </div>

      {/* Real-time Status */}
      <div className="px-4 pb-4">
        <div className="flex items-center justify-between text-xs text-gray-500">
          <div className="flex items-center space-x-4">
            <div className="flex items-center space-x-2">
              <div className={`w-2 h-2 rounded-full ${isConnected ? 'bg-green-500' : 'bg-red-500'}`} />
              <span>{isConnected ? 'Live' : 'Disconnected'}</span>
            </div>
            {stats && (
              <div className="flex items-center space-x-2">
                <Target className="w-3 h-3" />
                <span>Status: {stats.latency.status}</span>
              </div>
            )}
          </div>
          {lastUpdate && (
            <span>
              Last updated: {lastUpdate.toLocaleTimeString()}
            </span>
          )}
        </div>
      </div>
    </div>
  );
};

export default LatencyChart;