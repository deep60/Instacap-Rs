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
    ComposedChart,
    Bar
} from 'recharts';
import { 
    Activity, 
    TrendingUp, 
    TrendingDown, 
    Wifi, 
    AlertTriangle,
    Download,
    Upload,
    Gauge,
    Maximize2,
    Minimize2,
    RefreshCw,
    Settings
} from 'lucide-react';
import analyticsService from '../../services/analyticsService';
import { useRealTimeUpdates } from '../../hooks/useRealTimeUpdates';
import { formatBytes, formatBitsPerSecond, formatNumber } from '../../utils/formatters';
import { TIME_RANGES, CHART_COLORS, BANDWIDTH_THRESHOLDS } from '../../utils/constants';
import LoadingSpinner from '../Common/LoadingSpinner';

const BandwidthChart = ({ 
    timeRange = TIME_RANGES.LAST_HOUR,
    newInterface = 'all',
    showUtilization = true,
    showThroughput = true,
    height = 400,
    onInterfaceChange,
    className = ''
}) => {
const [bandwidthData, setBandwidthData] = useState(null);
const [loading, setLoading] = useState(true);
const [error, setError] = useState(null);
const [isExpanded, setIsExpanded] = useState(false);
const [chartType, setChartType] = useState('area'); // 'line', 'area', 'composed'
const [selectedInterface, setSelectedInterface] = useState(newInterface);
const [showSettings, setShowSettings] = useState(false);
const [autoRefresh, setAutoRefresh] = useState(true);
    
const chartRef = useRef(null);
const updateInterval = useRef(null);

    // Real-time updates hook
const { isConnected, lastUpdate } = useRealTimeUpdates(['bandwidth', 'interface_stats']);

    // Fetch bandwidth data
const fetchBandwidthData = async () => {
    try {
        setLoading(true);
        const data = await analyticsService.getBandwidthMetrics(timeRange, selectedInterface);
        setBandwidthData(data);
        setError(null);
    } catch (err) {
        setError(err.message);
        console.error('Error fetching bandwidth data:', err);
    } finally {
        setLoading(false);
    }
};

    // Initial load and interface changes
    useEffect(() => {
        fetchBandwidthData();
    }, [timeRange, selectedInterface]);

    // Auto-refresh mechanism
    useEffect(() => {
        if (autoRefresh) {
        updateInterval.current = setInterval(fetchBandwidthData, 30000); // 30 seconds
        return () => {
            if (updateInterval.current) {
            clearInterval(updateInterval.current);
            }
        };
        }
    }, [autoRefresh, timeRange, selectedInterface]);

    // Real-time updates
    useEffect(() => {
        if (isConnected && lastUpdate && autoRefresh) {
        fetchBandwidthData();
        }
    }, [lastUpdate, isConnected]);

    // Process chart data
    const chartData = useMemo(() => {
        if (!bandwidthData?.timeline) return [];

        return bandwidthData.timeline.map(point => ({
        timestamp: point.timestamp.getTime(),
        time: point.timestamp.toLocaleTimeString(),
        inbound: point.inbound / (1024 * 1024), // Convert to Mbps
        outbound: point.outbound / (1024 * 1024),
        total: point.total / (1024 * 1024),
        utilization: point.utilization,
        inboundBytes: point.inbound,
        outboundBytes: point.outbound,
        totalBytes: point.total
        }));
    }, [bandwidthData]);

    // Calculate statistics
    const stats = useMemo(() => {
        if (!bandwidthData) return null;

        const currentUtil = bandwidthData.currentUtilization;
        const avgUtil = bandwidthData.avgUtilization;
        const peakUtil = bandwidthData.peakUtilization;
        
        // Determine status based on utilization
        let status = 'normal';
        let statusColor = 'text-green-600';
        if (currentUtil > BANDWIDTH_THRESHOLDS.HIGH) {
        status = 'high';
        statusColor = 'text-red-600';
        } else if (currentUtil > BANDWIDTH_THRESHOLDS.MEDIUM) {
        status = 'medium';
        statusColor = 'text-yellow-600';
        }

        return {
        currentUtilization: currentUtil,
        avgUtilization: avgUtil,
        peakUtilization: peakUtil,
        maxCapacity: bandwidthData.maxCapacity,
        status,
        statusColor,
        trend: currentUtil > avgUtil ? 'up' : 'down'
        };
    }, [bandwidthData]);

    // Handle interface selection
    const handleInterfaceChange = (newInterface) => {
        setSelectedInterface(newInterface);
        if (onInterfaceChange) {
        onInterfaceChange(newInterface);
        }
    };

    // Custom tooltip
    const CustomTooltip = ({ active, payload, label }) => {
        if (!active || !payload || !payload.length) return null;

        const data = payload[0].payload;
        
        return (
        <div className="bg-white dark:bg-gray-800 p-4 border border-gray-200 dark:border-gray-700 rounded-lg shadow-lg">
            <p className="text-sm font-medium text-gray-900 dark:text-white mb-2">
            {new Date(data.timestamp).toLocaleString()}
            </p>
            
            <div className="space-y-1">
            <div className="flex items-center justify-between">
                <span className="flex items-center text-sm text-blue-600">
                <Download className="w-3 h-3 mr-1" />
                Inbound:
                </span>
                <span className="text-sm font-medium">
                {formatBitsPerSecond(data.inboundBytes)}
                </span>
            </div>
            
            <div className="flex items-center justify-between">
                <span className="flex items-center text-sm text-green-600">
                <Upload className="w-3 h-3 mr-1" />
                Outbound:
                </span>
                <span className="text-sm font-medium">
                {formatBitsPerSecond(data.outboundBytes)}
                </span>
            </div>
            
            <div className="flex items-center justify-between">
                <span className="flex items-center text-sm text-purple-600">
                <Activity className="w-3 h-3 mr-1" />
                Total:
                </span>
                <span className="text-sm font-medium">
                {formatBitsPerSecond(data.totalBytes)}
                </span>
            </div>
            
            {showUtilization && (
                <div className="flex items-center justify-between">
                <span className="flex items-center text-sm text-orange-600">
                    <Gauge className="w-3 h-3 mr-1" />
                    Utilization:
                </span>
                <span className="text-sm font-medium">
                    {data.utilization.toFixed(1)}%
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
        margin: { top: 5, right: 30, left: 20, bottom: 5 }
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
                label={{ value: 'Mbps', angle: -90, position: 'insideLeft' }}
                />
                <Tooltip content={<CustomTooltip />} />
                <Legend />
                
                {showThroughput && (
                <>
                    <Line
                    type="monotone"
                    dataKey="inbound"
                    stroke={CHART_COLORS.PRIMARY}
                    strokeWidth={2}
                    name="Inbound"
                    dot={false}
                    />
                    <Line
                    type="monotone"
                    dataKey="outbound"
                    stroke={CHART_COLORS.SUCCESS}
                    strokeWidth={2}
                    name="Outbound"
                    dot={false}
                    />
                    <Line
                    type="monotone"
                    dataKey="total"
                    stroke={CHART_COLORS.WARNING}
                    strokeWidth={2}
                    name="Total"
                    dot={false}
                    />
                </>
                )}
                
                {showUtilization && (
                <Line
                    type="monotone"
                    dataKey="utilization"
                    stroke={CHART_COLORS.DANGER}
                    strokeWidth={2}
                    name="Utilization %"
                    yAxisId="right"
                    dot={false}
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
                label={{ value: 'Mbps', angle: -90, position: 'insideLeft' }}
                />
                <Tooltip content={<CustomTooltip />} />
                <Legend />
                
                {showThroughput && (
                <>
                    <Area
                    type="monotone"
                    dataKey="total"
                    stackId="1"
                    stroke={CHART_COLORS.WARNING}
                    fill={CHART_COLORS.WARNING}
                    fillOpacity={0.3}
                    name="Total Throughput"
                    />
                    <Area
                    type="monotone"
                    dataKey="inbound"
                    stackId="2"
                    stroke={CHART_COLORS.PRIMARY}
                    fill={CHART_COLORS.PRIMARY}
                    fillOpacity={0.4}
                    name="Inbound"
                    />
                    <Area
                    type="monotone"
                    dataKey="outbound"
                    stackId="3"
                    stroke={CHART_COLORS.SUCCESS}
                    fill={CHART_COLORS.SUCCESS}
                    fillOpacity={0.4}
                    name="Outbound"
                    />
                </>
                )}
            </AreaChart>
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
                label={{ value: 'Mbps', angle: -90, position: 'insideLeft' }}
                />
                <YAxis 
                yAxisId="right"
                orientation="right"
                tick={{ fontSize: 12 }}
                tickLine={{ stroke: '#6B7280' }}
                label={{ value: 'Utilization %', angle: 90, position: 'insideRight' }}
                />
                <Tooltip content={<CustomTooltip />} />
                <Legend />
                
                {showThroughput && (
                <>
                    <Bar
                    dataKey="inbound"
                    fill={CHART_COLORS.PRIMARY}
                    name="Inbound"
                    opacity={0.7}
                    />
                    <Bar
                    dataKey="outbound"
                    fill={CHART_COLORS.SUCCESS}
                    name="Outbound"
                    opacity={0.7}
                    />
                </>
                )}
                
                {showUtilization && (
                <Line
                    type="monotone"
                    dataKey="utilization"
                    stroke={CHART_COLORS.DANGER}
                    strokeWidth={3}
                    name="Utilization %"
                    yAxisId="right"
                    dot={{ fill: CHART_COLORS.DANGER, strokeWidth: 2, r: 4 }}
                />
                )}
            </ComposedChart>
            );

        default:
            return null;
        }
    };

    if (loading && !bandwidthData) {
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
            <span>Error loading bandwidth data: {error}</span>
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
                <Wifi className="w-5 h-5 text-blue-600" />
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                    Bandwidth Utilization
                </h3>
                </div>
                
                {stats && (
                <div className="flex items-center space-x-2">
                    <span className={`text-sm font-medium ${stats.statusColor}`}>
                    {stats.currentUtilization.toFixed(1)}%
                    </span>
                    {stats.trend === 'up' ? (
                    <TrendingUp className="w-4 h-4 text-red-500" />
                    ) : (
                    <TrendingDown className="w-4 h-4 text-green-500" />
                    )}
                </div>
                )}
            </div>

            <div className="flex items-center space-x-2">
                {/* Interface Selector */}
                {bandwidthData?.interfaces && Object.keys(bandwidthData.interfaces).length > 1 && (
                <select
                    value={selectedInterface}
                    onChange={(e) => handleInterfaceChange(e.target.value)}
                    className="text-sm border border-gray-300 dark:border-gray-600 rounded px-2 py-1 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                >
                    <option value="all">All Interfaces</option>
                    {Object.keys(bandwidthData.interfaces).map(iface => (
                    <option key={iface} value={iface}>{iface}</option>
                    ))}
                </select>
                )}

                {/* Chart Type Selector */}
                <select
                value={chartType}
                onChange={(e) => setChartType(e.target.value)}
                className="text-sm border border-gray-300 dark:border-gray-600 rounded px-2 py-1 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                >
                <option value="area">Area</option>
                <option value="line">Line</option>
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
            <div className="mt-3 flex items-center space-x-6 text-sm">
                <div className="flex items-center space-x-1">
                <span className="text-gray-500">Current:</span>
                <span className={`font-medium ${stats.statusColor}`}>
                    {stats.currentUtilization.toFixed(1)}%
                </span>
                </div>
                <div className="flex items-center space-x-1">
                <span className="text-gray-500">Average:</span>
                <span className="font-medium text-gray-900 dark:text-white">
                    {stats.avgUtilization.toFixed(1)}%
                </span>
                </div>
                <div className="flex items-center space-x-1">
                <span className="text-gray-500">Peak:</span>
                <span className="font-medium text-red-600">
                    {stats.peakUtilization.toFixed(1)}%
                </span>
                </div>
                <div className="flex items-center space-x-1">
                <span className="text-gray-500">Capacity:</span>
                <span className="font-medium text-gray-900 dark:text-white">
                    {formatBitsPerSecond(stats.maxCapacity)}
                </span>
                </div>
            </div>
            )}

            {/* Settings Panel */}
            {showSettings && (
            <div className="mt-3 p-3 bg-gray-50 dark:bg-gray-700 rounded border">
                <div className="flex items-center space-x-4 text-sm">
                <label className="flex items-center space-x-2">
                    <input
                    type="checkbox"
                    checked={showThroughput}
                    onChange={(e) => setShowThroughput(e.target.checked)}
                    className="rounded"
                    />
                    <span>Show Throughput</span>
                </label>
                <label className="flex items-center space-x-2">
                    <input
                    type="checkbox"
                    checked={showUtilization}
                    onChange={(e) => setShowUtilization(e.target.checked)}
                    className="rounded"
                    />
                    <span>Show Utilization</span>
                </label>
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
            <div className="flex items-center space-x-2">
                <div className={`w-2 h-2 rounded-full ${isConnected ? 'bg-green-500' : 'bg-red-500'}`} />
                <span>{isConnected ? 'Live' : 'Disconnected'}</span>
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

    export default BandwidthChart;