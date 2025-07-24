import React from 'react';
import { 
  TrendingUp, 
  TrendingDown, 
  Activity, 
  AlertTriangle, 
  CheckCircle, 
  XCircle,
  Info,
  Zap,
  Shield,
  Network,
  Database,
  Clock,
  BarChart3
} from 'lucide-react';

const StatCard = ({
  title,
  value,
  subtitle,
  icon,
  trend,
  trendValue,
  trendLabel,
  status = 'neutral',
  size = 'medium',
  loading = false,
  onClick,
  className = '',
  showBorder = true,
  animate = true
}) => {
  const getStatusColors = (status) => {
    const colors = {
      success: {
        bg: 'bg-green-50 dark:bg-green-900/20',
        border: 'border-green-200 dark:border-green-800',
        icon: 'text-green-600 dark:text-green-400',
        value: 'text-green-700 dark:text-green-300',
        trend: 'text-green-600 dark:text-green-400'
      },
      warning: {
        bg: 'bg-yellow-50 dark:bg-yellow-900/20',
        border: 'border-yellow-200 dark:border-yellow-800',
        icon: 'text-yellow-600 dark:text-yellow-400',
        value: 'text-yellow-700 dark:text-yellow-300',
        trend: 'text-yellow-600 dark:text-yellow-400'
      },
      error: {
        bg: 'bg-red-50 dark:bg-red-900/20',
        border: 'border-red-200 dark:border-red-800',
        icon: 'text-red-600 dark:text-red-400',
        value: 'text-red-700 dark:text-red-300',
        trend: 'text-red-600 dark:text-red-400'
      },
      info: {
        bg: 'bg-blue-50 dark:bg-blue-900/20',
        border: 'border-blue-200 dark:border-blue-800',
        icon: 'text-blue-600 dark:text-blue-400',
        value: 'text-blue-700 dark:text-blue-300',
        trend: 'text-blue-600 dark:text-blue-400'
      },
      neutral: {
        bg: 'bg-white dark:bg-gray-800',
        border: 'border-gray-200 dark:border-gray-700',
        icon: 'text-gray-600 dark:text-gray-400',
        value: 'text-gray-900 dark:text-white',
        trend: 'text-gray-600 dark:text-gray-400'
      }
    };
    return colors[status] || colors.neutral;
  };

  const getSizeClasses = (size) => {
    const sizes = {
      small: {
        card: 'p-4',
        icon: 'w-8 h-8 p-1.5',
        title: 'text-sm',
        value: 'text-xl',
        subtitle: 'text-xs',
        trend: 'text-xs'
      },
      medium: {
        card: 'p-6',
        icon: 'w-10 h-10 p-2',
        title: 'text-sm',
        value: 'text-2xl',
        subtitle: 'text-sm',
        trend: 'text-sm'
      },
      large: {
        card: 'p-8',
        icon: 'w-12 h-12 p-2.5',
        title: 'text-base',
        value: 'text-3xl',
        subtitle: 'text-base',
        trend: 'text-base'
      }
    };
    return sizes[size] || sizes.medium;
  };

  const colors = getStatusColors(status);
  const sizes = getSizeClasses(size);
  
  const IconComponent = icon || Activity;
  
  const getTrendIcon = () => {
    if (!trend) return null;
    
    if (trend === 'up') {
      return <TrendingUp className="w-4 h-4" />;
    } else if (trend === 'down') {
      return <TrendingDown className="w-4 h-4" />;
    }
    return null;
  };

  const getTrendColor = () => {
    if (trend === 'up') return 'text-green-600 dark:text-green-400';
    if (trend === 'down') return 'text-red-600 dark:text-red-400';
    return 'text-gray-600 dark:text-gray-400';
  };

  const cardClasses = `
    ${colors.bg}
    ${showBorder ? `border ${colors.border}` : ''}
    ${sizes.card}
    rounded-lg shadow-sm
    ${onClick ? 'cursor-pointer hover:shadow-md transition-all duration-200' : ''}
    ${animate ? 'transform hover:scale-105' : ''}
    ${className}
  `;

  const content = (
    <>
      {/* Header */}
      <div className="flex items-start justify-between mb-4">
        <div className="flex-1">
          <h3 className={`${sizes.title} font-medium text-gray-600 dark:text-gray-400 mb-1`}>
            {title}
          </h3>
          {loading ? (
            <div className="animate-pulse">
              <div className="h-8 bg-gray-300 dark:bg-gray-600 rounded w-20 mb-2"></div>
              {subtitle && <div className="h-4 bg-gray-300 dark:bg-gray-600 rounded w-16"></div>}
            </div>
          ) : (
            <>
              <div className={`${sizes.value} font-bold ${colors.value} mb-1`}>
                {value}
              </div>
              {subtitle && (
                <p className={`${sizes.subtitle} text-gray-500 dark:text-gray-400`}>
                  {subtitle}
                </p>
              )}
            </>
          )}
        </div>
        
        <div className={`${sizes.icon} ${colors.icon} ${colors.bg} rounded-lg flex items-center justify-center`}>
          <IconComponent className="w-full h-full" />
        </div>
      </div>

      {/* Trend */}
      {(trend || trendValue || trendLabel) && !loading && (
        <div className="flex items-center justify-between pt-4 border-t border-gray-200 dark:border-gray-700">
          <div className={`flex items-center space-x-1 ${sizes.trend} ${getTrendColor()}`}>
            {getTrendIcon()}
            {trendValue && <span className="font-medium">{trendValue}</span>}
            {trendLabel && <span>{trendLabel}</span>}
          </div>
        </div>
      )}
    </>
  );

  if (onClick) {
    return (
      <button onClick={onClick} className={cardClasses}>
        {content}
      </button>
    );
  }

  return (
    <div className={cardClasses}>
      {content}
    </div>
  );
};

// Predefined stat card variants for common network monitoring metrics
export const PacketCountCard = ({ count, trend, trendValue, ...props }) => (
  <StatCard
    title="Packets Captured"
    value={count?.toLocaleString() || '0'}
    icon={Network}
    trend={trend}
    trendValue={trendValue}
    trendLabel="packets/sec"
    status="info"
    {...props}
  />
);

export const ThreatCountCard = ({ count, trend, trendValue, ...props }) => (
  <StatCard
    title="Threats Detected"
    value={count || '0'}
    icon={Shield}
    trend={trend}
    trendValue={trendValue}
    status={count > 0 ? 'error' : 'success'}
    {...props}
  />
);

export const BandwidthCard = ({ bandwidth, unit = 'Mbps', trend, trendValue, ...props }) => (
  <StatCard
    title="Bandwidth Usage"
    value={`${bandwidth || '0'} ${unit}`}
    icon={BarChart3}
    trend={trend}
    trendValue={trendValue}
    status="neutral"
    {...props}
  />
);

export const LatencyCard = ({ latency, unit = 'ms', trend, trendValue, ...props }) => (
  <StatCard
    title="Average Latency"
    value={`${latency || '0'} ${unit}`}
    icon={Clock}
    trend={trend}
    trendValue={trendValue}
    status={latency > 100 ? 'warning' : 'success'}
    {...props}
  />
);

export const UptimeCard = ({ uptime, ...props }) => (
  <StatCard
    title="System Uptime"
    value={uptime || '0 days'}
    icon={CheckCircle}
    status="success"
    {...props}
  />
);

export const ErrorRateCard = ({ errorRate, ...props }) => (
  <StatCard
    title="Error Rate"
    value={`${errorRate || '0'}%`}
    icon={errorRate > 5 ? XCircle : CheckCircle}
    status={errorRate > 5 ? 'error' : 'success'}
    {...props}
  />
);

export const ActiveConnectionsCard = ({ connections, trend, trendValue, ...props }) => (
  <StatCard
    title="Active Connections"
    value={connections?.toLocaleString() || '0'}
    icon={Activity}
    trend={trend}
    trendValue={trendValue}
    status="info"
    {...props}
  />
);

export const DataProcessedCard = ({ data, unit = 'GB', trend, trendValue, ...props }) => (
  <StatCard
    title="Data Processed"
    value={`${data || '0'} ${unit}`}
    icon={Database}
    trend={trend}
    trendValue={trendValue}
    status="neutral"
    {...props}
  />
);

export default StatCard;