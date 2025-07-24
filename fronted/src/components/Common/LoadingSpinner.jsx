import React from 'react';
import { Loader2, Activity, Network, Database } from 'lucide-react';

const LoadingSpinner = ({ 
  size = 'medium', 
  text = 'Loading...', 
  type = 'default',
  overlay = false,
  className = '',
  showIcon = true 
}) => {
  const sizeClasses = {
    small: 'w-4 h-4',
    medium: 'w-8 h-8',
    large: 'w-12 h-12',
    xlarge: 'w-16 h-16'
  };

  const textSizeClasses = {
    small: 'text-sm',
    medium: 'text-base',
    large: 'text-lg',
    xlarge: 'text-xl'
  };

  const getSpinnerIcon = () => {
    switch (type) {
      case 'network':
        return Network;
      case 'activity':
        return Activity;
      case 'database':
        return Database;
      default:
        return Loader2;
    }
  };

  const SpinnerIcon = getSpinnerIcon();

  const spinnerContent = (
    <div className={`flex flex-col items-center justify-center space-y-3 ${className}`}>
      {showIcon && (
        <div className="relative">
          <SpinnerIcon 
            className={`${sizeClasses[size]} text-blue-600 dark:text-blue-400 animate-spin`} 
          />
          {type === 'network' && (
            <div className="absolute inset-0 border-2 border-blue-200 dark:border-blue-800 rounded-full animate-ping"></div>
          )}
        </div>
      )}
      {text && (
        <div className={`${textSizeClasses[size]} text-gray-600 dark:text-gray-300 font-medium`}>
          {text}
        </div>
      )}
    </div>
  );

  if (overlay) {
    return (
      <div className="fixed inset-0 z-50 flex items-center justify-center bg-white/80 dark:bg-gray-900/80 backdrop-blur-sm">
        <div className="bg-white dark:bg-gray-800 p-8 rounded-lg shadow-lg border border-gray-200 dark:border-gray-700">
          {spinnerContent}
        </div>
      </div>
    );
  }

  return spinnerContent;
};

// Specialized loading components for different contexts
export const PacketLoadingSpinner = ({ text = 'Analyzing packets...' }) => (
  <LoadingSpinner 
    type="network" 
    text={text} 
    size="medium"
    className="py-8"
  />
);

export const ThreatLoadingSpinner = ({ text = 'Scanning for threats...' }) => (
  <LoadingSpinner 
    type="activity" 
    text={text} 
    size="medium"
    className="py-8"
  />
);

export const DataLoadingSpinner = ({ text = 'Loading data...' }) => (
  <LoadingSpinner 
    type="database" 
    text={text} 
    size="medium"
    className="py-8"
  />
);

// Inline spinner for buttons and small spaces
export const InlineSpinner = ({ size = 'small', className = '' }) => (
  <Loader2 className={`${sizeClasses[size]} animate-spin ${className}`} />
);

// Card skeleton loader
export const CardSkeleton = () => (
  <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 animate-pulse">
    <div className="flex items-center justify-between mb-4">
      <div className="h-4 bg-gray-300 dark:bg-gray-600 rounded w-24"></div>
      <div className="h-4 bg-gray-300 dark:bg-gray-600 rounded w-16"></div>
    </div>
    <div className="h-8 bg-gray-300 dark:bg-gray-600 rounded w-32 mb-2"></div>
    <div className="h-3 bg-gray-300 dark:bg-gray-600 rounded w-full"></div>
  </div>
);

// Table skeleton loader
export const TableSkeleton = ({ rows = 5, columns = 4 }) => (
  <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 overflow-hidden">
    <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
      <div className="flex space-x-4">
        {Array.from({ length: columns }).map((_, i) => (
          <div key={i} className="h-4 bg-gray-300 dark:bg-gray-600 rounded flex-1 animate-pulse"></div>
        ))}
      </div>
    </div>
    <div className="divide-y divide-gray-200 dark:divide-gray-700">
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="px-6 py-4">
          <div className="flex space-x-4">
            {Array.from({ length: columns }).map((_, j) => (
              <div key={j} className="h-4 bg-gray-300 dark:bg-gray-600 rounded flex-1 animate-pulse"></div>
            ))}
          </div>
        </div>
      ))}
    </div>
  </div>
);

// Chart skeleton loader
export const ChartSkeleton = ({ height = 'h-64' }) => (
  <div className={`bg-white dark:bg-gray-800 p-6 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 ${height}`}>
    <div className="h-4 bg-gray-300 dark:bg-gray-600 rounded w-32 mb-6 animate-pulse"></div>
    <div className="flex items-end space-x-2 h-40">
      {Array.from({ length: 12 }).map((_, i) => (
        <div 
          key={i} 
          className="bg-gray-300 dark:bg-gray-600 rounded-t animate-pulse flex-1"
          style={{ height: `${Math.random() * 80 + 20}%` }}
        ></div>
      ))}
    </div>
    <div className="flex justify-between mt-4">
      {Array.from({ length: 6 }).map((_, i) => (
        <div key={i} className="h-3 bg-gray-300 dark:bg-gray-600 rounded w-8 animate-pulse"></div>
      ))}
    </div>
  </div>
);

const sizeClasses = {
  small: 'w-4 h-4',
  medium: 'w-8 h-8',
  large: 'w-12 h-12',
  xlarge: 'w-16 h-16'
};

export default LoadingSpinner;