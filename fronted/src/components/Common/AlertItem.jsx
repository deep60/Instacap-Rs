import React, { useState } from 'react';
import { formatTimeAgo, formatBytes } from '../../utils/formatters';

const AlertItem = ({ 
  alert, 
  onDismiss, 
  onAcknowledge, 
  onViewDetails, 
  showActions = true,
  compact = false 
}) => {
  const [isExpanded, setIsExpanded] = useState(false);
  const [isProcessing, setIsProcessing] = useState(false);

  const getSeverityConfig = (severity) => {
    switch (severity?.toLowerCase()) {
      case 'critical':
        return {
          bgColor: 'bg-red-50',
          borderColor: 'border-red-200',
          textColor: 'text-red-800',
          iconBg: 'bg-red-100',
          icon: '🚨',
          badge: 'bg-red-500'
        };
      case 'high':
        return {
          bgColor: 'bg-orange-50',
          borderColor: 'border-orange-200',
          textColor: 'text-orange-800',
          iconBg: 'bg-orange-100',
          icon: '⚠️',
          badge: 'bg-orange-500'
        };
      case 'medium':
        return {
          bgColor: 'bg-yellow-50',
          borderColor: 'border-yellow-200',
          textColor: 'text-yellow-800',
          iconBg: 'bg-yellow-100',
          icon: '⚡',
          badge: 'bg-yellow-500'
        };
      case 'low':
        return {
          bgColor: 'bg-blue-50',
          borderColor: 'border-blue-200',
          textColor: 'text-blue-800',
          iconBg: 'bg-blue-100',
          icon: 'ℹ️',
          badge: 'bg-blue-500'
        };
      default:
        return {
          bgColor: 'bg-gray-50',
          borderColor: 'border-gray-200',
          textColor: 'text-gray-800',
          iconBg: 'bg-gray-100',
          icon: '📋',
          badge: 'bg-gray-500'
        };
    }
  };

  const getAlertTypeIcon = (type) => {
    switch (type?.toLowerCase()) {
      case 'malware': return '🦠';
      case 'intrusion': return '🔓';
      case 'ddos': return '🌊';
      case 'anomaly': return '📊';
      case 'port_scan': return '🔍';
      case 'data_exfiltration': return '📤';
      case 'brute_force': return '🔨';
      case 'packet_loss': return '📉';
      case 'bandwidth': return '📊';
      case 'latency': return '⏱️';
      default: return '🔔';
    }
  };

  const handleDismiss = async () => {
    if (!onDismiss) return;
    
    setIsProcessing(true);
    try {
      await onDismiss(alert.id);
    } catch (error) {
      console.error('Error dismissing alert:', error);
    } finally {
      setIsProcessing(false);
    }
  };

  const handleAcknowledge = async () => {
    if (!onAcknowledge) return;
    
    setIsProcessing(true);
    try {
      await onAcknowledge(alert.id);
    } catch (error) {
      console.error('Error acknowledging alert:', error);
    } finally {
      setIsProcessing(false);
    }
  };

  const handleViewDetails = () => {
    if (onViewDetails) {
      onViewDetails(alert);
    } else {
      setIsExpanded(!isExpanded);
    }
  };

  const severityConfig = getSeverityConfig(alert.severity);
  const typeIcon = getAlertTypeIcon(alert.type);

  if (compact) {
    return (
      <div className={`flex items-center space-x-3 p-3 rounded-lg border ${severityConfig.bgColor} ${severityConfig.borderColor}`}>
        <div className={`flex-shrink-0 w-8 h-8 rounded-full ${severityConfig.iconBg} flex items-center justify-center`}>
          <span className="text-sm">{typeIcon}</span>
        </div>
        <div className="flex-1 min-w-0">
          <p className={`text-sm font-medium ${severityConfig.textColor} truncate`}>
            {alert.title}
          </p>
          <p className="text-xs text-gray-500 truncate">
            {formatTimeAgo(alert.timestamp)}
          </p>
        </div>
        <div className={`w-2 h-2 rounded-full ${severityConfig.badge}`}></div>
      </div>
    );
  }

  return (
    <div className={`border rounded-lg ${severityConfig.bgColor} ${severityConfig.borderColor} ${
      alert.acknowledged ? 'opacity-75' : ''
    } transition-all duration-200 hover:shadow-md`}>
      {/* Main Alert Content */}
      <div className="p-4">
        <div className="flex items-start space-x-3">
          {/* Alert Icon */}
          <div className={`flex-shrink-0 w-10 h-10 rounded-full ${severityConfig.iconBg} flex items-center justify-center`}>
            <span className="text-lg">{typeIcon}</span>
          </div>

          {/* Alert Details */}
          <div className="flex-1 min-w-0">
            <div className="flex items-start justify-between">
              <div className="flex-1">
                <h4 className={`text-sm font-semibold ${severityConfig.textColor} mb-1`}>
                  {alert.title}
                </h4>
                <p className="text-sm text-gray-600 mb-2">
                  {alert.description}
                </p>
                
                {/* Alert Metadata */}
                <div className="flex flex-wrap items-center gap-2 text-xs text-gray-500">
                  <span className="flex items-center space-x-1">
                    <span>🕒</span>
                    <span>{formatTimeAgo(alert.timestamp)}</span>
                  </span>
                  
                  {alert.source && (
                    <span className="flex items-center space-x-1">
                      <span>📍</span>
                      <span>{alert.source}</span>
                    </span>
                  )}
                  
                  {alert.affectedIPs && alert.affectedIPs.length > 0 && (
                    <span className="flex items-center space-x-1">
                      <span>🌐</span>
                      <span>{alert.affectedIPs.length} IP{alert.affectedIPs.length > 1 ? 's' : ''}</span>
                    </span>
                  )}
                  
                  {alert.packetCount && (
                    <span className="flex items-center space-x-1">
                      <span>📦</span>
                      <span>{alert.packetCount.toLocaleString()} packets</span>
                    </span>
                  )}
                  
                  {alert.dataVolume && (
                    <span className="flex items-center space-x-1">
                      <span>💾</span>
                      <span>{formatBytes(alert.dataVolume)}</span>
                    </span>
                  )}
                </div>
              </div>

              {/* Severity Badge */}
              <div className="flex-shrink-0 ml-2">
                <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium text-white ${severityConfig.badge}`}>
                  {alert.severity?.toUpperCase()}
                </span>
              </div>
            </div>

            {/* Status Indicators */}
            <div className="flex items-center space-x-2 mt-2">
              {alert.acknowledged && (
                <span className="inline-flex items-center px-2 py-1 rounded-full text-xs bg-green-100 text-green-800">
                  ✓ Acknowledged
                </span>
              )}
              
              {alert.resolved && (
                <span className="inline-flex items-center px-2 py-1 rounded-full text-xs bg-gray-100 text-gray-800">
                  ✓ Resolved
                </span>
              )}
              
              {alert.isActive && !alert.resolved && (
                <span className="inline-flex items-center px-2 py-1 rounded-full text-xs bg-red-100 text-red-800">
                  🔴 Active
                </span>
              )}
            </div>
          </div>
        </div>

        {/* Action Buttons */}
        {showActions && (
          <div className="flex items-center justify-between mt-4 pt-3 border-t border-gray-200">
            <button
              onClick={handleViewDetails}
              className="text-sm text-blue-600 hover:text-blue-800 font-medium transition-colors"
            >
              {isExpanded ? 'Hide Details' : 'View Details'}
            </button>
            
            <div className="flex space-x-2">
              {!alert.acknowledged && (
                <button
                  onClick={handleAcknowledge}
                  disabled={isProcessing}
                  className="px-3 py-1 text-xs bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-50 transition-colors"
                >
                  {isProcessing ? 'Processing...' : 'Acknowledge'}
                </button>
              )}
              
              <button
                onClick={handleDismiss}
                disabled={isProcessing}
                className="px-3 py-1 text-xs bg-gray-600 text-white rounded hover:bg-gray-700 disabled:opacity-50 transition-colors"
              >
                {isProcessing ? 'Processing...' : 'Dismiss'}
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Expanded Details */}
      {isExpanded && (
        <div className="border-t border-gray-200 p-4 bg-white bg-opacity-50">
          <h5 className="text-sm font-semibold text-gray-800 mb-2">Additional Details</h5>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
            {alert.sourceIP && (
              <div>
                <span className="font-medium text-gray-700">Source IP:</span>
                <span className="ml-2 text-gray-600">{alert.sourceIP}</span>
              </div>
            )}
            
            {alert.destinationIP && (
              <div>
                <span className="font-medium text-gray-700">Destination IP:</span>
                <span className="ml-2 text-gray-600">{alert.destinationIP}</span>
              </div>
            )}
            
            {alert.protocol && (
              <div>
                <span className="font-medium text-gray-700">Protocol:</span>
                <span className="ml-2 text-gray-600">{alert.protocol}</span>
              </div>
            )}
            
            {alert.port && (
              <div>
                <span className="font-medium text-gray-700">Port:</span>
                <span className="ml-2 text-gray-600">{alert.port}</span>
              </div>
            )}
            
            {alert.riskScore && (
              <div>
                <span className="font-medium text-gray-700">Risk Score:</span>
                <span className="ml-2 text-gray-600">{alert.riskScore}/100</span>
              </div>
            )}
            
            {alert.category && (
              <div>
                <span className="font-medium text-gray-700">Category:</span>
                <span className="ml-2 text-gray-600">{alert.category}</span>
              </div>
            )}
          </div>

          {alert.recommendations && alert.recommendations.length > 0 && (
            <div className="mt-4">
              <span className="font-medium text-gray-700">Recommendations:</span>
              <ul className="mt-1 list-disc list-inside text-gray-600 space-y-1">
                {alert.recommendations.map((rec, index) => (
                  <li key={index} className="text-sm">{rec}</li>
                ))}
              </ul>
            </div>
          )}

          {alert.affectedIPs && alert.affectedIPs.length > 0 && (
            <div className="mt-4">
              <span className="font-medium text-gray-700">Affected IPs:</span>
              <div className="mt-1 flex flex-wrap gap-1">
                {alert.affectedIPs.slice(0, 10).map((ip, index) => (
                  <span key={index} className="px-2 py-1 bg-gray-100 text-gray-700 rounded text-xs">
                    {ip}
                  </span>
                ))}
                {alert.affectedIPs.length > 10 && (
                  <span className="px-2 py-1 bg-gray-100 text-gray-700 rounded text-xs">
                    +{alert.affectedIPs.length - 10} more
                  </span>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default AlertItem;