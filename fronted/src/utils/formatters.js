// Date and Time Formatters
export const formatTimestamp = (timestamp, options = {}) => {
  const {
    format = 'datetime',
    locale = 'en-US',
    timezone = 'UTC'
  } = options;

  if (!timestamp) return 'N/A';

  const date = new Date(timestamp);
  if (isNaN(date.getTime())) return 'Invalid Date';

  const formatOptions = {
    timeZone: timezone,
    ...getDateFormatOptions(format)
  };

  return new Intl.DateTimeFormat(locale, formatOptions).format(date);
};

const getDateFormatOptions = (format) => {
  switch (format) {
    case 'date':
      return {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit'
      };
    case 'time':
      return {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false
      };
    case 'datetime':
      return {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false
      };
    case 'relative':
      return null; // Handle separately
    default:
      return {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
      };
  }
};

export const formatRelativeTime = (timestamp) => {
  if (!timestamp) return 'N/A';

  const now = new Date();
  const past = new Date(timestamp);
  const diffInSeconds = Math.floor((now - past) / 1000);

  if (diffInSeconds < 60) return `${diffInSeconds}s ago`;
  if (diffInSeconds < 3600) return `${Math.floor(diffInSeconds / 60)}m ago`;
  if (diffInSeconds < 86400) return `${Math.floor(diffInSeconds / 3600)}h ago`;
  if (diffInSeconds < 2592000) return `${Math.floor(diffInSeconds / 86400)}d ago`;
  if (diffInSeconds < 31536000) return `${Math.floor(diffInSeconds / 2592000)}mo ago`;
  
  return `${Math.floor(diffInSeconds / 31536000)}y ago`;
};

export const formatDuration = (milliseconds) => {
  if (!milliseconds || milliseconds < 0) return '0ms';

  const units = [
    { label: 'd', value: 86400000 },
    { label: 'h', value: 3600000 },
    { label: 'm', value: 60000 },
    { label: 's', value: 1000 },
    { label: 'ms', value: 1 }
  ];

  for (const unit of units) {
    if (milliseconds >= unit.value) {
      const value = Math.floor(milliseconds / unit.value);
      const remainder = milliseconds % unit.value;
      
      if (remainder === 0 || unit.label === 'ms') {
        return `${value}${unit.label}`;
      }
      
      // Show two units for precision
      const nextUnit = units[units.indexOf(unit) + 1];
      if (nextUnit && remainder >= nextUnit.value) {
        const nextValue = Math.floor(remainder / nextUnit.value);
        return `${value}${unit.label} ${nextValue}${nextUnit.label}`;
      }
      
      return `${value}${unit.label}`;
    }
  }

  return `${milliseconds}ms`;
};

// Byte Size Formatters
export const formatBytes = (bytes, options = {}) => {
  const {
    precision = 2,
    binary = true,
    showUnit = true
  } = options;

  if (!bytes || bytes === 0) return showUnit ? '0 B' : '0';
  if (bytes < 0) return showUnit ? 'Invalid' : '0';

  const base = binary ? 1024 : 1000;
  const units = binary 
    ? ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB']
    : ['B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB'];

  const exponent = Math.floor(Math.log(bytes) / Math.log(base));
  const unit = units[Math.min(exponent, units.length - 1)];
  const value = bytes / Math.pow(base, exponent);

  const formatted = exponent === 0 
    ? bytes.toString()
    : value.toFixed(precision);

  return showUnit ? `${formatted} ${unit}` : formatted;
};

export const formatBandwidth = (bytesPerSecond, options = {}) => {
  const formatted = formatBytes(bytesPerSecond, options);
  return options.showUnit !== false ? `${formatted}/s` : formatted;
};

export const formatPacketSize = (size) => {
  if (size < 1024) return `${size} B`;
  if (size < 1048576) return `${(size / 1024).toFixed(1)} KB`;
  return `${(size / 1048576).toFixed(2)} MB`;
};

// Number Formatters
export const formatNumber = (number, options = {}) => {
  const {
    precision = 0,
    locale = 'en-US',
    notation = 'standard',
    compactDisplay = 'short'
  } = options;

  if (number === null || number === undefined || isNaN(number)) {
    return 'N/A';
  }

  const formatOptions = {
    minimumFractionDigits: precision,
    maximumFractionDigits: precision,
    notation,
    compactDisplay
  };

  return new Intl.NumberFormat(locale, formatOptions).format(number);
};

export const formatPercentage = (value, total, precision = 1) => {
  if (total === 0 || !value || !total) return '0%';
  const percentage = (value / total) * 100;
  return `${percentage.toFixed(precision)}%`;
};

export const formatLatency = (milliseconds, precision = 1) => {
  if (!milliseconds || milliseconds < 0) return '0ms';
  
  if (milliseconds < 1) {
    return `${(milliseconds * 1000).toFixed(precision)}μs`;
  }
  if (milliseconds < 1000) {
    return `${milliseconds.toFixed(precision)}ms`;
  }
  
  return `${(milliseconds / 1000).toFixed(precision)}s`;
};

export const formatPacketCount = (count) => {
  if (!count) return '0';
  
  if (count < 1000) return count.toString();
  if (count < 1000000) return `${(count / 1000).toFixed(1)}K`;
  if (count < 1000000000) return `${(count / 1000000).toFixed(1)}M`;
  
  return `${(count / 1000000000).toFixed(1)}B`;
};

// Network Address Formatters
export const formatIPAddress = (ip, options = {}) => {
  if (!ip) return 'Unknown';
  
  const { showPort = false, port } = options;
  
  // IPv6 handling
  if (ip.includes(':') && !ip.includes('.')) {
    const formatted = ip.toLowerCase();
    if (showPort && port) {
      return `[${formatted}]:${port}`;
    }
    return formatted;
  }
  
  // IPv4 handling
  if (showPort && port) {
    return `${ip}:${port}`;
  }
  
  return ip;
};

export const formatMACAddress = (mac) => {
  if (!mac) return 'Unknown';
  
  // Normalize MAC address format (XX:XX:XX:XX:XX:XX)
  const normalized = mac.replace(/[-\.]/g, ':').toUpperCase();
  
  // Validate MAC address format
  const macRegex = /^([0-9A-F]{2}:){5}[0-9A-F]{2}$/;
  if (!macRegex.test(normalized)) {
    return mac; // Return original if invalid format
  }
  
  return normalized;
};

export const formatEndpoint = (ip, port) => {
  if (!ip) return 'Unknown';
  
  if (port) {
    return ip.includes(':') && !ip.includes('.') 
      ? `[${ip}]:${port}` 
      : `${ip}:${port}`;
  }
  
  return ip;
};

// Protocol Formatters
export const formatProtocol = (protocol) => {
  if (!protocol) return 'Unknown';
  return protocol.toUpperCase();
};

export const formatPort = (port, protocol = '') => {
  if (!port) return 'Unknown';
  
  const commonPorts = {
    20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'TELNET',
    25: 'SMTP', 53: 'DNS', 67: 'DHCP', 68: 'DHCP',
    80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
    993: 'IMAPS', 995: 'POP3S'
  };
  
  const serviceName = commonPorts[port];
  if (serviceName) {
    return `${port} (${serviceName})`;
  }
  
  return port.toString();
};

// Threat and Security Formatters
export const formatThreatSeverity = (severity) => {
  const severityMap = {
    critical: { label: 'Critical', color: 'text-red-600' },
    high: { label: 'High', color: 'text-orange-600' },
    medium: { label: 'Medium', color: 'text-yellow-600' },
    low: { label: 'Low', color: 'text-blue-600' },
    info: { label: 'Info', color: 'text-gray-600' }
  };
  
  return severityMap[severity?.toLowerCase()] || { label: severity || 'Unknown', color: 'text-gray-600' };
};

export const formatThreatStatus = (status) => {
  const statusMap = {
    active: { label: 'Active', color: 'text-red-600' },
    investigating: { label: 'Investigating', color: 'text-yellow-600' },
    resolved: { label: 'Resolved', color: 'text-green-600' },
    false_positive: { label: 'False Positive', color: 'text-gray-600' }
  };
  
  return statusMap[status?.toLowerCase()] || { label: status || 'Unknown', color: 'text-gray-600' };
};

export const formatConfidenceScore = (score) => {
  if (score === null || score === undefined) return 'N/A';
  
  const percentage = Math.round(score * 100);
  let level = 'Low';
  let color = 'text-red-600';
  
  if (percentage >= 90) {
    level = 'Very High';
    color = 'text-green-600';
  } else if (percentage >= 75) {
    level = 'High';
    color = 'text-green-500';
  } else if (percentage >= 50) {
    level = 'Medium';
    color = 'text-yellow-600';
  } else if (percentage >= 25) {
    level = 'Low';
    color = 'text-orange-600';
  }
  
  return {
    percentage: `${percentage}%`,
    level,
    color
  };
};

// Chart Data Formatters
export const formatChartLabel = (value, type = 'default') => {
  switch (type) {
    case 'time':
      return formatTimestamp(value, { format: 'time' });
    case 'date':
      return formatTimestamp(value, { format: 'date' });
    case 'bytes':
      return formatBytes(value, { precision: 1 });
    case 'packets':
      return formatPacketCount(value);
    case 'percentage':
      return `${value}%`;
    default:
      return value?.toString() || '';
  }
};

export const formatTooltipValue = (value, type = 'default') => {
  switch (type) {
    case 'bytes':
      return formatBytes(value);
    case 'packets':
      return formatNumber(value);
    case 'latency':
      return formatLatency(value);
    case 'percentage':
      return formatPercentage(value, 100);
    default:
      return formatNumber(value);
  }
};

// Hash and ID Formatters
export const formatHash = (hash, length = 8) => {
  if (!hash) return 'N/A';
  return hash.length > length ? `${hash.substring(0, length)}...` : hash;
};

export const formatSessionId = (sessionId) => {
  return formatHash(sessionId, 12);
};

export const formatPacketId = (packetId) => {
  return formatHash(packetId, 10);
};

// Text Formatters
export const truncateText = (text, maxLength = 50) => {
  if (!text) return '';
  return text.length > maxLength ? `${text.substring(0, maxLength)}...` : text;
};

export const formatDescription = (description, maxLength = 100) => {
  return truncateText(description, maxLength);
};

export const capitalizeFirst = (str) => {
  if (!str) return '';
  return str.charAt(0).toUpperCase() + str.slice(1).toLowerCase();
};

export const formatCamelCase = (str) => {
  if (!str) return '';
  return str.replace(/([A-Z])/g, ' $1').replace(/^./, str => str.toUpperCase());
};

// Status Formatters
export const formatSystemStatus = (status) => {
  const statusMap = {
    online: { label: 'Online', color: 'text-green-600', bg: 'bg-green-100' },
    offline: { label: 'Offline', color: 'text-red-600', bg: 'bg-red-100' },
    maintenance: { label: 'Maintenance', color: 'text-yellow-600', bg: 'bg-yellow-100' },
    degraded: { label: 'Degraded', color: 'text-orange-600', bg: 'bg-orange-100' },
    error: { label: 'Error', color: 'text-red-600', bg: 'bg-red-100' }
  };
  
  return statusMap[status?.toLowerCase()] || { 
    label: status || 'Unknown', 
    color: 'text-gray-600', 
    bg: 'bg-gray-100' 
  };
};

// Performance Formatters
export const formatPerformanceMetric = (value, metric) => {
  switch (metric) {
    case 'latency':
    case 'jitter':
      return formatLatency(value);
    case 'bandwidth':
    case 'throughput':
      return formatBandwidth(value);
    case 'packet_loss':
      return formatPercentage(value, 100);
    case 'cpu_usage':
    case 'memory_usage':
    case 'disk_usage':
      return `${value?.toFixed(1)}%`;
    default:
      return formatNumber(value);
  }
};

// Utility Functions
export const sanitizeForDisplay = (value) => {
  if (value === null || value === undefined) return 'N/A';
  if (typeof value === 'string') return value.trim();
  if (typeof value === 'number') return value.toString();
  if (typeof value === 'boolean') return value ? 'Yes' : 'No';
  if (typeof value === 'object') return JSON.stringify(value);
  return value.toString();
};

export const formatArrayAsString = (arr, separator = ', ') => {
  if (!Array.isArray(arr)) return sanitizeForDisplay(arr);
  return arr.map(item => sanitizeForDisplay(item)).join(separator);
};