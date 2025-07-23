export const PROTOCOLS = ['HTTP', 'HTTPS', 'TCP', 'UDP', 'DNS', 'FTP', 'SSH', 'ICMP'];

export const THREAT_SEVERITIES = {
  LOW: 'low',
  MEDIUM: 'medium',
  HIGH: 'high',
  CRITICAL: 'critical'
};

export const THREAT_STATUSES = {
  ACTIVE: 'active',
  INVESTIGATING: 'investigating',
  RESOLVED: 'resolved',
  FALSE_POSITIVE: 'false_positive'
};

export const TIME_RANGES = {
  '1H': '1h',
  '6H': '6h',
  '12H': '12h',
  '24H': '24h',
  '7D': '7d',
  '30D': '30d'
};

export const CHART_COLORS = {
  primary: '#3b82f6',
  success: '#22c55e',
  warning: '#f59e0b',
  danger: '#ef4444',
  info: '#06b6d4',
  purple: '#8b5cf6'
};

export const COMMON_PORTS = {
  21: 'FTP',
  22: 'SSH',
  23: 'Telnet',
  25: 'SMTP',
  53: 'DNS',
  80: 'HTTP',
  110: 'POP3',
  143: 'IMAP',
  443: 'HTTPS',
  993: 'IMAPS',
  995: 'POP3S'
};
