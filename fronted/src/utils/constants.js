// API Configuration
export const API_CONFIG = {
  BASE_URL: process.env.REACT_APP_API_URL || 'http://localhost:8080/api',
  WEBSOCKET_URL: process.env.REACT_APP_WS_URL || 'ws://localhost:8080/ws',
  TIMEOUT: 30000,
  RETRY_ATTEMPTS: 3,
  RETRY_DELAY: 1000
};

// API Endpoints
export const API_ENDPOINTS = {
  PACKETS: '/packets',
  THREATS: '/threats',
  PERFORMANCE: '/performance',
  PROTOCOLS: '/protocols',
  ALERTS: '/alerts',
  STATS: '/stats',
  CAPTURE: '/capture',
  CONFIG: '/config'
};

// WebSocket Event Types
export const WS_EVENTS = {
  CONNECT: 'connect',
  DISCONNECT: 'disconnect',
  PACKET_DATA: 'packet_data',
  THREAT_ALERT: 'threat_alert',
  PERFORMANCE_UPDATE: 'performance_update',
  PROTOCOL_STATS: 'protocol_stats',
  ANOMALY_DETECTED: 'anomaly_detected',
  SYSTEM_STATUS: 'system_status'
};

// Legacy WebSocket Events (for backward compatibility)
export const WEBSOCKET_EVENTS = {
  PACKET_CAPTURED: 'packet_captured',
  THREAT_DETECTED: 'threat_detected',
  SYSTEM_STATUS: 'system_status',
  PERFORMANCE_UPDATE: 'performance_update',
  ANALYSIS_COMPLETE: 'analysis_complete'
};

// Threat Severity Levels
export const THREAT_SEVERITY = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
  INFO: 'info'
};

// Threat Status Types
export const THREAT_STATUS = {
  ACTIVE: 'active',
  INVESTIGATING: 'investigating',
  RESOLVED: 'resolved',
  FALSE_POSITIVE: 'false_positive'
};

// Threat Types
export const THREAT_TYPES = {
  MALWARE: 'malware',
  DDOS: 'ddos_attack',
  PORT_SCAN: 'port_scan',
  INTRUSION: 'intrusion_attempt',
  DATA_EXFILTRATION: 'data_exfiltration',
  SUSPICIOUS_TRAFFIC: 'suspicious_traffic',
  BOTNET: 'botnet_activity',
  PHISHING: 'phishing_attempt',
  SQL_INJECTION: 'sql_injection',
  XSS: 'cross_site_scripting',
  BRUTE_FORCE: 'brute_force_attack',
  DNS_TUNNELING: 'dns_tunneling',
  LATERAL_MOVEMENT: 'lateral_movement'
};

// Network Protocols
export const PROTOCOLS = {
  TCP: 'tcp',
  UDP: 'udp',
  ICMP: 'icmp',
  HTTP: 'http',
  HTTPS: 'https',
  FTP: 'ftp',
  SMTP: 'smtp',
  DNS: 'dns',
  DHCP: 'dhcp',
  SSH: 'ssh',
  TELNET: 'telnet',
  SNMP: 'snmp',
  ARP: 'arp',
  IPV4: 'ipv4',
  IPV6: 'ipv6'
};

// Common Network Ports
export const COMMON_PORTS = {
  HTTP: 80,
  HTTPS: 443,
  FTP: 21,
  SSH: 22,
  TELNET: 23,
  SMTP: 25,
  DNS: 53,
  DHCP_SERVER: 67,
  DHCP_CLIENT: 68,
  POP3: 110,
  IMAP: 143,
  SNMP: 161,
  LDAP: 389,
  SMB: 445,
  MYSQL: 3306,
  POSTGRESQL: 5432,
  REDIS: 6379,
  MONGODB: 27017
};

// Packet Analysis Constants
export const PACKET_ANALYSIS = {
  MAX_PACKET_SIZE: 65535,
  ETHERNET_HEADER_SIZE: 14,
  IP_HEADER_MIN_SIZE: 20,
  TCP_HEADER_MIN_SIZE: 20,
  UDP_HEADER_SIZE: 8,
  CAPTURE_BUFFER_SIZE: 10000,
  ANALYSIS_WINDOW_SIZE: 1000
};

// Performance Metrics Thresholds
export const PERFORMANCE_THRESHOLDS = {
  LATENCY: {
    EXCELLENT: 10,    // ms
    GOOD: 50,         // ms
    FAIR: 100,        // ms
    POOR: 200         // ms
  },
  PACKET_LOSS: {
    EXCELLENT: 0.1,   // %
    GOOD: 0.5,        // %
    FAIR: 1.0,        // %
    POOR: 2.0         // %
  },
  JITTER: {
    EXCELLENT: 5,     // ms
    GOOD: 20,         // ms
    FAIR: 50,         // ms
    POOR: 100         // ms
  },
  BANDWIDTH_UTILIZATION: {
    LOW: 30,          // %
    MEDIUM: 60,       // %
    HIGH: 80,         // %
    CRITICAL: 95      // %
  }
};

// Alert Levels
export const ALERT_LEVELS = {
  SUCCESS: 'success',
  INFO: 'info',
  WARNING: 'warning',
  ERROR: 'error'
};

// Dashboard Refresh Intervals (milliseconds)
export const REFRESH_INTERVALS = {
  REAL_TIME: 1000,      // 1 second
  FAST: 5000,           // 5 seconds
  NORMAL: 10000,        // 10 seconds
  SLOW: 30000,          // 30 seconds
  VERY_SLOW: 60000      // 1 minute
};

// Data Retention Periods (days)
export const DATA_RETENTION = {
  PACKETS: 7,
  THREATS: 90,
  PERFORMANCE_METRICS: 30,
  ALERTS: 60,
  LOGS: 365
};

// Chart Colors
export const CHART_COLORS = {
  PRIMARY: '#3B82F6',
  SUCCESS: '#10B981',
  WARNING: '#F59E0B',
  DANGER: '#EF4444',
  INFO: '#6B7280',
  PURPLE: '#8B5CF6',
  PINK: '#EC4899',
  INDIGO: '#6366F1',
  TEAL: '#14B8A6',
  ORANGE: '#F97316'
};

// Traffic Analysis Constants
export const TRAFFIC_ANALYSIS = {
  ANOMALY_DETECTION: {
    STATISTICAL_THRESHOLD: 2.5,    // Standard deviations
    MINIMUM_SAMPLES: 100,
    LEARNING_PERIOD: 24 * 60 * 60 * 1000  // 24 hours in ms
  },
  FLOW_TIMEOUT: 300000,  // 5 minutes in ms
  SESSION_TIMEOUT: 1800000,  // 30 minutes in ms
  MAX_FLOWS_PER_SECOND: 10000
};

// Machine Learning Model Constants
export const ML_MODELS = {
  ANOMALY_DETECTION: {
    UPDATE_INTERVAL: 3600000,     // 1 hour
    CONFIDENCE_THRESHOLD: 0.85,
    FEATURE_COUNT: 20
  },
  THREAT_CLASSIFICATION: {
    UPDATE_INTERVAL: 7200000,     // 2 hours
    CONFIDENCE_THRESHOLD: 0.9,
    MODEL_VERSION: '1.0'
  }
};

// Geo Location Constants
export const GEO_CONSTANTS = {
  PRIVATE_IP_RANGES: [
    '10.0.0.0/8',
    '172.16.0.0/12',
    '192.168.0.0/16',
    '127.0.0.0/8',
    '169.254.0.0/16'
  ],
  LOCALHOST_IPS: ['127.0.0.1', '::1', 'localhost']
};

// File Export Formats
export const EXPORT_FORMATS = {
  CSV: 'csv',
  JSON: 'json',
  PCAP: 'pcap',
  PDF: 'pdf',
  XML: 'xml'
};

// Pagination Constants
export const PAGINATION = {
  DEFAULT_PAGE_SIZE: 25,
  PAGE_SIZE_OPTIONS: [10, 25, 50, 100, 200],
  MAX_PAGE_SIZE: 1000
};

// Filter Constants
export const FILTERS = {
  TIME_RANGES: {
    LAST_5_MINUTES: '5m',
    LAST_15_MINUTES: '15m',
    LAST_30_MINUTES: '30m',
    LAST_HOUR: '1h',
    LAST_4_HOURS: '4h',
    LAST_12_HOURS: '12h',
    LAST_24_HOURS: '24h',
    LAST_7_DAYS: '7d',
    LAST_30_DAYS: '30d',
    CUSTOM: 'custom'
  },
  SORT_ORDERS: {
    ASC: 'asc',
    DESC: 'desc'
  }
};

// Time Ranges (for backward compatibility)
export const TIME_RANGES = FILTERS.TIME_RANGES;

// Protocol Colors for charts
export const PROTOCOL_COLORS = {
  TCP: '#3B82F6',
  UDP: '#10B981',
  ICMP: '#F59E0B',
  HTTP: '#EF4444',
  HTTPS: '#8B5CF6',
  FTP: '#EC4899',
  SMTP: '#6366F1',
  DNS: '#14B8A6',
  DHCP: '#F97316',
  SSH: '#6B7280',
  TELNET: '#9CA3AF',
  SNMP: '#DC2626',
  ARP: '#059669',
  IPV4: '#7C3AED',
  IPV6: '#DB2777',
  OTHER: '#374151'
};

// Validation Constants
export const VALIDATION = {
  IP_ADDRESS_REGEX: /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/,
  IPV6_ADDRESS_REGEX: /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/,
  MAC_ADDRESS_REGEX: /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/,
  PORT_RANGE: { MIN: 1, MAX: 65535 },
  MAX_SEARCH_LENGTH: 256
};

// System Status
export const SYSTEM_STATUS = {
  ONLINE: 'online',
  OFFLINE: 'offline',
  MAINTENANCE: 'maintenance',
  DEGRADED: 'degraded',
  ERROR: 'error'
};

// Storage Keys (for localStorage/sessionStorage alternatives)
export const STORAGE_KEYS = {
  USER_PREFERENCES: 'user_preferences',
  DASHBOARD_LAYOUT: 'dashboard_layout',
  FILTER_SETTINGS: 'filter_settings',
  THEME_PREFERENCE: 'theme_preference',
  NOTIFICATION_SETTINGS: 'notification_settings'
};

// Default Values
export const DEFAULTS = {
  THEME: 'light',
  LANGUAGE: 'en',
  TIMEZONE: 'UTC',
  DATE_FORMAT: 'YYYY-MM-DD HH:mm:ss',
  CURRENCY: 'USD',
  NUMBER_FORMAT: 'en-US'
};

// Error Messages
export const ERROR_MESSAGES = {
  NETWORK_ERROR: 'Network connection error. Please check your connection.',
  SERVER_ERROR: 'Server error occurred. Please try again later.',
  AUTHENTICATION_ERROR: 'Authentication failed. Please log in again.',
  VALIDATION_ERROR: 'Please check your input and try again.',
  PERMISSION_ERROR: 'You do not have permission to perform this action.',
  NOT_FOUND_ERROR: 'The requested resource was not found.',
  TIMEOUT_ERROR: 'Request timed out. Please try again.',
  UNKNOWN_ERROR: 'An unknown error occurred. Please contact support.'
};

// Success Messages
export const SUCCESS_MESSAGES = {
  DATA_SAVED: 'Data saved successfully.',
  DATA_UPDATED: 'Data updated successfully.',
  DATA_DELETED: 'Data deleted successfully.',
  ACTION_COMPLETED: 'Action completed successfully.',
  EXPORT_COMPLETED: 'Export completed successfully.',
  IMPORT_COMPLETED: 'Import completed successfully.'
};

// Route Paths
export const ROUTES = {
  HOME: '/',
  DASHBOARD: '/dashboard',
  PACKETS: '/packets',
  THREATS: '/threats',
  PERFORMANCE: '/performance',
  PROTOCOLS: '/protocols',
  SETTINGS: '/settings',
  REPORTS: '/reports',
  ALERTS: '/alerts'
};

// Component States
export const COMPONENT_STATES = {
  LOADING: 'loading',
  LOADED: 'loaded',
  ERROR: 'error',
  EMPTY: 'empty'
};

// Feature Flags
export const FEATURE_FLAGS = {
  REAL_TIME_UPDATES: true,
  ADVANCED_FILTERING: true,
  EXPORT_FUNCTIONALITY: true,
  THREAT_INTELLIGENCE: true,
  ML_ANOMALY_DETECTION: true,
  GEO_LOCATION: true,
  DARK_MODE: true
};