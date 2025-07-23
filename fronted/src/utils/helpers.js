    /**
     * Convert bytes to human readable format
     */
    export const formatBytes = (bytes, decimals = 2) => {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB'];
    
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
    };

    /**
     * Format timestamp to readable date/time
     */
    export const formatTimestamp = (timestamp, includeMs = true) => {
    const date = new Date(timestamp);
    const options = {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false
    };
    
    let formatted = date.toLocaleString('en-US', options);
    
    if (includeMs) {
        const ms = date.getMilliseconds().toString().padStart(3, '0');
        formatted += `.${ms}`;
    }
    
    return formatted;
    };

    /**
     * Format duration in milliseconds to human readable
     */
    export const formatDuration = (ms) => {
    if (ms < 1000) return `${ms}ms`;
    if (ms < 60000) return `${(ms / 1000).toFixed(2)}s`;
    if (ms < 3600000) return `${(ms / 60000).toFixed(2)}m`;
    return `${(ms / 3600000).toFixed(2)}h`;
    };

    /**
     * Convert MAC address to standard format
     */
    export const formatMacAddress = (mac) => {
    if (!mac) return 'N/A';
    
    // Remove any existing separators and convert to uppercase
    const cleanMac = mac.replace(/[:-]/g, '').toUpperCase();
    
    // Add colons every 2 characters
    return cleanMac.match(/.{2}/g)?.join(':') || mac;
    };

    /**
     * Validate IP address format
     */
    export const isValidIPv4 = (ip) => {
    const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    return ipv4Regex.test(ip);
    };

    export const isValidIPv6 = (ip) => {
    const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
    return ipv6Regex.test(ip);
    };

    /**
     * Get protocol color for visualization
     */
    export const getProtocolColor = (protocol) => {
    const protocolColors = {
        'HTTP': '#3B82F6',    // Blue
        'HTTPS': '#10B981',   // Green
        'TCP': '#8B5CF6',     // Purple
        'UDP': '#F59E0B',     // Amber
        'ICMP': '#EF4444',    // Red
        'DNS': '#06B6D4',     // Cyan
        'FTP': '#84CC16',     // Lime
        'SSH': '#6366F1',     // Indigo
        'SMTP': '#EC4899',    // Pink
        'SNMP': '#F97316',    // Orange
        'ARP': '#14B8A6',     // Teal
        'DHCP': '#A855F7',    // Violet
        'TLS': '#059669',     // Emerald
        'UNKNOWN': '#6B7280'  // Gray
    };
    
    return protocolColors[protocol?.toUpperCase()] || protocolColors['UNKNOWN'];
    };

    /**
     * Get threat severity color
     */
    export const getThreatSeverityColor = (severity) => {
    const severityColors = {
        'LOW': '#10B981',     // Green
        'MEDIUM': '#F59E0B',  // Amber
        'HIGH': '#EF4444',    // Red
        'CRITICAL': '#DC2626' // Dark Red
    };
    
    return severityColors[severity?.toUpperCase()] || severityColors['LOW'];
    };

    /**
     * Calculate packet rate (packets per second)
     */
    export const calculatePacketRate = (packets, timeWindow) => {
    if (!timeWindow || timeWindow === 0) return 0;
    return Math.round(packets / (timeWindow / 1000));
    };

    /**
     * Calculate bandwidth utilization
     */
    export const calculateBandwidth = (bytes, timeWindow) => {
    if (!timeWindow || timeWindow === 0) return 0;
    // Convert to bits per second
    return (bytes * 8) / (timeWindow / 1000);
    };

    /**
     * Parse port number and get service name
     */
    export const getServiceByPort = (port) => {
    const commonPorts = {
        20: 'FTP-DATA',
        21: 'FTP',
        22: 'SSH',
        23: 'TELNET',
        25: 'SMTP',
        53: 'DNS',
        67: 'DHCP',
        68: 'DHCP',
        69: 'TFTP',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP',
        161: 'SNMP',
        162: 'SNMP-TRAP',
        443: 'HTTPS',
        993: 'IMAPS',
        995: 'POP3S'
    };
    
    return commonPorts[port] || `Port ${port}`;
    };

    /**
     * Extract domain from URL or hostname
     */
    export const extractDomain = (url) => {
    if (!url) return '';
    
    try {
        // Remove protocol if present
        let domain = url.replace(/^https?:\/\//, '');
        
        // Remove path and query parameters
        domain = domain.split('/')[0].split('?')[0];
        
        // Remove port number
        domain = domain.split(':')[0];
        
        return domain;
    } catch (error) {
        return url;
    }
    };

    /**
     * Check if IP is in private range
     */
    export const isPrivateIP = (ip) => {
    if (!isValidIPv4(ip)) return false;
    
    const parts = ip.split('.').map(Number);
    
    // 10.0.0.0/8
    if (parts[0] === 10) return true;
    
    // 172.16.0.0/12
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    
    // 192.168.0.0/16
    if (parts[0] === 192 && parts[1] === 168) return true;
    
    // 127.0.0.0/8 (loopback)
    if (parts[0] === 127) return true;
    
    return false;
    };

    /**
     * Generate unique packet ID
     */
    export const generatePacketId = (packet) => {
    const { timestamp, srcIp, dstIp, srcPort, dstPort, protocol } = packet;
    return `${timestamp}_${srcIp}_${dstIp}_${srcPort}_${dstPort}_${protocol}`;
    };

    /**
     * Calculate network latency
     */
    export const calculateLatency = (sendTime, receiveTime) => {
    if (!sendTime || !receiveTime) return 0;
    return Math.max(0, receiveTime - sendTime);
    };

    /**
     * Format packet payload for display
     */
    export const formatPayload = (payload, maxLength = 100) => {
    if (!payload) return '';
    
    // Convert to hex if binary data
    if (typeof payload !== 'string') {
        payload = Array.from(payload)
        .map(byte => byte.toString(16).padStart(2, '0'))
        .join(' ');
    }
    
    if (payload.length > maxLength) {
        return `${payload.substring(0, maxLength)}...`;
    }
    
    return payload;
    };

    /**
     * Check if traffic pattern is suspicious
     */
    export const isSuspiciousTraffic = (packet) => {
    const { srcPort, dstPort, protocol, payloadSize } = packet;
    
    // Common suspicious patterns
    const suspiciousPatterns = [
        // Port scanning (connection to multiple high ports)
        dstPort > 1024 && payloadSize < 100,
        
        // Large payload on unusual ports
        payloadSize > 10000 && ![80, 443, 21, 22].includes(dstPort),
        
        // ICMP floods
        protocol === 'ICMP' && payloadSize > 1000,
        
        // Suspicious UDP traffic
        protocol === 'UDP' && dstPort !== 53 && payloadSize > 5000
    ];
    
    return suspiciousPatterns.some(pattern => pattern);
    };

    /**
     * Group packets by time interval
     */
    export const groupPacketsByInterval = (packets, intervalMs = 1000) => {
    const groups = {};
    
    packets.forEach(packet => {
        const intervalStart = Math.floor(packet.timestamp / intervalMs) * intervalMs;
        
        if (!groups[intervalStart]) {
        groups[intervalStart] = [];
        }
        
        groups[intervalStart].push(packet);
    });
    
    return groups;
    };

    /**
     * Calculate traffic statistics
     */
    export const calculateTrafficStats = (packets) => {
    if (!packets || packets.length === 0) {
        return {
        totalPackets: 0,
        totalBytes: 0,
        averagePacketSize: 0,
        protocolDistribution: {},
        trafficRate: 0
        };
    }
    
    const totalPackets = packets.length;
    const totalBytes = packets.reduce((sum, p) => sum + (p.size || 0), 0);
    const averagePacketSize = Math.round(totalBytes / totalPackets);
    
    // Protocol distribution
    const protocolDistribution = packets.reduce((dist, packet) => {
        const protocol = packet.protocol || 'UNKNOWN';
        dist[protocol] = (dist[protocol] || 0) + 1;
        return dist;
    }, {});
    
    // Traffic rate (packets per second)
    const timeSpan = packets.length > 1 ? 
        Math.max(...packets.map(p => p.timestamp)) - Math.min(...packets.map(p => p.timestamp)) : 
        1000;
    const trafficRate = Math.round((totalPackets * 1000) / timeSpan);
    
    return {
        totalPackets,
        totalBytes,
        averagePacketSize,
        protocolDistribution,
        trafficRate
    };
    };

    /**
     * Debounce function for search/filter inputs
     */
    export const debounce = (func, wait, immediate = false) => {
    let timeout;
    
    return function executedFunction(...args) {
        const later = () => {
        timeout = null;
        if (!immediate) func(...args);
        };
        
        const callNow = immediate && !timeout;
        
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
        
        if (callNow) func(...args);
    };
    };

    /**
     * Deep clone object
     */
    export const deepClone = (obj) => {
    if (obj === null || typeof obj !== 'object') return obj;
    if (obj instanceof Date) return new Date(obj.getTime());
    if (obj instanceof Array) return obj.map(item => deepClone(item));
    if (typeof obj === 'object') {
        const cloned = {};
        Object.keys(obj).forEach(key => {
        cloned[key] = deepClone(obj[key]);
        });
        return cloned;
    }
    };

    /**
     * Sort packets by various criteria
     */
    export const sortPackets = (packets, sortBy, sortOrder = 'desc') => {
    const sortedPackets = [...packets];
    
    sortedPackets.sort((a, b) => {
        let aVal, bVal;
        
        switch (sortBy) {
        case 'timestamp':
            aVal = a.timestamp;
            bVal = b.timestamp;
            break;
        case 'size':
            aVal = a.size || 0;
            bVal = b.size || 0;
            break;
        case 'protocol':
            aVal = a.protocol || '';
            bVal = b.protocol || '';
            break;
        case 'srcIp':
            aVal = a.srcIp || '';
            bVal = b.srcIp || '';
            break;
        case 'dstIp':
            aVal = a.dstIp || '';
            bVal = b.dstIp || '';
            break;
        default:
            return 0;
        }
        
        if (typeof aVal === 'string') {
        return sortOrder === 'asc' ? 
            aVal.localeCompare(bVal) : 
            bVal.localeCompare(aVal);
        }
        
        return sortOrder === 'asc' ? aVal - bVal : bVal - aVal;
    });
    
    return sortedPackets;
    };