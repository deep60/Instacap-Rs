// protocolService.js - Protocol analysis and classification service

import { packetCaptureApi, analysisEngineApi } from './api';

// Protocol definitions and metadata
const PROTOCOL_DEFINITIONS = {
  // Layer 2 Protocols
  ETHERNET: {
    name: 'Ethernet',
    layer: 2,
    description: 'Ethernet frame protocol',
    color: '#6B7280',
    category: 'datalink',
    riskLevel: 'low',
    defaultPorts: [],
  },
  ARP: {
    name: 'Address Resolution Protocol',
    layer: 2,
    description: 'Maps IP addresses to MAC addresses',
    color: '#9CA3AF',
    category: 'network',
    riskLevel: 'medium',
    defaultPorts: [],
    vulnerabilities: ['ARP spoofing', 'ARP poisoning'],
  },

  // Layer 3 Protocols
  IP: {
    name: 'Internet Protocol',
    layer: 3,
    description: 'Network layer protocol for packet routing',
    color: '#4B5563',
    category: 'network',
    riskLevel: 'low',
    defaultPorts: [],
  },
  ICMP: {
    name: 'Internet Control Message Protocol',
    layer: 3,
    description: 'Network diagnostic and error reporting',
    color: '#6B7280',
    category: 'network',
    riskLevel: 'medium',
    defaultPorts: [],
    vulnerabilities: ['ICMP flood', 'Ping of death'],
  },
  IPV6: {
    name: 'Internet Protocol Version 6',
    layer: 3,
    description: 'Next generation IP protocol',
    color: '#374151',
    category: 'network',
    riskLevel: 'low',
    defaultPorts: [],
  },

  // Layer 4 Protocols
  TCP: {
    name: 'Transmission Control Protocol',
    layer: 4,
    description: 'Reliable connection-oriented transport',
    color: '#3B82F6',
    category: 'transport',
    riskLevel: 'low',
    defaultPorts: [],
    vulnerabilities: ['SYN flood', 'TCP hijacking'],
  },
  UDP: {
    name: 'User Datagram Protocol',
    layer: 4,
    description: 'Connectionless transport protocol',
    color: '#10B981',
    category: 'transport',
    riskLevel: 'medium',
    defaultPorts: [],
    vulnerabilities: ['UDP flood', 'UDP amplification'],
  },

  // Application Layer Protocols
  HTTP: {
    name: 'Hypertext Transfer Protocol',
    layer: 7,
    description: 'Web communication protocol',
    color: '#8B5CF6',
    category: 'web',
    riskLevel: 'medium',
    defaultPorts: [80, 8080, 8000],
    vulnerabilities: ['HTTP injection', 'Cross-site scripting'],
  },
  HTTPS: {
    name: 'HTTP Secure',
    layer: 7,
    description: 'Encrypted web communication',
    color: '#6366F1',
    category: 'web',
    riskLevel: 'low',
    defaultPorts: [443, 8443],
    vulnerabilities: ['SSL/TLS vulnerabilities'],
  },
  DNS: {
    name: 'Domain Name System',
    layer: 7,
    description: 'Domain name resolution',
    color: '#F59E0B',
    category: 'network',
    riskLevel: 'high',
    defaultPorts: [53],
    vulnerabilities: ['DNS poisoning', 'DNS amplification', 'DNS tunneling'],
  },
  FTP: {
    name: 'File Transfer Protocol',
    layer: 7,
    description: 'File transfer service',
    color: '#EF4444',
    category: 'file_transfer',
    riskLevel: 'high',
    defaultPorts: [21, 20],
    vulnerabilities: ['FTP bounce', 'Anonymous access', 'Plaintext credentials'],
  },
  SSH: {
    name: 'Secure Shell',
    layer: 7,
    description: 'Encrypted remote access',
    color: '#06B6D4',
    category: 'remote_access',
    riskLevel: 'medium',
    defaultPorts: [22],
    vulnerabilities: ['Brute force attacks', 'Key-based attacks'],
  },
  TELNET: {
    name: 'Telnet',
    layer: 7,
    description: 'Unencrypted remote access',
    color: '#F97316',
    category: 'remote_access',
    riskLevel: 'critical',
    defaultPorts: [23],
    vulnerabilities: ['Plaintext credentials', 'Session hijacking'],
  },
  SMTP: {
    name: 'Simple Mail Transfer Protocol',
    layer: 7,
    description: 'Email transmission',
    color: '#EC4899',
    category: 'email',
    riskLevel: 'medium',
    defaultPorts: [25, 587, 465],
    vulnerabilities: ['Email spoofing', 'SMTP relay abuse'],
  },
  POP3: {
    name: 'Post Office Protocol v3',
    layer: 7,
    description: 'Email retrieval',
    color: '#84CC16',
    category: 'email',
    riskLevel: 'medium',
    defaultPorts: [110, 995],
    vulnerabilities: ['Plaintext authentication'],
  },
  IMAP: {
    name: 'Internet Message Access Protocol',
    layer: 7,
    description: 'Email access and management',
    color: '#14B8A6',
    category: 'email',
    riskLevel: 'medium',
    defaultPorts: [143, 993],
    vulnerabilities: ['Authentication bypass'],
  },
  DHCP: {
    name: 'Dynamic Host Configuration Protocol',
    layer: 7,
    description: 'Automatic IP configuration',
    color: '#D1D5DB',
    category: 'network',
    riskLevel: 'high',
    defaultPorts: [67, 68],
    vulnerabilities: ['DHCP spoofing', 'Rogue DHCP server'],
  },
  SNMP: {
    name: 'Simple Network Management Protocol',
    layer: 7,
    description: 'Network device management',
    color: '#A78BFA',
    category: 'management',
    riskLevel: 'high',
    defaultPorts: [161, 162],
    vulnerabilities: ['Community string attacks', 'Information disclosure'],
  },
  NTP: {
    name: 'Network Time Protocol',
    layer: 7,
    description: 'Time synchronization',
    color: '#F472B6',
    category: 'network',
    riskLevel: 'medium',
    defaultPorts: [123],
    vulnerabilities: ['NTP amplification'],
  },
};

// Protocol analysis utilities
class ProtocolAnalyzer {
  static getProtocolInfo(protocolName) {
    const protocol = protocolName.toUpperCase();
    return PROTOCOL_DEFINITIONS[protocol] || {
      name: protocolName,
      layer: 'unknown',
      description: 'Unknown protocol',
      color: '#6B7280',
      category: 'unknown',
      riskLevel: 'unknown',
      defaultPorts: [],
    };
  }

  static categorizeProtocols(protocols) {
    const categories = {};
    
    protocols.forEach(protocol => {
      const info = this.getProtocolInfo(protocol.name);
      const category = info.category;
      
      if (!categories[category]) {
        categories[category] = {
          name: category,
          protocols: [],
          totalPackets: 0,
          totalBytes: 0,
        };
      }
      
      categories[category].protocols.push({
        ...protocol,
        ...info,
      });
      categories[category].totalPackets += protocol.packets || 0;
      categories[category].totalBytes += protocol.bytes || 0;
    });

    return Object.values(categories);
  }

  static analyzeProtocolRisks(protocols) {
    const riskLevels = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
    const vulnerabilities = [];

    protocols.forEach(protocol => {
      const info = this.getProtocolInfo(protocol.name);
      riskLevels[info.riskLevel]++;
      
      if (info.vulnerabilities) {
        vulnerabilities.push({
          protocol: protocol.name,
          vulnerabilities: info.vulnerabilities,
          traffic: protocol.packets || 0,
        });
      }
    });

    return { riskLevels, vulnerabilities };
  }

  static detectAnomalousProtocols(protocols, baseline = {}) {
    const anomalies = [];

    protocols.forEach(protocol => {
      const info = this.getProtocolInfo(protocol.name);
      const baselineTraffic = baseline[protocol.name] || 0;
      const currentTraffic = protocol.packets || 0;
      
      // Detect unusual traffic volume
      if (baselineTraffic > 0) {
        const deviation = Math.abs(currentTraffic - baselineTraffic) / baselineTraffic;
        if (deviation > 2.0) { // 200% deviation threshold
          anomalies.push({
            type: 'traffic_deviation',
            protocol: protocol.name,
            expected: baselineTraffic,
            actual: currentTraffic,
            severity: deviation > 5.0 ? 'high' : 'medium',
          });
        }
      }

      // Detect protocols on unusual ports
      if (info.defaultPorts.length > 0 && protocol.ports) {
        const unusualPorts = protocol.ports.filter(port => 
          !info.defaultPorts.includes(port)
        );
        
        if (unusualPorts.length > 0) {
          anomalies.push({
            type: 'unusual_ports',
            protocol: protocol.name,
            unusualPorts,
            severity: 'medium',
          });
        }
      }
    });

    return anomalies;
  }

  static generateProtocolInsights(protocols, timeRange) {
    const insights = [];
    const totalPackets = protocols.reduce((sum, p) => sum + (p.packets || 0), 0);
    
    // Top protocols by traffic
    const sortedByTraffic = [...protocols].sort((a, b) => (b.packets || 0) - (a.packets || 0));
    const topProtocol = sortedByTraffic[0];
    
    if (topProtocol) {
      const percentage = ((topProtocol.packets / totalPackets) * 100).toFixed(1);
      insights.push({
        type: 'dominant_protocol',
        message: `${topProtocol.name} accounts for ${percentage}% of all traffic`,
        severity: percentage > 80 ? 'warning' : 'info',
      });
    }

    // Security concerns
    const highRiskProtocols = protocols.filter(p => {
      const info = this.getProtocolInfo(p.name);
      return ['critical', 'high'].includes(info.riskLevel);
    });

    if (highRiskProtocols.length > 0) {
      insights.push({
        type: 'security_concern',
        message: `${highRiskProtocols.length} high-risk protocols detected`,
        protocols: highRiskProtocols.map(p => p.name),
        severity: 'warning',
      });
    }

    // Encrypted vs unencrypted traffic
    const encryptedProtocols = ['HTTPS', 'SSH', 'TLS', 'SSL'];
    const encryptedTraffic = protocols
      .filter(p => encryptedProtocols.includes(p.name.toUpperCase()))
      .reduce((sum, p) => sum + (p.packets || 0), 0);
    
    const encryptionRatio = totalPackets > 0 ? (encryptedTraffic / totalPackets) * 100 : 0;
    
    insights.push({
      type: 'encryption_ratio',
      message: `${encryptionRatio.toFixed(1)}% of traffic is encrypted`,
      severity: encryptionRatio < 50 ? 'warning' : 'good',
    });

    return insights;
  }
}

// Main protocol service class
class ProtocolService {
  constructor() {
    this.cache = new Map();
    this.cacheTimeout = 60000; // 1 minute
    this.baseline = null;
  }

  // Cache management
  _getCacheKey(endpoint, params) {
    return `${endpoint}_${JSON.stringify(params)}`;
  }

  _setCache(key, data) {
    this.cache.set(key, {
      data,
      timestamp: Date.now(),
    });
  }

  _getCache(key) {
    const cached = this.cache.get(key);
    if (cached && Date.now() - cached.timestamp < this.cacheTimeout) {
      return cached.data;
    }
    this.cache.delete(key);
    return null;
  }

  // Protocol analysis methods
  async getProtocolDistribution(timeRange = '1h', includeDetails = true) {
    const cacheKey = this._getCacheKey('protocol_distribution', { timeRange, includeDetails });
    const cached = this._getCache(cacheKey);
    if (cached) return cached;

    try {
      const response = await analysisEngineApi.get('/protocols/distribution', {
        timeRange,
        includeDetails,
      });

      const enrichedProtocols = response.protocols.map(protocol => ({
        ...protocol,
        ...ProtocolAnalyzer.getProtocolInfo(protocol.name),
        percentage: ((protocol.packets / response.totalPackets) * 100).toFixed(2),
        bytesFormatted: this._formatBytes(protocol.bytes),
      }));

      const result = {
        ...response,
        protocols: enrichedProtocols,
        categories: ProtocolAnalyzer.categorizeProtocols(enrichedProtocols),
        riskAnalysis: ProtocolAnalyzer.analyzeProtocolRisks(enrichedProtocols),
        insights: ProtocolAnalyzer.generateProtocolInsights(enrichedProtocols, timeRange),
      };

      this._setCache(cacheKey, result);
      return result;
    } catch (error) {
      console.error('Error fetching protocol distribution:', error);
      throw error;
    }
  }

  async getProtocolTimeline(timeRange = '24h', interval = '1h') {
    const cacheKey = this._getCacheKey('protocol_timeline', { timeRange, interval });
    const cached = this._getCache(cacheKey);
    if (cached) return cached;

    try {
      const response = await analysisEngineApi.get('/protocols/timeline', {
        timeRange,
        interval,
      });

      const processedTimeline = response.timeline.map(dataPoint => ({
        ...dataPoint,
        protocols: dataPoint.protocols.map(protocol => ({
          ...protocol,
          ...ProtocolAnalyzer.getProtocolInfo(protocol.name),
        })),
      }));

      const result = {
        ...response,
        timeline: processedTimeline,
      };

      this._setCache(cacheKey, result);
      return result;
    } catch (error) {
      console.error('Error fetching protocol timeline:', error);
      throw error;
    }
  }

  async getProtocolDetails(protocolName, timeRange = '1h') {
    const cacheKey = this._getCacheKey('protocol_details', { protocolName, timeRange });
    const cached = this._getCache(cacheKey);
    if (cached) return cached;

    try {
      const response = await analysisEngineApi.get(`/protocols/${protocolName}`, {
        timeRange,
      });

      const protocolInfo = ProtocolAnalyzer.getProtocolInfo(protocolName);
      const result = {
        ...response,
        ...protocolInfo,
        conversations: response.conversations?.map(conv => ({
          ...conv,
          bytesFormatted: this._formatBytes(conv.bytes),
        })) || [],
        ports: response.ports?.map(port => ({
          ...port,
          isDefault: protocolInfo.defaultPorts.includes(port.number),
          bytesFormatted: this._formatBytes(port.bytes),
        })) || [],
      };

      this._setCache(cacheKey, result);
      return result;
    } catch (error) {
      console.error('Error fetching protocol details:', error);
      throw error;
    }
  }

  async analyzeProtocolAnomalies(timeRange = '24h') {
    try {
      const currentDistribution = await this.getProtocolDistribution(timeRange, false);
      
      if (!this.baseline) {
        await this.updateBaseline();
      }

      const anomalies = ProtocolAnalyzer.detectAnomalousProtocols(
        currentDistribution.protocols,
        this.baseline
      );

      return {
        anomalies,
        totalProtocols: currentDistribution.protocols.length,
        analysisTimestamp: new Date().toISOString(),
      };
    } catch (error) {
      console.error('Error analyzing protocol anomalies:', error);
      throw error;
    }
  }

  async getProtocolSecurity(timeRange = '1h') {
    const cacheKey = this._getCacheKey('protocol_security', { timeRange });
    const cached = this._getCache(cacheKey);
    if (cached) return cached;

    try {
      const distribution = await this.getProtocolDistribution(timeRange, true);
      const securityAnalysis = await analysisEngineApi.get('/protocols/security', {
        timeRange,
      });

      const vulnerableProtocols = distribution.protocols
        .filter(protocol => {
          const info = ProtocolAnalyzer.getProtocolInfo(protocol.name);
          return info.vulnerabilities && info.vulnerabilities.length > 0;
        })
        .map(protocol => {
          const info = ProtocolAnalyzer.getProtocolInfo(protocol.name);
          return {
            ...protocol,
            vulnerabilities: info.vulnerabilities,
            threatLevel: this._calculateThreatLevel(protocol, info),
          };
        });

      const result = {
        ...securityAnalysis,
        vulnerableProtocols,
        riskSummary: distribution.riskAnalysis,
        recommendations: this._generateSecurityRecommendations(vulnerableProtocols),
      };

      this._setCache(cacheKey, result);
      return result;
    } catch (error) {
      console.error('Error fetching protocol security analysis:', error);
      throw error;
    }
  }

  async getProtocolPerformance(timeRange = '1h') {
    const cacheKey = this._getCacheKey('protocol_performance', { timeRange });
    const cached = this._getCache(cacheKey);
    if (cached) return cached;

    try {
      const performance = await analysisEngineApi.get('/protocols/performance', {
        timeRange,
      });

      const enrichedMetrics = performance.protocols.map(protocol => ({
        ...protocol,
        ...ProtocolAnalyzer.getProtocolInfo(protocol.name),
        averageLatency: protocol.totalLatency / protocol.packets,
        throughput: protocol.bytes / (performance.duration / 1000), // bytes per second
        efficiency: this._calculateEfficiency(protocol),
      }));

      const result = {
        ...performance,
        protocols: enrichedMetrics,
        overallMetrics: {
          averageLatency: enrichedMetrics.reduce((sum, p) => sum + p.averageLatency, 0) / enrichedMetrics.length,
          totalThroughput: enrichedMetrics.reduce((sum, p) => sum + p.throughput, 0),
          averageEfficiency: enrichedMetrics.reduce((sum, p) => sum + p.efficiency, 0) / enrichedMetrics.length,
        },
      };

      this._setCache(cacheKey, result);
      return result;
    } catch (error) {
      console.error('Error fetching protocol performance:', error);
      throw error;
    }
  }

  // Protocol filtering and search
  async searchProtocols(query, filters = {}) {
    try {
      const searchParams = {
        query,
        ...filters,
      };

      const results = await analysisEngineApi.get('/protocols/search', searchParams);
      
      return {
        ...results,
        protocols: results.protocols.map(protocol => ({
          ...protocol,
          ...ProtocolAnalyzer.getProtocolInfo(protocol.name),
        })),
      };
    } catch (error) {
      console.error('Error searching protocols:', error);
      throw error;
    }
  }

  // Baseline management
  async updateBaseline(timeRange = '7d') {
    try {
      const baselineData = await analysisEngineApi.get('/protocols/baseline', {
        timeRange,
      });

      this.baseline = baselineData.protocols.reduce((acc, protocol) => {
        acc[protocol.name] = protocol.averagePackets;
        return acc;
      }, {});

      return this.baseline;
    } catch (error) {
      console.error('Error updating protocol baseline:', error);
      throw error;
    }
  }

  // Export functionality
  async exportProtocolData(timeRange = '1h', format = 'json') {
    try {
      const distribution = await this.getProtocolDistribution(timeRange, true);
      
      switch (format.toLowerCase()) {
        case 'csv':
          return this._exportToCsv(distribution.protocols);
        case 'json':
          return JSON.stringify(distribution, null, 2);
        case 'xml':
          return this._exportToXml(distribution);
        default:
          throw new Error(`Unsupported export format: ${format}`);
      }
    } catch (error) {
      console.error('Error exporting protocol data:', error);
      throw error;
    }
  }

  // Real-time protocol monitoring
  subscribeToProtocolUpdates(callback, filters = {}) {
    const ws = new WebSocket('ws://localhost:8081/protocols/stream');
    
    ws.onopen = () => {
      ws.send(JSON.stringify({ type: 'subscribe', filters }));
    };

    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      if (data.type === 'protocol_update') {
        const enrichedData = {
          ...data,
          protocols: data.protocols.map(protocol => ({
            ...protocol,
            ...ProtocolAnalyzer.getProtocolInfo(protocol.name),
          })),
        };
        callback(enrichedData);
      }
    };

    return () => ws.close();
  }

  // Utility methods
  _formatBytes(bytes) {
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    if (bytes === 0) return '0 B';
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return `${(bytes / Math.pow(1024, i)).toFixed(2)} ${sizes[i]}`;
  }

  _calculateThreatLevel(protocol, protocolInfo) {
    let score = 0;
    
    // Base score from risk level
    const riskScores = { critical: 10, high: 7, medium: 4, low: 1, unknown: 2 };
    score += riskScores[protocolInfo.riskLevel] || 0;
    
    // Traffic volume factor
    const trafficScore = Math.min(protocol.packets / 1000, 5);
    score += trafficScore;
    
    // Vulnerability count
    score += (protocolInfo.vulnerabilities?.length || 0) * 2;
    
    if (score >= 15) return 'critical';
    if (score >= 10) return 'high';
    if (score >= 5) return 'medium';
    return 'low';
  }

  _calculateEfficiency(protocol) {
    // Simple efficiency calculation based on payload vs overhead ratio
    const headerOverhead = protocol.packets * 40; // Estimated header overhead
    const efficiency = protocol.bytes / (protocol.bytes + headerOverhead);
    return Math.round(efficiency * 100);
  }

  _generateSecurityRecommendations(vulnerableProtocols) {
    const recommendations = [];
    
    vulnerableProtocols.forEach(protocol => {
      if (protocol.name === 'TELNET') {
        recommendations.push({
          protocol: protocol.name,
          severity: 'critical',
          message: 'Replace Telnet with SSH for secure remote access',
          action: 'migrate_to_ssh',
        });
      }
      
      if (protocol.name === 'FTP') {
        recommendations.push({
          protocol: protocol.name,
          severity: 'high',
          message: 'Use SFTP or FTPS instead of plain FTP',
          action: 'use_secure_ftp',
        });
      }
      
      if (protocol.name === 'HTTP' && protocol.packets > 1000) {
        recommendations.push({
          protocol: protocol.name,
          severity: 'medium',
          message: 'Consider migrating HTTP traffic to HTTPS',
          action: 'enable_https',
        });
      }
    });
    
    return recommendations;
  }

  _exportToCsv(protocols) {
    const headers = ['Protocol,Packets,Bytes,Layer,Category,Risk Level,Description'];
    const rows = protocols.map(p => 
      `${p.name},${p.packets},${p.bytes},${p.layer},${p.category},${p.riskLevel},"${p.description}"`
    );
    return [headers, ...rows].join('\n');
  }

  _exportToXml(data) {
    let xml = '<?xml version="1.0" encoding="UTF-8"?>\n<protocolAnalysis>\n';
    data.protocols.forEach(protocol => {
      xml += `  <protocol name="${protocol.name}" layer="${protocol.layer}" risk="${protocol.riskLevel}">\n`;
      xml += `    <packets>${protocol.packets}</packets>\n`;
      xml += `    <bytes>${protocol.bytes}</bytes>\n`;
      xml += `    <category>${protocol.category}</category>\n`;
      xml += `    <description>${protocol.description}</description>\n`;
      xml += '  </protocol>\n';
    });
    xml += '</protocolAnalysis>';
    return xml;
  }

  // Clear cache
  clearCache() {
    this.cache.clear();
  }

  // Get all available protocol definitions
  getProtocolDefinitions() {
    return PROTOCOL_DEFINITIONS;
  }
}

// Export singleton instance
export const protocolService = new ProtocolService();
export { ProtocolAnalyzer, PROTOCOL_DEFINITIONS };
export default protocolService;