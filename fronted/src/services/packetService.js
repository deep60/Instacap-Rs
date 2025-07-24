import { packetCaptureApi, analysisEngineApi } from './api';

// Packet data processing utilities
class PacketProcessor {
  static formatPacketSize(bytes) {
    const sizes = ['B', 'KB', 'MB', 'GB'];
    if (bytes === 0) return '0 B';
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return `${(bytes / Math.pow(1024, i)).toFixed(2)} ${sizes[i]}`;
  }

  static formatTimestamp(timestamp) {
    return new Date(timestamp).toLocaleString();
  }

  static getProtocolColor(protocol) {
    const colors = {
      'TCP': '#3B82F6',
      'UDP': '#10B981',
      'HTTP': '#8B5CF6',
      'HTTPS': '#6366F1',
      'DNS': '#F59E0B',
      'FTP': '#EF4444',
      'SSH': '#06B6D4',
      'TELNET': '#F97316',
      'SMTP': '#EC4899',
      'POP3': '#84CC16',
      'IMAP': '#14B8A6',
      'ICMP': '#6B7280',
      'ARP': '#9CA3AF',
      'DHCP': '#D1D5DB',
    };
    return colors[protocol.toUpperCase()] || '#6B7280';
  }

  static classifyTraffic(packet) {
    const { protocol, sourcePort, destPort, flags } = packet;
    
    // Web traffic
    if ([80, 443, 8080, 8443].includes(sourcePort) || [80, 443, 8080, 8443].includes(destPort)) {
      return 'web';
    }
    
    // Email traffic
    if ([25, 110, 143, 465, 587, 993, 995].includes(sourcePort) || [25, 110, 143, 465, 587, 993, 995].includes(destPort)) {
      return 'email';
    }
    
    // File transfer
    if ([21, 22, 69].includes(sourcePort) || [21, 22, 69].includes(destPort)) {
      return 'file_transfer';
    }
    
    // DNS
    if (sourcePort === 53 || destPort === 53) {
      return 'dns';
    }
    
    // Database
    if ([1433, 3306, 5432, 1521, 27017].includes(sourcePort) || [1433, 3306, 5432, 1521, 27017].includes(destPort)) {
      return 'database';
    }
    
    return 'other';
  }
}

// Main packet service class
class PacketService {
  constructor() {
    this.cache = new Map();
    this.cacheTimeout = 30000; // 30 seconds
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

  // Packet retrieval methods
  async getPackets(filters = {}) {
    const {
      page = 1,
      limit = 100,
      protocol,
      sourceIp,
      destIp,
      sourcePort,
      destPort,
      startTime,
      endTime,
      sortBy = 'timestamp',
      sortOrder = 'desc',
    } = filters;

    const params = {
      page,
      limit,
      sortBy,
      sortOrder,
      ...(protocol && { protocol }),
      ...(sourceIp && { sourceIp }),
      ...(destIp && { destIp }),
      ...(sourcePort && { sourcePort }),
      ...(destPort && { destPort }),
      ...(startTime && { startTime }),
      ...(endTime && { endTime }),
    };

    const cacheKey = this._getCacheKey('packets', params);
    const cached = this._getCache(cacheKey);
    if (cached) return cached;

    try {
      const response = await packetCaptureApi.get('/packets', params);
      const processedData = {
        ...response,
        packets: response.packets.map(packet => ({
          ...packet,
          formattedSize: PacketProcessor.formatPacketSize(packet.size),
          formattedTimestamp: PacketProcessor.formatTimestamp(packet.timestamp),
          protocolColor: PacketProcessor.getProtocolColor(packet.protocol),
          trafficType: PacketProcessor.classifyTraffic(packet),
        })),
      };

      this._setCache(cacheKey, processedData);
      return processedData;
    } catch (error) {
      console.error('Error fetching packets:', error);
      throw error;
    }
  }

  async getPacketById(packetId) {
    const cacheKey = this._getCacheKey('packet', { id: packetId });
    const cached = this._getCache(cacheKey);
    if (cached) return cached;

    try {
      const packet = await packetCaptureApi.get(`/packets/${packetId}`);
      const processedPacket = {
        ...packet,
        formattedSize: PacketProcessor.formatPacketSize(packet.size),
        formattedTimestamp: PacketProcessor.formatTimestamp(packet.timestamp),
        protocolColor: PacketProcessor.getProtocolColor(packet.protocol),
        trafficType: PacketProcessor.classifyTraffic(packet),
        hexDump: this._formatHexDump(packet.payload),
        decodedPayload: this._decodePayload(packet.payload, packet.protocol),
      };

      this._setCache(cacheKey, processedPacket);
      return processedPacket;
    } catch (error) {
      console.error('Error fetching packet details:', error);
      throw error;
    }
  }

  // Packet analysis methods
  async analyzePacket(packetId) {
    try {
      const analysis = await analysisEngineApi.post('/analyze/packet', { packetId });
      return {
        ...analysis,
        riskLevel: this._calculateRiskLevel(analysis),
        suggestions: this._generateSuggestions(analysis),
      };
    } catch (error) {
      console.error('Error analyzing packet:', error);
      throw error;
    }
  }

  async getPacketFlow(packetId) {
    try {
      const flow = await analysisEngineApi.get(`/packets/${packetId}/flow`);
      return {
        ...flow,
        packets: flow.packets.map(packet => ({
          ...packet,
          formattedSize: PacketProcessor.formatPacketSize(packet.size),
          formattedTimestamp: PacketProcessor.formatTimestamp(packet.timestamp),
          protocolColor: PacketProcessor.getProtocolColor(packet.protocol),
        })),
      };
    } catch (error) {
      console.error('Error fetching packet flow:', error);
      throw error;
    }
  }

  // Statistical methods
  async getPacketStatistics(timeRange = '1h') {
    const cacheKey = this._getCacheKey('packet_stats', { timeRange });
    const cached = this._getCache(cacheKey);
    if (cached) return cached;

    try {
      const stats = await packetCaptureApi.get('/packets/statistics', { timeRange });
      const processedStats = {
        ...stats,
        totalSize: PacketProcessor.formatPacketSize(stats.totalBytes),
        averageSize: PacketProcessor.formatPacketSize(stats.averagePacketSize),
        protocolDistribution: stats.protocolDistribution.map(item => ({
          ...item,
          color: PacketProcessor.getProtocolColor(item.protocol),
        })),
      };

      this._setCache(cacheKey, processedStats);
      return processedStats;
    } catch (error) {
      console.error('Error fetching packet statistics:', error);
      throw error;
    }
  }

  async getTopConversations(limit = 10, timeRange = '1h') {
    try {
      const conversations = await analysisEngineApi.get('/traffic/conversations', {
        limit,
        timeRange,
      });

      return conversations.map(conv => ({
        ...conv,
        totalBytes: PacketProcessor.formatPacketSize(conv.bytes),
        avgPacketSize: PacketProcessor.formatPacketSize(conv.bytes / conv.packets),
      }));
    } catch (error) {
      console.error('Error fetching top conversations:', error);
      throw error;
    }
  }

  // Search and filtering
  async searchPackets(searchTerm, filters = {}) {
    const searchParams = {
      query: searchTerm,
      ...filters,
    };

    try {
      const results = await packetCaptureApi.get('/packets/search', searchParams);
      return {
        ...results,
        packets: results.packets.map(packet => ({
          ...packet,
          formattedSize: PacketProcessor.formatPacketSize(packet.size),
          formattedTimestamp: PacketProcessor.formatTimestamp(packet.timestamp),
          protocolColor: PacketProcessor.getProtocolColor(packet.protocol),
          trafficType: PacketProcessor.classifyTraffic(packet),
        })),
      };
    } catch (error) {
      console.error('Error searching packets:', error);
      throw error;
    }
  }

  // Export functionality
  async exportPackets(filters = {}, format = 'pcap') {
    try {
      const exportParams = {
        ...filters,
        format,
      };

      const response = await packetCaptureApi.get('/packets/export', exportParams);
      return response;
    } catch (error) {
      console.error('Error exporting packets:', error);
      throw error;
    }
  }

  // Real-time packet streaming
  subscribeToPackets(callback, filters = {}) {
    // This would typically use WebSocket connection
    // Implementation depends on your WebSocket service
    const ws = new WebSocket(`ws://localhost:8080/packets/stream`);
    
    ws.onopen = () => {
      ws.send(JSON.stringify({ type: 'subscribe', filters }));
    };

    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      if (data.type === 'packet') {
        const processedPacket = {
          ...data.packet,
          formattedSize: PacketProcessor.formatPacketSize(data.packet.size),
          formattedTimestamp: PacketProcessor.formatTimestamp(data.packet.timestamp),
          protocolColor: PacketProcessor.getProtocolColor(data.packet.protocol),
          trafficType: PacketProcessor.classifyTraffic(data.packet),
        };
        callback(processedPacket);
      }
    };

    return () => ws.close();
  }

  // Utility methods
  _formatHexDump(payload) {
    if (!payload) return '';
    
    const hex = payload.match(/.{1,2}/g).join(' ');
    const ascii = payload.replace(/[^\x20-\x7E]/g, '.');
    
    return { hex, ascii };
  }

  _decodePayload(payload, protocol) {
    try {
      switch (protocol.toUpperCase()) {
        case 'HTTP':
          return this._decodeHttpPayload(payload);
        case 'DNS':
          return this._decodeDnsPayload(payload);
        default:
          return { type: 'raw', data: payload };
      }
    } catch (error) {
      return { type: 'error', message: 'Failed to decode payload' };
    }
  }

  _decodeHttpPayload(payload) {
    const text = atob(payload);
    const lines = text.split('\r\n');
    const requestLine = lines[0];
    const headers = {};
    let body = '';
    let inBody = false;

    for (let i = 1; i < lines.length; i++) {
      if (lines[i] === '') {
        inBody = true;
        continue;
      }
      
      if (inBody) {
        body += lines[i] + '\n';
      } else {
        const [key, value] = lines[i].split(': ');
        if (key && value) {
          headers[key] = value;
        }
      }
    }

    return {
      type: 'http',
      requestLine,
      headers,
      body: body.trim(),
    };
  }

  _decodeDnsPayload(payload) {
    // Simplified DNS payload decoding
    return {
      type: 'dns',
      data: 'DNS query/response data',
    };
  }

  _calculateRiskLevel(analysis) {
    const { threats, anomalies, suspiciousPatterns } = analysis;
    let score = 0;

    score += threats.length * 10;
    score += anomalies.length * 5;
    score += suspiciousPatterns.length * 3;

    if (score >= 30) return 'high';
    if (score >= 15) return 'medium';
    if (score >= 5) return 'low';
    return 'none';
  }

  _generateSuggestions(analysis) {
    const suggestions = [];
    
    if (analysis.threats.length > 0) {
      suggestions.push('Review threat indicators and consider blocking source');
    }
    
    if (analysis.anomalies.length > 0) {
      suggestions.push('Investigate anomalous behavior patterns');
    }
    
    if (analysis.suspiciousPatterns.length > 0) {
      suggestions.push('Monitor for similar suspicious patterns');
    }

    return suggestions;
  }

  // Clear cache
  clearCache() {
    this.cache.clear();
  }
}

// Export singleton instance
export const packetService = new PacketService();
export default packetService;