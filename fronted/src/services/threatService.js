import { apiService } from './api';

class ThreatService {
  constructor() {
    this.threatTypes = [
      'DDoS Attack',
      'Port Scan',
      'Malware Communication',
      'Suspicious Traffic',
      'Data Exfiltration',
      'Brute Force Attack',
      'SQL Injection',
      'Cross-Site Scripting',
      'DNS Tunneling',
      'Botnet Activity'
    ];
    
    this.severityLevels = ['critical', 'high', 'medium', 'low'];
    this.threatSources = [
      '192.168.1.50',
      '10.0.0.100',
      '172.16.1.25',
      '203.0.113.45',
      '198.51.100.78',
      '192.0.2.123'
    ];
  }

  async getThreats(filters = {}) {
    try {
      // In production, this would be: return apiService.get('/threats', filters);
      // For demo purposes, we'll simulate the API call
      return new Promise((resolve) => {
        setTimeout(() => {
          const mockThreats = this.generateMockThreats(filters.limit || 20);
          resolve(mockThreats);
        }, 400);
      });
    } catch (error) {
      throw new Error(`Failed to fetch threats: ${error.message}`);
    }
  }

  async getThreatStats() {
    try {
      // In production: return apiService.get('/threats/stats');
      return new Promise((resolve) => {
        setTimeout(() => {
          resolve({
            total: 23,
            critical: 3,
            high: 7,
            medium: 8,
            low: 5,
            resolved: 45,
            acknowledged: 12,
            new: 11
          });
        }, 300);
      });
    } catch (error) {
      throw new Error(`Failed to fetch threat statistics: ${error.message}`);
    }
  }

  async getThreatDetails(threatId) {
    try {
      // In production: return apiService.get(`/threats/${threatId}`);
      return new Promise((resolve) => {
        setTimeout(() => {
          resolve({
            id: threatId,
            type: 'DDoS Attack',
            severity: 'critical',
            status: 'active',
            sourceIp: '203.0.113.45',
            targetIp: '192.168.1.100',
            firstSeen: new Date(Date.now() - 3600000).toISOString(),
            lastSeen: new Date().toISOString(),
            attackVector: 'UDP Flood',
            affectedPorts: [80, 443, 22],
            packetCount: 15420,
            bandwidth: '850 Mbps',
            geoLocation: {
              country: 'Unknown',
              city: 'Unknown',
              coordinates: { lat: 0, lng: 0 }
            },
            mitigation: {
              status: 'active',
              method: 'Rate Limiting',
              effectiveness: '78%'
            },
            timeline: [
              {
                timestamp: new Date(Date.now() - 3600000).toISOString(),
                event: 'Threat detected',
                details: 'Unusual traffic pattern identified'
              },
              {
                timestamp: new Date(Date.now() - 3000000).toISOString(),
                event: 'Analysis completed',
                details: 'Confirmed DDoS attack pattern'
              },
              {
                timestamp: new Date(Date.now() - 2400000).toISOString(),
                event: 'Mitigation started',
                details: 'Rate limiting rules applied'
              }
            ],
            relatedPackets: [
              'packet_1234', 'packet_1235', 'packet_1236'
            ],
            recommendations: [
              'Implement additional rate limiting',
              'Consider IP blacklisting for source',
              'Monitor for pattern evolution',
              'Review firewall rules'
            ]
          });
        }, 500);
      });
    } catch (error) {
      throw new Error(`Failed to fetch threat details: ${error.message}`);
    }
  }

  async acknowledgeThreat(threatId) {
    try {
      // In production: return apiService.patch(`/threats/${threatId}/acknowledge`);
      return new Promise((resolve) => {
        setTimeout(() => {
          resolve({
            id: threatId,
            acknowledged: true,
            acknowledgedAt: new Date().toISOString(),
            acknowledgedBy: 'current_user'
          });
        }, 200);
      });
    } catch (error) {
      throw new Error(`Failed to acknowledge threat: ${error.message}`);
    }
  }

  async dismissThreat(threatId) {
    try {
      // In production: return apiService.delete(`/threats/${threatId}`);
      return new Promise((resolve) => {
        setTimeout(() => {
          resolve({
            id: threatId,
            dismissed: true,
            dismissedAt: new Date().toISOString()
          });
        }, 200);
      });
    } catch (error) {
      throw new Error(`Failed to dismiss threat: ${error.message}`);
    }
  }

  async resolveThreat(threatId, resolution) {
    try {
      return apiService.patch(`/threats/${threatId}/resolve`, {
        resolution: resolution,
        resolvedAt: new Date().toISOString()
      });
    } catch (error) {
      throw new Error(`Failed to resolve threat: ${error.message}`);
    }
  }

  async blockThreatSource(threatId, sourceIp) {
    try {
      return apiService.post(`/threats/${threatId}/block`, {
        sourceIp: sourceIp,
        action: 'block',
        duration: '24h'
      });
    } catch (error) {
      throw new Error(`Failed to block threat source: ${error.message}`);
    }
  }

  async getThreatHistory(threatId) {
    try {
      return apiService.get(`/threats/${threatId}/history`);
    } catch (error) {
      throw new Error(`Failed to fetch threat history: ${error.message}`);
    }
  }

  async updateThreatSeverity(threatId, severity) {
    try {
      return apiService.patch(`/threats/${threatId}/severity`, {
        severity: severity,
        updatedAt: new Date().toISOString()
      });
    } catch (error) {
      throw new Error(`Failed to update threat severity: ${error.message}`);
    }
  }

  async searchThreats(query, filters = {}) {
    try {
      return apiService.get('/threats/search', {
        q: query,
        ...filters
      });
    } catch (error) {
      throw new Error(`Failed to search threats: ${error.message}`);
    }
  }

  async exportThreats(format = 'json', filters = {}) {
    try {
      return apiService.post('/threats/export', {
        format: format,
        filters: filters,
        exportedAt: new Date().toISOString()
      });
    } catch (error) {
      throw new Error(`Failed to export threats: ${error.message}`);
    }
  }

  async getThreatsByTimeRange(startTime, endTime) {
    try {
      return apiService.get('/threats/timerange', {
        start: startTime,
        end: endTime
      });
    } catch (error) {
      throw new Error(`Failed to fetch threats by time range: ${error.message}`);
    }
  }

  async getThreatTrends(period = '24h') {
    try {
      // In production: return apiService.get(`/threats/trends?period=${period}`);
      return new Promise((resolve) => {
        setTimeout(() => {
          const trends = this.generateMockTrends(period);
          resolve(trends);
        }, 600);
      });
    } catch (error) {
      throw new Error(`Failed to fetch threat trends: ${error.message}`);
    }
  }

  // Helper methods for generating mock data
  generateMockThreats(count = 20) {
    const threats = [];
    
    for (let i = 0; i < count; i++) {
      const timestamp = new Date(Date.now() - Math.random() * 86400000); // Last 24 hours
      const severity = this.severityLevels[Math.floor(Math.random() * this.severityLevels.length)];
      const threatType = this.threatTypes[Math.floor(Math.random() * this.threatTypes.length)];
      const sourceIp = this.threatSources[Math.floor(Math.random() * this.threatSources.length)];
      
      threats.push({
        id: `threat_${i + 1}`,
        type: threatType,
        severity: severity,
        status: Math.random() > 0.7 ? 'resolved' : Math.random() > 0.5 ? 'investigating' : 'active',
        sourceIp: sourceIp,
        targetIp: '192.168.1.100',
        firstSeen: timestamp.toISOString(),
        lastSeen: new Date(timestamp.getTime() + Math.random() * 3600000).toISOString(),
        description: this.generateThreatDescription(threatType),
        confidence: Math.floor(Math.random() * 40) + 60, // 60-100%
        riskScore: Math.floor(Math.random() * 50) + 50, // 50-100
        acknowledged: Math.random() > 0.6,
        affectedAssets: Math.floor(Math.random() * 5) + 1,
        mitigationStatus: Math.random() > 0.5 ? 'active' : 'pending'
      });
    }
    
    return threats.sort((a, b) => new Date(b.firstSeen) - new Date(a.firstSeen));
  }

  generateThreatDescription(threatType) {
    const descriptions = {
      'DDoS Attack': 'High volume of requests detected from multiple sources',
      'Port Scan': 'Sequential port scanning activity identified',
      'Malware Communication': 'Suspicious outbound connections to known malware C&C servers',
      'Suspicious Traffic': 'Anomalous network behavior patterns detected',
      'Data Exfiltration': 'Unusual large data transfers to external destinations',
      'Brute Force Attack': 'Multiple failed authentication attempts detected',
      'SQL Injection': 'Malicious SQL queries detected in web traffic',
      'Cross-Site Scripting': 'XSS attack patterns identified in HTTP requests',
      'DNS Tunneling': 'Suspicious DNS query patterns suggesting data exfiltration',
      'Botnet Activity': 'Communication patterns consistent with botnet behavior'
    };
    
    return descriptions[threatType] || 'Security threat detected';
  }

  generateMockTrends(period) {
    const dataPoints = period === '1h' ? 60 : period === '24h' ? 24 : 30;
    const trends = [];
    
    for (let i = dataPoints - 1; i >= 0; i--) {
      const timestamp = new Date();
      
      if (period === '1h') {
        timestamp.setMinutes(timestamp.getMinutes() - i);
      } else if (period === '24h') {
        timestamp.setHours(timestamp.getHours() - i);
      } else {
        timestamp.setDate(timestamp.getDate() - i);
      }
      
      trends.push({
        timestamp: timestamp.toISOString(),
        total: Math.floor(Math.random() * 10) + 1,
        critical: Math.floor(Math.random() * 3),
        high: Math.floor(Math.random() * 4) + 1,
        medium: Math.floor(Math.random() * 3) + 2,
        low: Math.floor(Math.random() * 2) + 1
      });
    }
    
    return trends;
  }

  // Utility methods
  getSeverityColor(severity) {
    const colors = {
      critical: '#EF4444', // red-500
      high: '#F97316',     // orange-500
      medium: '#EAB308',   // yellow-500
      low: '#22C55E'       // green-500
    };
    return colors[severity] || '#6B7280'; // gray-500
  }

  getSeverityWeight(severity) {
    const weights = {
      critical: 4,
      high: 3,
      medium: 2,
      low: 1
    };
    return weights[severity] || 0;
  }

  formatThreatType(type) {
    return type.split(' ').map(word => 
      word.charAt(0).toUpperCase() + word.slice(1).toLowerCase()
    ).join(' ');
  }

  calculateRiskLevel(threats) {
    if (!threats.length) return 'low';
    
    const totalWeight = threats.reduce((sum, threat) => 
      sum + this.getSeverityWeight(threat.severity), 0
    );
    
    const avgWeight = totalWeight / threats.length;
    
    if (avgWeight >= 3.5) return 'critical';
    if (avgWeight >= 2.5) return 'high';
    if (avgWeight >= 1.5) return 'medium';
    return 'low';
  }
}

export const threatService = new ThreatService();