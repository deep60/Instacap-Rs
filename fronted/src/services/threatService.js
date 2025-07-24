import api from './api';
import { formatThreatData, calculateThreatSeverity, validateThreatResponse } from '../utils/formatters';

// Threat severity levels
export const THREAT_LEVELS = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
  INFO: 'info'
};

// Threat types
export const THREAT_TYPES = {
  MALWARE: 'malware',
  INTRUSION: 'intrusion',
  DDoS: 'ddos',
  PORT_SCAN: 'port_scan',
  DATA_EXFILTRATION: 'data_exfiltration',
  BRUTE_FORCE: 'brute_force',
  SUSPICIOUS_TRAFFIC: 'suspicious_traffic',
  UNKNOWN: 'unknown'
};

// Threat status
export const THREAT_STATUS = {
  ACTIVE: 'active',
  RESOLVED: 'resolved',
  INVESTIGATING: 'investigating',
  FALSE_POSITIVE: 'false_positive'
};

class ThreatService {
  constructor() {
    this.cache = new Map();
    this.cacheTimeout = 30000; // 30 seconds
  }

  /**
   * Get all threats with optional filtering
   * @param {Object} params - Query parameters
   * @returns {Promise<Array>} Array of threat objects
   */
  async getThreats(params = {}) {
    try {
      const queryParams = new URLSearchParams({
        page: params.page || 1,
        limit: params.limit || 50,
        severity: params.severity || '',
        type: params.type || '',
        status: params.status || '',
        start_time: params.startTime || '',
        end_time: params.endTime || '',
        source_ip: params.sourceIp || '',
        destination_ip: params.destinationIp || ''
      });

      const cacheKey = `threats-${queryParams.toString()}`;
      
      // Check cache first
      if (this.cache.has(cacheKey)) {
        const cached = this.cache.get(cacheKey);
        if (Date.now() - cached.timestamp < this.cacheTimeout) {
          return cached.data;
        }
      }

      const response = await api.get(`/threats?${queryParams}`);
      
      if (!validateThreatResponse(response.data)) {
        throw new Error('Invalid threat data received');
      }

      const formattedThreats = response.data.threats.map(formatThreatData);
      
      // Cache the response
      this.cache.set(cacheKey, {
        data: {
          threats: formattedThreats,
          total: response.data.total,
          page: response.data.page,
          totalPages: response.data.totalPages
        },
        timestamp: Date.now()
      });

      return {
        threats: formattedThreats,
        total: response.data.total,
        page: response.data.page,
        totalPages: response.data.totalPages
      };
    } catch (error) {
      console.error('Error fetching threats:', error);
      throw new Error(`Failed to fetch threats: ${error.message}`);
    }
  }

  /**
   * Get threat by ID
   * @param {string} threatId - Threat identifier
   * @returns {Promise<Object>} Threat object with detailed information
   */
  async getThreatById(threatId) {
    try {
      if (!threatId) {
        throw new Error('Threat ID is required');
      }

      const cacheKey = `threat-${threatId}`;
      
      if (this.cache.has(cacheKey)) {
        const cached = this.cache.get(cacheKey);
        if (Date.now() - cached.timestamp < this.cacheTimeout) {
          return cached.data;
        }
      }

      const response = await api.get(`/threats/${threatId}`);
      const threat = formatThreatData(response.data);
      
      // Cache the threat
      this.cache.set(cacheKey, {
        data: threat,
        timestamp: Date.now()
      });

      return threat;
    } catch (error) {
      console.error(`Error fetching threat ${threatId}:`, error);
      throw new Error(`Failed to fetch threat details: ${error.message}`);
    }
  }

  /**
   * Get real-time threat statistics
   * @returns {Promise<Object>} Threat statistics
   */
  async getThreatStats() {
    try {
      const response = await api.get('/threats/stats');
      
      return {
        total: response.data.total || 0,
        active: response.data.active || 0,
        critical: response.data.critical || 0,
        high: response.data.high || 0,
        medium: response.data.medium || 0,
        low: response.data.low || 0,
        resolved: response.data.resolved || 0,
        falsePositives: response.data.false_positives || 0,
        topThreatTypes: response.data.top_threat_types || [],
        recentThreats: response.data.recent_threats?.map(formatThreatData) || []
      };
    } catch (error) {
      console.error('Error fetching threat stats:', error);
      throw new Error(`Failed to fetch threat statistics: ${error.message}`);
    }
  }

  /**
   * Update threat status
   * @param {string} threatId - Threat identifier
   * @param {string} status - New status
   * @param {string} notes - Optional notes
   * @returns {Promise<Object>} Updated threat object
   */
  async updateThreatStatus(threatId, status, notes = '') {
    try {
      if (!threatId || !status) {
        throw new Error('Threat ID and status are required');
      }

      if (!Object.values(THREAT_STATUS).includes(status)) {
        throw new Error('Invalid threat status');
      }

      const response = await api.patch(`/threats/${threatId}/status`, {
        status,
        notes,
        updated_at: new Date().toISOString()
      });

      // Clear cache for this threat
      this.cache.delete(`threat-${threatId}`);
      this.clearThreatsCache();

      return formatThreatData(response.data);
    } catch (error) {
      console.error(`Error updating threat status:`, error);
      throw new Error(`Failed to update threat status: ${error.message}`);
    }
  }

  /**
   * Get threat timeline/history
   * @param {string} threatId - Threat identifier
   * @returns {Promise<Array>} Array of timeline events
   */
  async getThreatTimeline(threatId) {
    try {
      if (!threatId) {
        throw new Error('Threat ID is required');
      }

      const response = await api.get(`/threats/${threatId}/timeline`);
      
      return response.data.timeline.map(event => ({
        id: event.id,
        timestamp: new Date(event.timestamp),
        action: event.action,
        description: event.description,
        severity: event.severity,
        user: event.user || 'System',
        metadata: event.metadata || {}
      }));
    } catch (error) {
      console.error(`Error fetching threat timeline:`, error);
      throw new Error(`Failed to fetch threat timeline: ${error.message}`);
    }
  }

  /**
   * Get similar threats
   * @param {string} threatId - Threat identifier
   * @param {number} limit - Number of similar threats to return
   * @returns {Promise<Array>} Array of similar threat objects
   */
  async getSimilarThreats(threatId, limit = 5) {
    try {
      if (!threatId) {
        throw new Error('Threat ID is required');
      }

      const response = await api.get(`/threats/${threatId}/similar?limit=${limit}`);
      
      return response.data.similar_threats.map(formatThreatData);
    } catch (error) {
      console.error(`Error fetching similar threats:`, error);
      throw new Error(`Failed to fetch similar threats: ${error.message}`);
    }
  }

  /**
   * Create manual threat entry
   * @param {Object} threatData - Threat information
   * @returns {Promise<Object>} Created threat object
   */
  async createThreat(threatData) {
    try {
      const requiredFields = ['type', 'severity', 'source_ip', 'description'];
      for (const field of requiredFields) {
        if (!threatData[field]) {
          throw new Error(`${field} is required`);
        }
      }

      const payload = {
        ...threatData,
        created_at: new Date().toISOString(),
        status: THREAT_STATUS.ACTIVE,
        severity_score: calculateThreatSeverity(threatData)
      };

      const response = await api.post('/threats', payload);
      
      // Clear threats cache
      this.clearThreatsCache();
      
      return formatThreatData(response.data);
    } catch (error) {
      console.error('Error creating threat:', error);
      throw new Error(`Failed to create threat: ${error.message}`);
    }
  }

  /**
   * Delete threat
   * @param {string} threatId - Threat identifier
   * @returns {Promise<boolean>} Success status
   */
  async deleteThreat(threatId) {
    try {
      if (!threatId) {
        throw new Error('Threat ID is required');
      }

      await api.delete(`/threats/${threatId}`);
      
      // Clear cache
      this.cache.delete(`threat-${threatId}`);
      this.clearThreatsCache();
      
      return true;
    } catch (error) {
      console.error(`Error deleting threat:`, error);
      throw new Error(`Failed to delete threat: ${error.message}`);
    }
  }

  /**
   * Get threat detection rules
   * @returns {Promise<Array>} Array of detection rules
   */
  async getDetectionRules() {
    try {
      const response = await api.get('/threats/detection-rules');
      
      return response.data.rules.map(rule => ({
        id: rule.id,
        name: rule.name,
        description: rule.description,
        type: rule.type,
        severity: rule.severity,
        enabled: rule.enabled,
        conditions: rule.conditions,
        actions: rule.actions,
        created_at: new Date(rule.created_at),
        updated_at: new Date(rule.updated_at)
      }));
    } catch (error) {
      console.error('Error fetching detection rules:', error);
      throw new Error(`Failed to fetch detection rules: ${error.message}`);
    }
  }

  /**
   * Update detection rule
   * @param {string} ruleId - Rule identifier
   * @param {Object} ruleData - Updated rule data
   * @returns {Promise<Object>} Updated rule object
   */
  async updateDetectionRule(ruleId, ruleData) {
    try {
      if (!ruleId) {
        throw new Error('Rule ID is required');
      }

      const response = await api.patch(`/threats/detection-rules/${ruleId}`, {
        ...ruleData,
        updated_at: new Date().toISOString()
      });

      return response.data;
    } catch (error) {
      console.error('Error updating detection rule:', error);
      throw new Error(`Failed to update detection rule: ${error.message}`);
    }
  }

  /**
   * Get threat intelligence feeds
   * @returns {Promise<Array>} Array of threat intelligence data
   */
  async getThreatIntelligence() {
    try {
      const response = await api.get('/threats/intelligence');
      
      return response.data.feeds.map(feed => ({
        id: feed.id,
        source: feed.source,
        type: feed.type,
        indicators: feed.indicators,
        confidence: feed.confidence,
        last_updated: new Date(feed.last_updated),
        tags: feed.tags || []
      }));
    } catch (error) {
      console.error('Error fetching threat intelligence:', error);
      throw new Error(`Failed to fetch threat intelligence: ${error.message}`);
    }
  }

  /**
   * Export threats data
   * @param {Object} params - Export parameters
   * @returns {Promise<Blob>} Export file blob
   */
  async exportThreats(params = {}) {
    try {
      const queryParams = new URLSearchParams({
        format: params.format || 'csv',
        start_time: params.startTime || '',
        end_time: params.endTime || '',
        severity: params.severity || '',
        type: params.type || ''
      });

      const response = await api.get(`/threats/export?${queryParams}`, {
        responseType: 'blob'
      });

      return response.data;
    } catch (error) {
      console.error('Error exporting threats:', error);
      throw new Error(`Failed to export threats: ${error.message}`);
    }
  }

  /**
   * Clear threats cache
   */
  clearThreatsCache() {
    for (const key of this.cache.keys()) {
      if (key.startsWith('threats-')) {
        this.cache.delete(key);
      }
    }
  }

  /**
   * Clear all cache
   */
  clearCache() {
    this.cache.clear();
  }

  /**
   * Get cache statistics
   * @returns {Object} Cache statistics
   */
  getCacheStats() {
    return {
      size: this.cache.size,
      keys: Array.from(this.cache.keys())
    };
  }
}

// Create and export singleton instance
const threatService = new ThreatService();

// Export named export for compatibility
export { threatService };
export default threatService;
