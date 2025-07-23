// services/protocolService.js
import { API_CONFIG } from '../utils/constants';

class ProtocolService {
  constructor() {
    this.baseURL = API_CONFIG.BASE_URL;
    this.cache = new Map();
    this.cacheTimeout = 30000; // 30 seconds cache
  }

  /**
   * Get authentication token from localStorage or sessionStorage
   */
  getAuthToken() {
    return localStorage.getItem('auth_token') || sessionStorage.getItem('auth_token') || '';
  }

  /**
   * Generic fetch method with error handling
   */
  async fetchWithErrorHandling(url, options = {}) {
    try {
      const defaultOptions = {
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.getAuthToken()}`
        }
      };

      const response = await fetch(url, { ...defaultOptions, ...options });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      return {
        success: true,
        data: data
      };
    } catch (error) {
      console.error('API request failed:', error);
      return {
        success: false,
        error: error.message,
        data: null
      };
    }
  }

  /**
   * Get protocol distribution data
   */
  async getProtocolDistribution(timeRange = '1h') {
    const cacheKey = `protocol_distribution_${timeRange}`;
    
    // Check cache first
    if (this.cache.has(cacheKey)) {
      const cached = this.cache.get(cacheKey);
      if (Date.now() - cached.timestamp < this.cacheTimeout) {
        return cached.data;
      }
    }

    const url = `${this.baseURL}/protocols/distribution?range=${timeRange}`;
    const result = await this.fetchWithErrorHandling(url);

    if (result.success) {
      // Cache the result
      this.cache.set(cacheKey, {
        data: result,
        timestamp: Date.now()
      });
    }

    return result;
  }

  /**
   * Get protocol trends over time
   */
  async getProtocolTrends(timeRange = '1h', granularity = '5m') {
    const url = `${this.baseURL}/protocols/trends?range=${timeRange}&granularity=${granularity}`;
    return await this.fetchWithErrorHandling(url);
  }

  /**
   * Get protocol statistics
   */
  async getProtocolStatistics(timeRange = '1h') {
    const url = `${this.baseURL}/protocols/statistics?range=${timeRange}`;
    return await this.fetchWithErrorHandling(url);
  }

  /**
   * Get protocol anomalies
   */
  async getProtocolAnomalies(timeRange = '1h') {
    const url = `${this.baseURL}/protocols/anomalies?range=${timeRange}`;
    return await this.fetchWithErrorHandling(url);
  }

  /**
   * Get detailed protocol information
   */
  async getProtocolDetails(protocol, timeRange = '1h') {
    const url = `${this.baseURL}/protocols/${protocol}/details?range=${timeRange}`;
    return await this.fetchWithErrorHandling(url);
  }

  /**
   * Get protocol traffic analysis
   */
  async getProtocolTrafficAnalysis(protocol, timeRange = '1h') {
    const url = `${this.baseURL}/protocols/${protocol}/traffic?range=${timeRange}`;
    return await this.fetchWithErrorHandling(url);
  }

  /**
   * Get protocol port usage
   */
  async getProtocolPortUsage(protocol, timeRange = '1h') {
    const url = `${this.baseURL}/protocols/${protocol}/ports?range=${timeRange}`;
    return await this.fetchWithErrorHandling(url);
  }

  /**
   * Export protocol data
   */
  async exportProtocolData(timeRange = '1h', format = 'csv') {
    try {
      const url = `${this.baseURL}/protocols/export?range=${timeRange}&format=${format}`;
      const response = await fetch(url, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${this.getAuthToken()}`
        }
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const blob = await response.blob();
      const filename = `protocol_data_${timeRange}_${Date.now()}.${format}`;

      return {
        success: true,
        data: blob,
        filename: filename
      };
    } catch (error) {
      console.error('Export failed:', error);
      return {
        success: false,
        error: error.message,
        data: null
      };
    }
  }

  /**
   * Get protocol comparison data
   */
  async getProtocolComparison(protocols, timeRange = '1h') {
    const protocolList = protocols.join(',');
    const url = `${this.baseURL}/protocols/compare?protocols=${protocolList}&range=${timeRange}`;
    return await this.fetchWithErrorHandling(url);
  }

  /**
   * Get protocol performance metrics
   */
  async getProtocolPerformance(protocol, timeRange = '1h') {
    const url = `${this.baseURL}/protocols/${protocol}/performance?range=${timeRange}`;
    return await this.fetchWithErrorHandling(url);
  }

  /**
   * Clear cache
   */
  clearCache() {
    this.cache.clear();
  }

  /**
   * Get cache statistics
   */
  getCacheStats() {
    return {
      size: this.cache.size,
      keys: Array.from(this.cache.keys())
    };
  }
}

// Create and export a singleton instance
const protocolService = new ProtocolService();
export default protocolService;
