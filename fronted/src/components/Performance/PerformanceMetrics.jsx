// services/performanceMetrics.js
import { API_CONFIG } from '../../utils/constants';

// Define API endpoints for performance metrics
const API_ENDPOINTS = {
  PERFORMANCE: {
    CURRENT: '/performance/current',
    HISTORICAL: '/performance/historical',
    LATENCY: '/performance/latency',
    BANDWIDTH: '/performance/bandwidth',
    PACKET_LOSS: '/performance/packet-loss',
    THROUGHPUT: '/performance/throughput',
    INTERFACES: '/performance/interfaces',
    ALERTS: '/performance/alerts',
    THRESHOLDS: '/performance/thresholds',
    EXPORT: '/performance/export'
  }
};

class PerformanceMetricsService {
  constructor() {
    this.baseURL = API_CONFIG.BASE_URL;
    this.cache = new Map();
    this.cacheTimeout = 30000; // 30 seconds cache
  }

  /**
   * Get current performance metrics overview
   */
  async getCurrentMetrics() {
    try {
      const response = await fetch(`${this.baseURL}${API_ENDPOINTS.PERFORMANCE.CURRENT}`, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.getAuthToken()}`
        }
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      return {
        success: true,
        data: data
      };
    } catch (error) {
      console.error('Error fetching current metrics:', error);
      return {
        success: false,
        error: error.message,
        data: null
      };
    }
  }

  /**
   * Get historical performance data with time range
   */
  async getHistoricalMetrics(timeRange = '1h', granularity = '1m') {
    const cacheKey = `historical_${timeRange}_${granularity}`;
    
    // Check cache first
    if (this.cache.has(cacheKey)) {
      const cached = this.cache.get(cacheKey);
      if (Date.now() - cached.timestamp < this.cacheTimeout) {
        return cached.data;
      }
    }

    try {
      const response = await fetch(
        `${this.baseURL}${API_ENDPOINTS.PERFORMANCE.HISTORICAL}?range=${timeRange}&granularity=${granularity}`,
        {
          method: 'GET',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${this.getAuthToken()}`
          }
        }
      );

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      const result = {
        success: true,
        data: data
      };

      // Cache the result
      this.cache.set(cacheKey, {
        data: result,
        timestamp: Date.now()
      });

      return result;
    } catch (error) {
      console.error('Error fetching historical metrics:', error);
      return {
        success: false,
        error: error.message,
        data: null
      };
    }
  }

  /**
   * Get network latency statistics
   */
  async getLatencyStats(timeRange = '1h') {
    try {
      const response = await fetch(
        `${this.baseURL}${API_ENDPOINTS.PERFORMANCE.LATENCY}?range=${timeRange}`,
        {
          method: 'GET',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${this.getAuthToken()}`
          }
        }
      );

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      return {
        success: true,
        data: {
          average: data.average_latency,
          min: data.min_latency,
          max: data.max_latency,
          p95: data.p95_latency,
          p99: data.p99_latency,
          jitter: data.jitter,
          timeline: data.latency_timeline || []
        }
      };
    } catch (error) {
      console.error('Error fetching latency stats:', error);
      return {
        success: false,
        error: error.message,
        data: null
      };
    }
  }

  /**
   * Get bandwidth utilization data
   */
  async getBandwidthUtilization(timeRange = '1h', interfaceId = null) {
    try {
      let url = `${this.baseURL}${API_ENDPOINTS.PERFORMANCE.BANDWIDTH}?range=${timeRange}`;
      if (interfaceId) {
        url += `&interface=${interfaceId}`;
      }

      const response = await fetch(url, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.getAuthToken()}`
        }
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      return {
        success: true,
        data: {
          current_utilization: data.current_utilization,
          peak_utilization: data.peak_utilization,
          average_utilization: data.average_utilization,
          ingress_bps: data.ingress_bps,
          egress_bps: data.egress_bps,
          total_bytes: data.total_bytes,
          timeline: data.bandwidth_timeline || []
        }
      };
    } catch (error) {
      console.error('Error fetching bandwidth utilization:', error);
      return {
        success: false,
        error: error.message,
        data: null
      };
    }
  }

  /**
   * Get packet loss statistics
   */
  async getPacketLossStats(timeRange = '1h') {
    try {
      const response = await fetch(
        `${this.baseURL}${API_ENDPOINTS.PERFORMANCE.PACKET_LOSS}?range=${timeRange}`,
        {
          method: 'GET',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${this.getAuthToken()}`
          }
        }
      );

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      return {
        success: true,
        data: {
          loss_percentage: data.loss_percentage,
          total_packets: data.total_packets,
          lost_packets: data.lost_packets,
          out_of_order: data.out_of_order_packets,
          duplicates: data.duplicate_packets,
          timeline: data.loss_timeline || []
        }
      };
    } catch (error) {
      console.error('Error fetching packet loss stats:', error);
      return {
        success: false,
        error: error.message,
        data: null
      };
    }
  }

  /**
   * Get throughput statistics
   */
  async getThroughputStats(timeRange = '1h', protocol = null) {
    try {
      let url = `${this.baseURL}${API_ENDPOINTS.PERFORMANCE.THROUGHPUT}?range=${timeRange}`;
      if (protocol) {
        url += `&protocol=${protocol}`;
      }

      const response = await fetch(url, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.getAuthToken()}`
        }
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      return {
        success: true,
        data: {
          current_throughput: data.current_throughput,
          peak_throughput: data.peak_throughput,
          average_throughput: data.average_throughput,
          packets_per_second: data.packets_per_second,
          bytes_per_second: data.bytes_per_second,
          timeline: data.throughput_timeline || []
        }
      };
    } catch (error) {
      console.error('Error fetching throughput stats:', error);
      return {
        success: false,
        error: error.message,
        data: null
      };
    }
  }

  /**
   * Get network interface statistics
   */
  async getInterfaceStats() {
    try {
      const response = await fetch(`${this.baseURL}${API_ENDPOINTS.PERFORMANCE.INTERFACES}`, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.getAuthToken()}`
        }
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      return {
        success: true,
        data: data.interfaces || []
      };
    } catch (error) {
      console.error('Error fetching interface stats:', error);
      return {
        success: false,
        error: error.message,
        data: []
      };
    }
  }

  /**
   * Get performance alerts and thresholds
   */
  async getPerformanceAlerts() {
    try {
      const response = await fetch(`${this.baseURL}${API_ENDPOINTS.PERFORMANCE.ALERTS}`, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.getAuthToken()}`
        }
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      return {
        success: true,
        data: {
          active_alerts: data.active_alerts || [],
          thresholds: data.thresholds || {},
          alert_history: data.alert_history || []
        }
      };
    } catch (error) {
      console.error('Error fetching performance alerts:', error);
      return {
        success: false,
        error: error.message,
        data: null
      };
    }
  }

  /**
   * Update performance alert thresholds
   */
  async updateThresholds(thresholds) {
    try {
      const response = await fetch(`${this.baseURL}${API_ENDPOINTS.PERFORMANCE.THRESHOLDS}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.getAuthToken()}`
        },
        body: JSON.stringify(thresholds)
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      return {
        success: true,
        message: 'Thresholds updated successfully',
        data: data
      };
    } catch (error) {
      console.error('Error updating thresholds:', error);
      return {
        success: false,
        error: error.message,
        data: null
      };
    }
  }

  /**
   * Get comprehensive performance report
   */
  async getPerformanceReport(timeRange = '24h') {
    try {
      const [
        currentMetrics,
        latencyStats,
        bandwidthStats,
        packetLossStats,
        throughputStats,
        interfaceStats
      ] = await Promise.all([
        this.getCurrentMetrics(),
        this.getLatencyStats(timeRange),
        this.getBandwidthUtilization(timeRange),
        this.getPacketLossStats(timeRange),
        this.getThroughputStats(timeRange),
        this.getInterfaceStats()
      ]);

      return {
        success: true,
        data: {
          current: currentMetrics.data,
          latency: latencyStats.data,
          bandwidth: bandwidthStats.data,
          packet_loss: packetLossStats.data,
          throughput: throughputStats.data,
          interfaces: interfaceStats.data,
          generated_at: new Date().toISOString()
        }
      };
    } catch (error) {
      console.error('Error generating performance report:', error);
      return {
        success: false,
        error: error.message,
        data: null
      };
    }
  }

  /**
   * Export performance data
   */
  async exportPerformanceData(timeRange = '24h', format = 'json') {
    try {
      const response = await fetch(
        `${this.baseURL}${API_ENDPOINTS.PERFORMANCE.EXPORT}?range=${timeRange}&format=${format}`,
        {
          method: 'GET',
          headers: {
            'Authorization': `Bearer ${this.getAuthToken()}`
          }
        }
      );

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const blob = await response.blob();
      return {
        success: true,
        data: blob,
        filename: `performance_data_${timeRange}_${Date.now()}.${format}`
      };
    } catch (error) {
      console.error('Error exporting performance data:', error);
      return {
        success: false,
        error: error.message,
        data: null
      };
    }
  }

  /**
   * Clear cache
   */
  clearCache() {
    this.cache.clear();
  }

  /**
   * Get authentication token
   */
  getAuthToken() {
    return localStorage.getItem('auth_token') || '';
  }

  /**
   * Helper method to format bytes
   */
  formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';

    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];

    const i = Math.floor(Math.log(bytes) / Math.log(k));

    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
  }

  /**
   * Helper method to format duration
   */
  formatDuration(milliseconds) {
    if (milliseconds < 1000) {
      return `${milliseconds.toFixed(2)}ms`;
    } else if (milliseconds < 60000) {
      return `${(milliseconds / 1000).toFixed(2)}s`;
    } else {
      return `${(milliseconds / 60000).toFixed(2)}m`;
    }
  }
}

// Create and export a singleton instance
const performanceMetricsService = new PerformanceMetricsService();
export default performanceMetricsService;