import api from './api';
import { 
  ANALYTICS_ENDPOINTS, 
  TIME_RANGES, 
  METRIC_TYPES,
  PROTOCOL_TYPES 
} from '../utils/constants';

/**
 * Analytics Service for Packet Analyzer
 * Handles traffic analytics, performance metrics, and statistical data
 */
class AnalyticsService {
  constructor() {
    this.cache = new Map();
    this.cacheTimeout = 30000; // 30 seconds
  }

  /**
   * Get cached data if available and not expired
   */
  getCachedData(key) {
    const cached = this.cache.get(key);
    if (cached && Date.now() - cached.timestamp < this.cacheTimeout) {
      return cached.data;
    }
    return null;
  }

  /**
   * Set data in cache
   */
  setCachedData(key, data) {
    this.cache.set(key, {
      data,
      timestamp: Date.now()
    });
  }

  /**
   * Get traffic analytics for specified time range
   */
  async getTrafficAnalytics(timeRange = TIME_RANGES.LAST_HOUR, filters = {}) {
    try {
      const cacheKey = `traffic_analytics_${timeRange}_${JSON.stringify(filters)}`;
      const cached = this.getCachedData(cacheKey);
      if (cached) return cached;

      const params = {
        time_range: timeRange,
        ...filters
      };

      const response = await api.get(ANALYTICS_ENDPOINTS.TRAFFIC_ANALYTICS, { params });
      
      const processedData = this.processTrafficData(response.data);
      this.setCachedData(cacheKey, processedData);
      
      return processedData;
    } catch (error) {
      console.error('Error fetching traffic analytics:', error);
      throw new Error('Failed to fetch traffic analytics');
    }
  }

  /**
   * Get bandwidth utilization metrics
   */
  async getBandwidthMetrics(timeRange = TIME_RANGES.LAST_HOUR, interface = 'all') {
    try {
      const cacheKey = `bandwidth_${timeRange}_${interface}`;
      const cached = this.getCachedData(cacheKey);
      if (cached) return cached;

      const response = await api.get(ANALYTICS_ENDPOINTS.BANDWIDTH_METRICS, {
        params: { time_range: timeRange, interface }
      });

      const processedData = this.processBandwidthData(response.data);
      this.setCachedData(cacheKey, processedData);
      
      return processedData;
    } catch (error) {
      console.error('Error fetching bandwidth metrics:', error);
      throw new Error('Failed to fetch bandwidth metrics');
    }
  }

  /**
   * Get protocol distribution analytics
   */
  async getProtocolDistribution(timeRange = TIME_RANGES.LAST_HOUR) {
    try {
      const cacheKey = `protocol_distribution_${timeRange}`;
      const cached = this.getCachedData(cacheKey);
      if (cached) return cached;

      const response = await api.get(ANALYTICS_ENDPOINTS.PROTOCOL_DISTRIBUTION, {
        params: { time_range: timeRange }
      });

      const processedData = this.processProtocolData(response.data);
      this.setCachedData(cacheKey, processedData);
      
      return processedData;
    } catch (error) {
      console.error('Error fetching protocol distribution:', error);
      throw new Error('Failed to fetch protocol distribution');
    }
  }

  /**
   * Get performance metrics (latency, jitter, packet loss)
   */
  async getPerformanceMetrics(timeRange = TIME_RANGES.LAST_HOUR, metricType = 'all') {
    try {
      const cacheKey = `performance_${timeRange}_${metricType}`;
      const cached = this.getCachedData(cacheKey);
      if (cached) return cached;

      const response = await api.get(ANALYTICS_ENDPOINTS.PERFORMANCE_METRICS, {
        params: { time_range: timeRange, metric_type: metricType }
      });

      const processedData = this.processPerformanceData(response.data);
      this.setCachedData(cacheKey, processedData);
      
      return processedData;
    } catch (error) {
      console.error('Error fetching performance metrics:', error);
      throw new Error('Failed to fetch performance metrics');
    }
  }

  /**
   * Get top talkers (hosts with highest traffic)
   */
  async getTopTalkers(timeRange = TIME_RANGES.LAST_HOUR, limit = 10) {
    try {
      const cacheKey = `top_talkers_${timeRange}_${limit}`;
      const cached = this.getCachedData(cacheKey);
      if (cached) return cached;

      const response = await api.get(ANALYTICS_ENDPOINTS.TOP_TALKERS, {
        params: { time_range: timeRange, limit }
      });

      const processedData = this.processTopTalkersData(response.data);
      this.setCachedData(cacheKey, processedData);
      
      return processedData;
    } catch (error) {
      console.error('Error fetching top talkers:', error);
      throw new Error('Failed to fetch top talkers');
    }
  }

  /**
   * Get geographical traffic distribution
   */
  async getGeoTrafficData(timeRange = TIME_RANGES.LAST_HOUR) {
    try {
      const cacheKey = `geo_traffic_${timeRange}`;
      const cached = this.getCachedData(cacheKey);
      if (cached) return cached;

      const response = await api.get(ANALYTICS_ENDPOINTS.GEO_TRAFFIC, {
        params: { time_range: timeRange }
      });

      const processedData = this.processGeoData(response.data);
      this.setCachedData(cacheKey, processedData);
      
      return processedData;
    } catch (error) {
      console.error('Error fetching geo traffic data:', error);
      throw new Error('Failed to fetch geographical traffic data');
    }
  }

  /**
   * Get anomaly detection analytics
   */
  async getAnomalyAnalytics(timeRange = TIME_RANGES.LAST_HOUR, severity = 'all') {
    try {
      const response = await api.get(ANALYTICS_ENDPOINTS.ANOMALY_ANALYTICS, {
        params: { time_range: timeRange, severity }
      });

      return this.processAnomalyData(response.data);
    } catch (error) {
      console.error('Error fetching anomaly analytics:', error);
      throw new Error('Failed to fetch anomaly analytics');
    }
  }

  /**
   * Get custom analytics based on query
   */
  async getCustomAnalytics(query) {
    try {
      const response = await api.post(ANALYTICS_ENDPOINTS.CUSTOM_QUERY, { query });
      return this.processCustomQueryData(response.data);
    } catch (error) {
      console.error('Error executing custom analytics query:', error);
      throw new Error('Failed to execute custom analytics query');
    }
  }

  /**
   * Export analytics data
   */
  async exportAnalytics(params) {
    try {
      const response = await api.post(ANALYTICS_ENDPOINTS.EXPORT, params, {
        responseType: 'blob'
      });

      // Create download link
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `analytics_export_${Date.now()}.csv`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);

      return { success: true, message: 'Analytics data exported successfully' };
    } catch (error) {
      console.error('Error exporting analytics:', error);
      throw new Error('Failed to export analytics data');
    }
  }

  /**
   * Process raw traffic data
   */
  processTrafficData(rawData) {
    return {
      totalPackets: rawData.total_packets || 0,
      totalBytes: rawData.total_bytes || 0,
      packetsPerSecond: rawData.packets_per_second || 0,
      bytesPerSecond: rawData.bytes_per_second || 0,
      peakTraffic: rawData.peak_traffic || 0,
      avgTraffic: rawData.avg_traffic || 0,
      timeline: rawData.timeline?.map(point => ({
        timestamp: new Date(point.timestamp),
        packets: point.packets || 0,
        bytes: point.bytes || 0,
        connections: point.connections || 0
      })) || [],
      protocols: rawData.protocols || {},
      directions: {
        inbound: rawData.inbound_bytes || 0,
        outbound: rawData.outbound_bytes || 0
      }
    };
  }

  /**
   * Process bandwidth data
   */
  processBandwidthData(rawData) {
    return {
      currentUtilization: rawData.current_utilization || 0,
      maxCapacity: rawData.max_capacity || 0,
      avgUtilization: rawData.avg_utilization || 0,
      peakUtilization: rawData.peak_utilization || 0,
      timeline: rawData.timeline?.map(point => ({
        timestamp: new Date(point.timestamp),
        inbound: point.inbound_bps || 0,
        outbound: point.outbound_bps || 0,
        total: point.total_bps || 0,
        utilization: point.utilization_percent || 0
      })) || [],
      interfaces: rawData.interfaces || {}
    };
  }

  /**
   * Process protocol distribution data
   */
  processProtocolData(rawData) {
    const protocols = rawData.protocols || {};
    const total = Object.values(protocols).reduce((sum, count) => sum + count, 0);

    return {
      distribution: Object.entries(protocols).map(([protocol, count]) => ({
        protocol,
        count,
        percentage: total > 0 ? ((count / total) * 100).toFixed(2) : 0,
        bytes: rawData.protocol_bytes?.[protocol] || 0
      })).sort((a, b) => b.count - a.count),
      totalProtocols: Object.keys(protocols).length,
      timeline: rawData.protocol_timeline?.map(point => ({
        timestamp: new Date(point.timestamp),
        ...point.protocols
      })) || []
    };
  }

  /**
   * Process performance metrics data
   */
  processPerformanceData(rawData) {
    return {
      latency: {
        current: rawData.latency?.current || 0,
        avg: rawData.latency?.avg || 0,
        min: rawData.latency?.min || 0,
        max: rawData.latency?.max || 0,
        p95: rawData.latency?.p95 || 0,
        timeline: rawData.latency?.timeline?.map(point => ({
          timestamp: new Date(point.timestamp),
          value: point.latency || 0
        })) || []
      },
      jitter: {
        current: rawData.jitter?.current || 0,
        avg: rawData.jitter?.avg || 0,
        timeline: rawData.jitter?.timeline?.map(point => ({
          timestamp: new Date(point.timestamp),
          value: point.jitter || 0
        })) || []
      },
      packetLoss: {
        current: rawData.packet_loss?.current || 0,
        avg: rawData.packet_loss?.avg || 0,
        timeline: rawData.packet_loss?.timeline?.map(point => ({
          timestamp: new Date(point.timestamp),
          value: point.packet_loss || 0
        })) || []
      },
      throughput: {
        current: rawData.throughput?.current || 0,
        avg: rawData.throughput?.avg || 0,
        peak: rawData.throughput?.peak || 0,
        timeline: rawData.throughput?.timeline?.map(point => ({
          timestamp: new Date(point.timestamp),
          value: point.throughput || 0
        })) || []
      }
    };
  }

  /**
   * Process top talkers data
   */
  processTopTalkersData(rawData) {
    return {
      hosts: rawData.hosts?.map(host => ({
        ip: host.ip,
        hostname: host.hostname || host.ip,
        totalBytes: host.total_bytes || 0,
        totalPackets: host.total_packets || 0,
        inboundBytes: host.inbound_bytes || 0,
        outboundBytes: host.outbound_bytes || 0,
        connections: host.connections || 0,
        firstSeen: new Date(host.first_seen),
        lastSeen: new Date(host.last_seen),
        reputation: host.reputation || 'unknown'
      })) || [],
      conversations: rawData.conversations?.map(conv => ({
        source: conv.source_ip,
        destination: conv.dest_ip,
        protocol: conv.protocol,
        totalBytes: conv.total_bytes || 0,
        totalPackets: conv.total_packets || 0,
        duration: conv.duration || 0
      })) || []
    };
  }

  /**
   * Process geographical data
   */
  processGeoData(rawData) {
    return {
      countries: rawData.countries?.map(country => ({
        code: country.country_code,
        name: country.country_name,
        totalBytes: country.total_bytes || 0,
        totalPackets: country.total_packets || 0,
        coordinates: [country.longitude, country.latitude]
      })) || [],
      cities: rawData.cities?.map(city => ({
        name: city.city_name,
        country: city.country_name,
        totalBytes: city.total_bytes || 0,
        coordinates: [city.longitude, city.latitude]
      })) || []
    };
  }

  /**
   * Process anomaly detection data
   */
  processAnomalyData(rawData) {
    return {
      anomalies: rawData.anomalies?.map(anomaly => ({
        id: anomaly.id,
        type: anomaly.type,
        severity: anomaly.severity,
        score: anomaly.score,
        description: anomaly.description,
        timestamp: new Date(anomaly.timestamp),
        affectedHosts: anomaly.affected_hosts || [],
        metrics: anomaly.metrics || {}
      })) || [],
      summary: {
        totalAnomalies: rawData.total_count || 0,
        severityDistribution: rawData.severity_distribution || {},
        typeDistribution: rawData.type_distribution || {}
      }
    };
  }

  /**
   * Process custom query results
   */
  processCustomQueryData(rawData) {
    return {
      results: rawData.results || [],
      metadata: rawData.metadata || {},
      executionTime: rawData.execution_time || 0,
      totalRows: rawData.total_rows || 0
    };
  }

  /**
   * Calculate traffic statistics
   */
  calculateTrafficStats(data) {
    if (!data || !data.timeline || data.timeline.length === 0) {
      return null;
    }

    const values = data.timeline.map(point => point.bytes);
    const total = values.reduce((sum, val) => sum + val, 0);
    const avg = total / values.length;
    const max = Math.max(...values);
    const min = Math.min(...values);

    // Calculate standard deviation
    const variance = values.reduce((sum, val) => sum + Math.pow(val - avg, 2), 0) / values.length;
    const stdDev = Math.sqrt(variance);

    return {
      total,
      average: avg,
      maximum: max,
      minimum: min,
      standardDeviation: stdDev,
      growth: values.length > 1 ? ((values[values.length - 1] - values[0]) / values[0]) * 100 : 0
    };
  }

  /**
   * Clear all cached data
   */
  clearCache() {
    this.cache.clear();
  }

  /**
   * Generate analytics report
   */
  async generateReport(timeRange, includeCharts = false) {
    try {
      const [traffic, bandwidth, protocols, performance, topTalkers] = await Promise.all([
        this.getTrafficAnalytics(timeRange),
        this.getBandwidthMetrics(timeRange),
        this.getProtocolDistribution(timeRange),
        this.getPerformanceMetrics(timeRange),
        this.getTopTalkers(timeRange)
      ]);

      return {
        timestamp: new Date(),
        timeRange,
        summary: {
          totalTraffic: traffic.totalBytes,
          avgBandwidth: bandwidth.avgUtilization,
          topProtocol: protocols.distribution[0]?.protocol || 'N/A',
          avgLatency: performance.latency.avg
        },
        traffic,
        bandwidth,
        protocols,
        performance,
        topTalkers,
        includeCharts
      };
    } catch (error) {
      console.error('Error generating analytics report:', error);
      throw new Error('Failed to generate analytics report');
    }
  }
}

// Create and export singleton instance
const analyticsService = new AnalyticsService();
export default analyticsService;