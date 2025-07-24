// Main API service 

const API_BASE_URL = process.env.REACT_APP_API_BASE_URL || 'http://localhost:8080/api';
const ANALYSIS_ENGINE_URL = process.env.REACT_APP_ANALYSIS_ENGINE_URL || 'http://localhost:8081/api';
const ML_MODELS_URL = process.env.REACT_APP_ML_MODELS_URL || 'http://localhost:8082/api';

// API response interceptor for error handling
class ApiError extends Error {
  constructor(message, status, data) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.data = data;
  }
}

// Base API class with common functionality
class ApiService {
  constructor(baseURL = API_BASE_URL) {
    this.baseURL = baseURL;
    this.headers = {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    };
  }

  // Set authentication token
  setAuthToken(token) {
    if (token) {
      this.headers['Authorization'] = `Bearer ${token}`;
    } else {
      delete this.headers['Authorization'];
    }
  }

  // Generic request method
  async request(endpoint, options = {}) {
    const url = `${this.baseURL}${endpoint}`;
    const config = {
      headers: { ...this.headers, ...options.headers },
      ...options,
    };

    try {
      const response = await fetch(url, config);
      
      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new ApiError(
          errorData.message || `HTTP ${response.status}: ${response.statusText}`,
          response.status,
          errorData
        );
      }

      const contentType = response.headers.get('content-type');
      if (contentType && contentType.includes('application/json')) {
        return await response.json();
      }
      
      return await response.text();
    } catch (error) {
      if (error instanceof ApiError) {
        throw error;
      }
      throw new ApiError(`Network error: ${error.message}`, 0, null);
    }
  }

  // HTTP methods
  async get(endpoint, params = {}) {
    const queryString = new URLSearchParams(params).toString();
    const url = queryString ? `${endpoint}?${queryString}` : endpoint;
    return this.request(url, { method: 'GET' });
  }

  async post(endpoint, data = {}) {
    return this.request(endpoint, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async put(endpoint, data = {}) {
    return this.request(endpoint, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  }

  async patch(endpoint, data = {}) {
    return this.request(endpoint, {
      method: 'PATCH',
      body: JSON.stringify(data),
    });
  }

  async delete(endpoint) {
    return this.request(endpoint, { method: 'DELETE' });
  }
}

// Service instances
export const packetCaptureApi = new ApiService(API_BASE_URL);
export const analysisEngineApi = new ApiService(ANALYSIS_ENGINE_URL);
export const mlModelsApi = new ApiService(ML_MODELS_URL);

// Dashboard API endpoints
export const dashboardApi = {
  // Get real-time statistics
  getStats: () => packetCaptureApi.get('/stats'),
  
  // Get system health status
  getSystemHealth: () => packetCaptureApi.get('/health'),
  
  // Get traffic overview
  getTrafficOverview: (timeRange = '1h') => 
    packetCaptureApi.get('/traffic/overview', { timeRange }),
};

// Packet capture API endpoints
export const captureApi = {
  // Start packet capture
  startCapture: (config) => packetCaptureApi.post('/capture/start', config),
  
  // Stop packet capture
  stopCapture: () => packetCaptureApi.post('/capture/stop'),
  
  // Get capture status
  getCaptureStatus: () => packetCaptureApi.get('/capture/status'),
  
  // Get capture statistics
  getCaptureStats: () => packetCaptureApi.get('/capture/stats'),
  
  // Update capture filters
  updateFilters: (filters) => packetCaptureApi.put('/capture/filters', filters),
};

// Traffic analysis API endpoints
export const trafficApi = {
  // Get traffic data with pagination
  getTrafficData: (params = {}) => 
    analysisEngineApi.get('/traffic', params),
  
  // Get protocol distribution
  getProtocolDistribution: (timeRange = '1h') => 
    analysisEngineApi.get('/traffic/protocols', { timeRange }),
  
  // Get top talkers
  getTopTalkers: (limit = 10, timeRange = '1h') => 
    analysisEngineApi.get('/traffic/top-talkers', { limit, timeRange }),
  
  // Get geographic traffic distribution
  getGeoTraffic: (timeRange = '1h') => 
    analysisEngineApi.get('/traffic/geographic', { timeRange }),
};

// Threat detection API endpoints
export const threatApi = {
  // Get active threats
  getActiveThreats: () => analysisEngineApi.get('/threats/active'),
  
  // Get threat history
  getThreatHistory: (params = {}) => 
    analysisEngineApi.get('/threats/history', params),
  
  // Get threat details
  getThreatDetails: (threatId) => 
    analysisEngineApi.get(`/threats/${threatId}`),
  
  // Update threat status
  updateThreatStatus: (threatId, status) => 
    analysisEngineApi.patch(`/threats/${threatId}`, { status }),
  
  // Get threat statistics
  getThreatStats: (timeRange = '24h') => 
    analysisEngineApi.get('/threats/stats', { timeRange }),
};

// Anomaly detection API endpoints
export const anomalyApi = {
  // Get detected anomalies
  getAnomalies: (params = {}) => 
    analysisEngineApi.get('/anomalies', params),
  
  // Get anomaly details
  getAnomalyDetails: (anomalyId) => 
    analysisEngineApi.get(`/anomalies/${anomalyId}`),
  
  // Mark anomaly as reviewed
  markAnomalyReviewed: (anomalyId) => 
    analysisEngineApi.patch(`/anomalies/${anomalyId}`, { reviewed: true }),
};

// Performance monitoring API endpoints
export const performanceApi = {
  // Get performance metrics
  getMetrics: (timeRange = '1h') => 
    packetCaptureApi.get('/performance/metrics', { timeRange }),
  
  // Get latency data
  getLatencyData: (timeRange = '1h') => 
    packetCaptureApi.get('/performance/latency', { timeRange }),
  
  // Get bandwidth utilization
  getBandwidthData: (timeRange = '1h') => 
    packetCaptureApi.get('/performance/bandwidth', { timeRange }),
  
  // Get packet loss statistics
  getPacketLoss: (timeRange = '1h') => 
    packetCaptureApi.get('/performance/packet-loss', { timeRange }),
};

// Machine Learning API endpoints
export const mlApi = {
  // Get ML model status
  getModelStatus: () => mlModelsApi.get('/models/status'),
  
  // Retrain anomaly detection model
  retrainAnomalyModel: () => mlModelsApi.post('/models/anomaly/retrain'),
  
  // Get threat predictions
  getThreatPredictions: () => mlModelsApi.get('/predictions/threats'),
  
  // Get performance predictions
  getPerformancePredictions: (timeAhead = '1h') => 
    mlModelsApi.get('/predictions/performance', { timeAhead }),
};

// Alerts API endpoints
export const alertsApi = {
  // Get active alerts
  getActiveAlerts: () => analysisEngineApi.get('/alerts/active'),
  
  // Get alert history
  getAlertHistory: (params = {}) => 
    analysisEngineApi.get('/alerts/history', params),
  
  // Acknowledge alert
  acknowledgeAlert: (alertId) => 
    analysisEngineApi.patch(`/alerts/${alertId}/acknowledge`),
  
  // Dismiss alert
  dismissAlert: (alertId) => 
    analysisEngineApi.patch(`/alerts/${alertId}/dismiss`),
  
  // Update alert rules
  updateAlertRules: (rules) => 
    analysisEngineApi.put('/alerts/rules', rules),
};

// Configuration API endpoints
export const configApi = {
  // Get configuration
  getConfig: () => packetCaptureApi.get('/config'),
  
  // Update configuration
  updateConfig: (config) => packetCaptureApi.put('/config', config),
  
  // Get detection rules
  getDetectionRules: () => analysisEngineApi.get('/config/rules'),
  
  // Update detection rules
  updateDetectionRules: (rules) => 
    analysisEngineApi.put('/config/rules', rules),
  
  // Get thresholds
  getThresholds: () => analysisEngineApi.get('/config/thresholds'),
  
  // Update thresholds
  updateThresholds: (thresholds) => 
    analysisEngineApi.put('/config/thresholds', thresholds),
};

// Configuration function
export const setApiBaseUrl = (baseUrl) => {
  packetCaptureApi.baseURL = baseUrl;
  analysisEngineApi.baseURL = baseUrl.replace('8080', '8081');
  mlModelsApi.baseURL = baseUrl.replace('8080', '8082');
};

// Export default API instance
export default packetCaptureApi;
