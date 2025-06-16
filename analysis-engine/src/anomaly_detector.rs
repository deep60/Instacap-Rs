use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use tokio::time::interval;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMetrics {
    pub timestamp: u64,
    pub bytes_per_second: f64,
    pub packets_per_second: f64,
    pub connection_count: u32,
    pub unique_ips: u32,
    pub protocol_distribution: HashMap<String, u32>,
    pub port_activity: HashMap<u16, u32>,
    pub average_packet_size: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyAlert {
    pub alert_id: String,
    pub anomaly_type: AnomalyType,
    pub severity: Severity,
    pub description: String,
    pub timestamp: u64,
    pub confidence: f64,
    pub affected_metrics: Vec<String>,
    pub source_ip: Option<String>,
    pub destination_ip: Option<String>,
    pub protocol: Option<String>,
    pub port: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AnomalyType {
    TrafficSpike,
    UnusualProtocol,
    PortScanning,
    DDoSAttack,
    DataExfiltration,
    UnauthorizedAceess,
    PerformanceDegradation,
    SuspiciousTrafficPattern,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug)]
pub struct BaselineMetrics {
    pub avg_bytes_per_second: f64,
    pub avg_packets_per_second: f64,
    pub avg_connection_count: u32,
    pub avg_unique_ips: u32,
    pub std_bytes_per_second: f64,
    pub std_packets_per_second: f64,
    pub std_connection_count: f64,
    pub std_unique_ips: f64,
    pub common_protocols: HashMap<String, f64>,
    pub common_ports: HashMap<u16, f64>,
}

#[derive(Debug)]
pub struct AnomalyDetector {
    baseline: Option<BaselineMetrics>,
    metrics_history: VecDeque<NetworkMetrics>,
    port_scan_tracker: HashMap<String, PortSacnTracker>
    connection_tracker: HashMap<String, ConnectionTracker>,
    protocol_whitelist: Vec<String>,
    suspicious_ports: Vec<u16>,
    max_history_size: usize,
    learning_period: Duration,
    detection_threshold: DetectionThresholds,
    last_baseline_update: Option<Instant>,
}

#[derive(Debug)]
struct PortSacnTracker {
    port_accessed: std::collections::HashSet<u16,
    first_seen: Instant,
    last_activity: Instant,
}
#[derive(Debug)]
struct ConnectionTracker {
    connection_count: u32,
    first_seen: Instant,
    last_activity: Instant,
    bytes_transferred: u64,
}
#[derive(Debug, Clone)]
pub struct DetectionThresholds {
    pub traffic_spike_multiplier: f64,
    pub port_scan_threshold: u32,
    pub port_scan_time_window: Duration,
    pub ddos_connection_threshold: u32,
    pub ddos_time_window: Duration,
    pub data_exfiltration_threshold: u64,
    pub unusual_protocol_threshold: f64,
    pub performance_degradation_threshold: f64,
}

impl Default for DetectionThresholds {
    fn default() -> Self {
        DetectionThresholds {
            traffic_spike_multiplier: 3.0,
            port_scan_threshold: 20,
            port_scan_time_window: Duration::from_secs(60),
            ddos_connection_threshold: 1000,
            ddos_time_window: Duration::from_secs(10),
            data_exfiltration_threshold: 100 * 1024 * 1024, // 100 MB
            unusual_protocol_threshold: 0.01, // 1% of total traffic
            performance_degradation_threshold: 2.0,
        }
    }
}

impl AnomalyDetector {
    pub fn new() -> Self {
        Self {
            baseline: None,
            metrics_history: VecDeque::new(),
            port_scan_tracker: HashMap::new(),
            connection_tracker: HashMap::new(),
            protocol_whitelist: vec![
                "HTTP".to_string(),
                "HTTPS".to_string(),
                "DNS".to_string(),
                "FTP".to_string(),
                "SSH".to_string(),
                "SMTP".to_string(),
                "POP3".to_string(),
                "IMAP".to_string(),
            ],
            suspicious_ports: vec![
                23, 135, 137, 138, 139, 445, 1433, 1521, 3389, 5432, 5900, 6667,
            ],
            max_history_size: 1000,
            learning_period: Duration::from_secs(3600), // 1 hour
            detection_threshold: DetectionThresholds::default(),
            last_baseline_update: None,
        }
    }

    pub async fn analyze_metrics(&mut self, metrics: NetworkMetrics) -> Vec<AnomalyAlert> {
        let mut alerts = Vec::new();

        // Add metrics to history
        self.add_metrics_to_history(metrics.clone());

        // Update baseline if needed
        if self.should_update_baseline() {
            self.update_baseline();
        }

        // Perform anomaly detection if baseline exists
        if let Some(baseline) = &self.baseline {
            // Taffic spike detection
            alerts.extend(self.detect_traffic_spikes(&metrics, baseline));

            // Unusual protocol usage detection
            alerts.extend(self.detect_unusual_protocol_usage(&metrics, baseline));

            //Performance degradation detection
            alerts.extend(self.detect_performance_issues(&metrics, baseline));
        }

        // Behavioral analysis (does not require baseline)
        alerts.extend(self.detect_port_scanning(&metrics));
        alerts.extend(self.detect_ddos_patterns(&metrics));
        alerts.extend(self.detect_data_exfiltration(&metrics));
        alerts.extend(self.detect_suspicious_traffic_patterns(&metrics));

        // Clean up old tracking data
        self.cleanup_trackers();
        alerts
    }

    fn add_metrics_to_history(&mut self, metrics: NetworkMetrics) {
        self.metrics_history.push_back(metrics);
        if self.metrics_history.len() > self.max_history_size {
            self.metrics_history.pop_front();
        }
    }

    fn should_update_baseline(&self) -> bool {
        match self.last_baseline_update {
            Some(last_update) => { last_update.elapsed() > self.learning_period && self.metrics_history.len() >= 50 },
            None => self.metrics_history,len() >= 100,
        }
    }

    fn update_baseline(&mut self) {
        if self.metrics_history.len() < 10 {
            return;
        }

        let mut bytes_per_second: Vec<f64> = Vec::new();
        let mut packets_per_second: Vec<f64> = Vec::new();
        let mut connection_counts: Vec<f64> = Vec::new();
        let mut unique_ips: Vec<f64> = Vec::new();
        let mut protocol_counts: HashMap<String, Vec<u32>> = HashMap::new();
        let mut port_counts: HashMap<u16, Vec<u32>> = HashMap::new();

        for metrics in &self.metrics_history {
            bytes_per_second.push(metrics.bytes_per_second);
            packets_per_second.push(metrics.packets_per_second);
            connection_counts.push(metrics.connection_count as f64);
            unique_ips.push(metrics.unique_ips as f64);

            for (protocol, count) in &metrics.protocol_distribution {
                protocol_counts.entry(protocol.clone()).or_insert_with(Vec::new).push(*count);
            }

            for (port, count) in &metrics.port_activity {
                port_counts.entry(*port).or_insert_with(Vec::new).push(*count);
            }
        }

        let baseline = BaselineMetrics {
            avg_bytes_per_second: calculate_mean(&bytes_per_second),
            avg_packets_per_second: calculate_mean(&packets_per_second),
            avg_connection_count: calculate_mean(&connection_counts),
            avg_unique_ips: calculate_mean(&unique_ips),
            std_bytes_per_second: calculate_std_dev(&bytes_per_second),
            std_packets_per_second: calculate_std_dev(&packets_per_second),
            std_connection_count: calculate_std_dev(&connection_counts),
            std_unique_ips: calculate_std_dev(&unique_ips),
            common_protocols: protocol_counts.into_iter()
                .map(|(k, v)| (k, calculate_mean(&v.into_iter().map(|x| x as f64).collect())))
                .collect(),
            common_ports: port_counts.into_iter()
                .map(|(k, v)| (k, calculate_mean(&v.into_iter().map(|x| x as f64).collect())))
                .collect(),
        };
        self.baseline = Some(baseline);
        self.last_baseline_update = Some(Instant::now());
    }

    fn detect_traffic_spikes(&self, metrics: &NetworkMetrics, baseline: &BaselineMetrics) -> Vec<AnomalyAlert> {
        let mut alerts = Vec::new();
        // Check bytes per second spike
        if metrics.bytes_per_second > baseline.avg_bytes_per_second + (baseline.std_bytes_per_second * self.detection_threshold.traffic_spike_multiplier) {
            alerts.push(AnomalyAlert {
                alert_id: format!("traffic_spike_{}", metrics.timestamp),
                anomaly_type: AnomalyType::TrafficSpike,
                severity: Severity::High,
                description: format!(
                    "Traffic spike detected: {:.2} bytes/sec (baseline: {:.2} ± {:.2})",
                    metrics.bytes_per_second,
                    baseline.avg_bytes_per_second,
                    baseline.std_bytes_per_second
                ),
                timestamp: metrics.timestamp,
                confidence: calculate_confidence(
                    metrics.bytes_per_second,
                    baseline.avg_bytes_per_second,
                    baseline.std_bytes_per_second
                ),
                affected_metrics: vec!["bytes_per_second".to_string()],
                source_ip: None,
                destination_ip: None,
                protocol: None,
                port: None,
            });
        }

        // Check packets per second spike
        if metrics.packets_per_second > baseline.avg_packets_per_second + (baseline.std_packets_per_second * self.detection_threshold.traffic_spike_multiplier) {
            alerts.push(AnomalyAlert {
                alert_id: format!("packets_spike_{}", metrics.timestamp),
                anomaly_type: AnomalyType::TrafficSpike,
                severity: Severity::High,
                description: format!(
                    "Packets per second spike detected: {:.2} packets/sec (baseline: {:.2} ± {:.2})",
                    metrics.packets_per_second,
                    baseline.avg_packets_per_second,
                    baseline.std_packets_per_second
                ),
                timestamp: metrics.timestamp,
                confidence: calculate_confidence(
                    metrics.packets_per_second,
                    baseline.avg_packets_per_second,
                    baseline.std_packets_per_second
                ),
                affected_metrics: vec!["packets_per_second".to_string()],
                source_ip: None,
                destination_ip: None,
                protocol: None,
                port: None,
            });
        }

        alerts
    }

    fn detect_unusual_protocols(&self, metrics: &NetworkMetrics, baseline: &BaselineMetrics) -> Vec<AnomalyAlert> {
        let mut alerts = Vec::new();

        let total_protocol_activity: u32 = metrics.protocol_distribution.values().sum();)

        for (protocol, count) in &metrics.protocol_distribution {
            let percentage = *count as f64 / total_protocol_activity as f64;
            // Check if protocol is not in whitelist and has significant activity
            if !self.protocol_whitelist.contains(protocol) && percentage > self.detection_threshold.unusual_protocol_threshold {
                alerts.push(AnomalyAlert {
                    alert_id: format!("unusual_protocol_{}_{}", protocol, metrics.timestamp),
                    anomaly_type: AnomalyType::UnusualProtocol,
                    severity: Severity::Medium,
                    description: format!(
                        "Unusual protocol detected: {}  ({:.2}% of traffic)",
                        protocol, percentage * 100.0,
                    ),
                    timestamp: metrics.timestamp,
                    confidence: percentage.min(1.0),
                    affected_metrics: vec!["protocol_distribution".to_string()],
                    source_ip: None,
                    destination_ip: None,
                    protocol: Some(protocol.clone()),
                    port: None,
                });
            }
        }
        alerts
    }

    fn detect_port_scanning(&mut self, metrics: &NetworkMetrics) -> Vec<AnomalyAlert> {
        let mut alerts = Vec::new();
        let now = Instant::now();

        // This is a simplified port scan detection
        // In a real implementation, you'd need packet_level data
        for (port, activity) in &metrics.port_activity {
            if self.suspicious_ports.contains(port) && *activity > 10 {
                alerts.push(AnomalyAlert {
                    alert_id: format!("suspicious_port_{}_{}", port, metrics.timestamp),
                    anomaly_type: AnomalyType::PortScanning,
                    severity: Severity::High,
                    description: format!("High activity on suspicious port: {}", port),
                    timestamp: metrics.timestamp,
                    confidence: 0.7,
                    affected_metrics: vec!["port_activity".to_string()],
                    source_ip: None,
                    destination_ip: None,
                    protocol: None,
                    port: Some(*port),
                })
        }

        alerts
    }

    fn detect_ddos_patterns(&mut self, metrics: &NetworkMetrics) -> Vec<AnomalyAlert> {
        let mut alerts = Vec::new();

        // Simple DDoS detection based on connection count
        if metrics.connection_count > self.detection_threshold.ddos_connection_threshold {
            alerts.push(AnomalyAlert {
                alert_id: format!("ddos_attack_{}", metrics.timestamp),
                anomaly_type: AnomalyType::DDoSAttack,
                severity: Severity::Critical,
                description: format!(
                    "Potential DDoS attack detected: {} connections in a short time",
                    metrics.connection_count
                ),
                timestamp: metrics.timestamp,
                confidence: 0.8,
                affected_metrics: vec!["connection_count".to_string()],
                source_ip: None,
                destination_ip: None,
                protocol: None,
                port: None,
            });
        }

        alerts
    }

    fn detect_data_exfiltration(&mut self, metrics: &NetworkMetrics) -> Vec<AnomalyAlert> {
        let mut alerts = Vec::new();

        // Simple data exfiltration detection based on bytes transferred
        if metrics.bytes_per_second > self.detection_threshold.data_exfiltration_threshold as f64 {
            alerts.push(AnomalyAlert {
                alert_id: format!("data_exfiltration_{}", metrics.timestamp),
                anomaly_type: AnomalyType::DataExfiltration,
                severity: Severity::Critical,
                description: format!(
                    "Potential data exfiltration detected: {:.2} MB/sec outbound traffic",
                    metrics.bytes_per_second / (1024 * 1024)
                ),
                timestamp: metrics.timestamp,
                confidence: 0.6,
                affected_metrics: vec!["bytes_per_second".to_string()],
                source_ip: None,
                destination_ip: None,
                protocol: None,
                port: None,
            });
        }

        alerts
    }

    fn detect_performance_issues(&self, metrics: &NetworkMetrics, baseline: &BaselineMetrics) -> Vec<AnomalyAlert> {
        let mut alerts = Vec::new();

        // Check for performance degradation based on average packet size
        if metrics.average_packet_size > baseline.avg_bytes_per_second * self.detection_threshold.performance_degradation_threshold {
            alerts.push(AnomalyAlert {
                alert_id: format!("performance_degradation_{}", metrics.timestamp),
                anomaly_type: AnomalyType::PerformanceDegradation,
                severity: Severity::Medium,
                description: format!(
                    "Performance degradation detected: Average packet size {:.2} bytes (baseline: {:.2} bytes)",
                    metrics.average_packet_size,
                    baseline.avg_bytes_per_second
                ),
                timestamp: metrics.timestamp,
                confidence: 0.5,
                affected_metrics: vec!["average_packet_size".to_string()],
                source_ip: None,
                destination_ip: None,
                protocol: None,
                port: None,
            });
        }

        alerts
    }
    fn detect_suspicious_traffic_patterns(&self, metrics: &NetworkMetrics) -> Vec<AnomalyAlert> {
        let mut alerts = Vec::new();

        // Detect traffic patterns that may indicate suspicious activity
        let total_connections = metrics.connection_count;
        let unique_ips = metrics.unique_ips;

        // High connection count with low unique IPs might indicate malicioous activity
        if total_connections > 100 && unique_ips > 0 {
            let connection_per_ip = total_connections as f64 / unique_ips as f64;
            if connection_per_ip > 50.0 { // Arbitrary threshold for suspicious activity
                alerts.push(AnomalyAlert {
                    alert_id: format!("suspicious_pattern_{}", metrics.timestamp),
                    anomaly_type: AnomalyType::SuspiciousTrafficPattern,
                    severity: Severity::Medium,
                    description: format!(
                        "Suspicious traffic pattern detected: {} connections from only {} unique IPs ({} connections per IP)",
                        total_connections, unique_ips, connection_per_ip
                    ),
                    timestamp: metrics.timestamp,
                    confidence: 0.7,
                    affected_metrics: vec!["connection_count".to_string(), "unique_ips".to_string()],
                    source_ip: None,
                    destination_ip: None,
                    protocol: None,
                    port: None,
                });
            }
        }
        alerts
    }

    fn calculate_mean(values: &[f64]) -> f64 {
        if values.is_empty() {
            return 0.0;
        }
        values.iter().sum::<f64>() / values.len() as f64
    }                                                                                                                                                                                                                                                                                                                                                                                                                       

    fn cleanup_trackers(&mut self) {
        let now = Instant::now();
        let cleanup_threshold = Duration::from_secs(300); // 5 minutes

        // Clean up port scan trackers
        self.port_scan_tracker.retain(|_, tracker| {
            now.duration_since(tracker.last_activity) < cleanup_threshold
        });

        // Clean up connection trackers
        self.connection_tracker.retain(|_, tracker| {
            now.duration_since(tracker.last_activity) < cleanup_threshold
        });
    }

    pub fn get_current_baseline(&self) -> Option<&BaselineMetrics> {
        self.baseline.as_ref()
    }

    pub fn update_thresholds(&mut self, thresholds: DetectionThresholds) {
        self.detection_threshold = thresholds;
    } 

    fn calculate_std_dev(values: &[f64]) -> f64 {
        if values.len < 2 {
            return 0.0;
        }
        let mean = Self::calculate_mean(values);
        let variance = values.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (values.len() - 1) as f64;
        variance.sqrt()
    }

    fn calculate_confidence(current: f64, baseline: f64, std_dev: f64) -> f64 {
        if std_dev == 0.0 {
            return if current == baseline { 1.0 } else { 0.0 }; // No variation, full confidence
        }
        let z_score = (current - baseline).abs() / std_dev;
        (z_score / 5.0).min(1.0) // Normalize to [0, 1]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_anomaly_detector_creation() {
        let detector = AnomalyDetector::new();
        assert!(detector.baseline.is_none());
        assert_eq!(detector.metric_history.len(), 0);
    }

    #[tokio::test]
    async fn test_traffic_spike_detection() {
        let mut detector = AnomalyDetector::new();
        
        // Create baseline metrics
        for i in 0..100 {
            let metrics = NetworkMetrics {
                timestamp: i,
                bytes_per_second: 1000.0,
                packets_per_second: 100.0,
                connection_count: 50,
                unique_ips: 10,
                protocol_distribution: HashMap::new(),
                port_activity: HashMap::new(),
                average_packet_size: 1024.0,
            };
            detector.analyze_metrics(metrics).await;
        }
        
        // Create spike
        let spike_metrics = NetworkMetrics {
            timestamp: 101,
            bytes_per_second: 10000.0, // 10x normal
            packets_per_second: 100.0,
            connection_count: 50,
            unique_ips: 10,
            protocol_distribution: HashMap::new(),
            port_activity: HashMap::new(),
            average_packet_size: 1024.0,
        };
        
        let alerts = detector.analyze_metrics(spike_metrics).await;
        assert!(!alerts.is_empty());
        assert!(alerts.iter().any(|a| matches!(a.anomaly_type, AnomalyType::TrafficSpike)));
    }
}
