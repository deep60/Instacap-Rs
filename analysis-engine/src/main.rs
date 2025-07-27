use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, RwLock};
use tokio::time::interval;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

mod anomaly_detector;
mod threat_detector;
mod traffic_analyzer;
mod alert_manager;

use anomaly_detector::AnomalyDetector;
use threat_detector::ThreatDetector;
use traffic_analyzer::TrafficAnalyzer;
use alert_manager::AlertManager;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketData {
    pub timestamp: u64,
    pub source_ip: String,
    pub dest_ip: String,
    pub source_port: u16,
    pub dest_port: u16,
    pub protocol: String,
    pub packet_size: usize,
    pub payload: Vec<u8>,
    pub flags: HashMap<String, bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: String,
    pub severity: AlertSeverity,
    pub alert_type: AlertType,
    pub message: String,
    pub timestamp: u64,
    pub source_ip: Option<String>,
    pub dest_ip: Option<String>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertType {
    Anomaly,
    Threat,
    Performance,
    Security,
}

pub struct AnalysisConfig {
    pub anomaly_threshold: f64,
    pub threat_score_threshold: f64,
    pub performance_window_ms: u64,
    pub max_alerts_per_minute: usize,
    pub enable_deep_inspection: bool,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            anomaly_threshold: 0.8,
            threat_score_threshold: 0.7,
            performance_window_ms: 5000,
            max_alerts_per_minute: 50,
            enable_deep_inspection: true,
        }
    }
}

pub struct AnalysisEngine {
    anomaly_detector: AnomalyDetector,
    threat_detector: ThreatDetector,
    traffic_analyzer: TrafficAnalyzer,
    alert_manager: AlertManager,
    config: Arc<RwLock<AnalysisConfig>>,
    packet_rx: mpsc::Receiver<PacketData>,
    alert_tx: mpsc::Sender<Alert>, 
}

impl AnalysisEngine {
    pub fn new(
        packet_rx: mpsc::Receiver<PacketData>,
        alert_tx: mpsc::Sender<Alert>,
        config: AnalysisConfig,
    ) -> Self {
        let config = Arc::new(RwLock::new(config));

        let (threat_alert_tx, _threat_alert_rx) = mpsc::channel(100);
        
        Self {
            anomaly_detector: AnomalyDetector::new(),
            threat_detector: ThreatDetector::new(threat_alert_tx),
            traffic_analyzer: TrafficAnalyzer::new(60), // 60 second window
            alert_manager: AlertManager::new(100, Duration::from_secs(3600)), // Max alerts, retention period
            config,
            packet_rx,
            alert_tx,
        }
    }

    pub async fn start(&mut self) -> Result<(), Box<dyn std::error::Error + Send>> {
        println!("Starting Analysis Engine...");

        // Start background tasks
        let mut performance_interval = interval(Duration::from_millis(1000));
        let mut cleanup_interval = interval(Duration::from_secs(300));    // 5 minutes

        // Main analysis loop
        loop {
            tokio::select! {
                // Process incoming packets
                packet_result = self.packet_rx.recv() => {
                    match packet_result {
                        Some(packet) => {
                            if let Err(e) = self.process_packet(packet).await {
                                eprintln!("Error processing packets: {}", e);
                            }
                        }
                        None => {
                            println!("Packet channel closed, shutting down analysis engine...");
                            break;
                        }
                    }
                }

                // Periodic performance analysis
                _ = performance_interval.tick() => {
                    if let Err(e) = self.analyze_performance().await {
                        eprintln!("Error in performance analysis: {}", e);
                    }
                }

                // Periodic cleanup
                _ = cleanup_interval.tick() => {
                    if let Err(e) = self.cleanup_old_data().await {
                        eprintln!("Error in cleanup: {}", e);
                    }
                }

                else => {
                    println!("Analysis engine shutting down..");
                    break;
                }
            }
        }

        Ok(())
    }

    async fn process_packet(&mut self, packet: PacketData) -> Result<(), Box<dyn std::error::Error + Send>> {
        // Update traffic statistics
        self.traffic_analyzer.update_stats(&packet).await;

        // Run anomaly detection
        let anomaly_alerts = self.anomaly_detector.analyze(&packet).await?;
        for anomaly_alert in anomaly_alerts {
            // Convert AnomalyAlert to Alert
            let alert = Alert {
                id: anomaly_alert.alert_id,
                severity: match anomaly_alert.severity {
                    anomaly_detector::Severity::Low => AlertSeverity::Low,
                    anomaly_detector::Severity::Medium => AlertSeverity::Medium,
                    anomaly_detector::Severity::High => AlertSeverity::High,
                    anomaly_detector::Severity::Critical => AlertSeverity::Critical,
                },
                alert_type: AlertType::Anomaly,
                message: anomaly_alert.description,
                timestamp: anomaly_alert.timestamp,
                source_ip: anomaly_alert.source_ip,
                dest_ip: anomaly_alert.destination_ip,
                metadata: HashMap::from([
                    ("confidence".to_string(), anomaly_alert.confidence.to_string()),
                    ("anomaly_type".to_string(), format!("{:?}", anomaly_alert.anomaly_type)),
                    ("affected_metrics".to_string(), anomaly_alert.affected_metrics.join(", ")),
                ]),
            };
            
            self.send_alert(alert).await?;
        }

        // Run threat detection
        if let Some(threat_score) = self.threat_detector.analyze_packet(&packet).await? {
            let threat_score_threshold = {
                let config = self.config.read().await;
                config.threat_score_threshold
            };
            if threat_score > threat_score_threshold {
                let alert = Alert {
                    id: format!("threat_{}", packet.timestamp),
                    severity: self.calculate_threat_severity(threat_score),
                    alert_type: AlertType::Threat,
                    message: format!("Potential threat detected (score: {:.2})", threat_score),
                    timestamp: packet.timestamp,
                    source_ip: Some(packet.source_ip.clone()),
                    dest_ip: Some(packet.dest_ip.clone()),
                    metadata: self.create_threat_metadata(&packet, threat_score),
                };

                self.send_alert(alert).await?;
            }
        }

        // Deep packet inspection if enabled
        let enable_deep_inspection = {
            let config = self.config.read().await;
            config.enable_deep_inspection
        };
        if enable_deep_inspection {
            if let Some(security_issues) = self.deep_inspect_payload(&packet).await? {
                for issue in security_issues {
                    let alert = Alert {
                        id: format!("security_{}_{}", packet.timestamp, issue.issue_type),
                        severity: issue.severity,
                        alert_type: AlertType::Security,
                        message: issue.description,
                        timestamp: packet.timestamp,
                        source_ip: Some(packet.source_ip.clone()),
                        dest_ip: Some(packet.dest_ip.clone()),
                        metadata: issue.metadata,
                    };

                    self.send_alert(alert).await?;
                }
            }
        }

        Ok(())
    }

    async fn analyze_performance(&mut self) -> Result<(), Box<dyn std::error::Error + Send>> {
        let metrics = self.traffic_analyzer.get_performance_metrics().await;

        // Check for performance issues
        if metrics.packet_loss_rate > 0.05 {     //5% packet loss
            let alert = Alert {
                id: format!("perf_loss_{}", chrono::Utc::now().timestamp()),
                severity: AlertSeverity::High,
                alert_type: AlertType::Performance,
                message: format!("High packet loss detected (rate: {:.2})", metrics.packet_loss_rate),
                timestamp: chrono::Utc::now().timestamp() as u64,
                source_ip: None,
                dest_ip: None,
                metadata: HashMap::from([
                    ("metric_type".to_string(), "packet_loss".to_string()),
                    ("rate".to_string(), metrics.packet_loss_rate.to_string()),
                ]),
            };

            self.send_alert(alert).await?;
        }

        if metrics.average_latency_ms > 100.0 {        //High latency
            let alert = Alert {
                id: format!("perf_latency_{}", chrono::Utc::now().timestamp()),
                severity: AlertSeverity::Medium,
                alert_type: AlertType::Performance,
                message: format!("High latency detected: {:.2}ms", metrics.average_latency_ms),
                timestamp: chrono::Utc::now().timestamp() as u64,
                source_ip: None,
                dest_ip: None,
                metadata: HashMap::from([
                    ("metric_type".to_string(), "latency".to_string()),
                    ("latency_ms".to_string(), metrics.average_latency_ms.to_string()),
                ]),
            };
            self.send_alert(alert).await?;
        }

        // Check for traffic spikes
        if metrics.packet_per_second > 10000 {      // Configurable threshold
            let alert = Alert {
                id: format!("perf_spike_{}", chrono::Utc::now().timestamp()),
                severity: AlertSeverity::Medium,
                alert_type: AlertType::Performance,
                message: format!("Traffic spike detected: {} pps", metrics.packet_per_second),
                timestamp: chrono::Utc::now().timestamp() as u64,
                source_ip: None,
                dest_ip: None,
                metadata: HashMap::from([
                    ("metric_type".to_string(), "traffic_spike".to_string()),
                    ("pps".to_string(), metrics.packet_per_second.to_string()),
                ]),
            };

            self.send_alert(alert).await?;
        }

        Ok(())
    }

    async fn cleanup_old_data(&mut self) -> Result<(), Box<dyn std::error::Error + Send>> {
        // Clean up old data from detectors old analyzers
        self.anomaly_detector.cleanup_old_data().await?;
        self.threat_detector.cleanup_old_data().await?;
        self.traffic_analyzer.cleanup_old_data();
        self.alert_manager.cleanup_old_data().await?;

        println!("Cleanup completed");
        Ok(())
    }

    async fn send_alert(&mut self, alert: Alert) -> Result<(), Box<dyn std::error::Error + Send>> {
        // Rate limiting check
        if !self.alert_manager.should_send_alert(&alert).await {
            return Ok(());
        }

        // Record the alert
        self.alert_manager.record_alert(&alert).await;

        // Send the alert
        if let Err(e) = self.alert_tx.send(alert.clone()).await {
            eprintln!("Failed to send alert: {}", e);
        }

        // Log the alert
        println!("ALERT: [{:?}] {}", alert.severity, alert.message);

        Ok(())
    }


    fn calculate_threat_severity(&self, score: f64) -> AlertSeverity {
        match score {
            s if s >= 0.9 => AlertSeverity::Critical,
            s if s >= 0.8 => AlertSeverity::High,
            s if s >= 0.75 => AlertSeverity::Medium,
            _ => AlertSeverity::Low,
        }
    }

    fn create_threat_metadata(&self, packet: &PacketData, score: f64) -> HashMap<String, String> {
        HashMap::from([
            ("detection_type".to_string(), "threat".to_string()),
            ("threat_score".to_string(), score.to_string()),
            ("protocol".to_string(), packet.protocol.clone()),
            ("packet_size".to_string(), packet.packet_size.to_string()),
            ("source_port".to_string(), packet.source_port.to_string()),
            ("dest_port".to_string(), packet.dest_port.to_string()),
        ])
    }

    async fn deep_inspect_payload(&self, packet: &PacketData) -> Result<Option<Vec<SecurityIssue>>, Box<dyn std::error::Error + Send>> {
        let mut issues = Vec::new();

        // Check for suspicious patterns in payload
        if self.contains_suspicious_patterns(&packet.payload) {
            issues.push(SecurityIssue {
                issue_type: "suspicious_payload".to_string(),
                severity: AlertSeverity::High,
                description: "Suspicious patterns detected in packet payload".to_string(),
                metadata: HashMap::from([
                    ("payload_size".to_string(), packet.payload.len().to_string()),
                    ("protocol".to_string(), packet.protocol.clone()),
                ]),
            });
        }

        // Check for known malware signatures
        if self.check_malware_signatures(&packet.payload) {
            issues.push(SecurityIssue {
                issue_type: "malware_signature".to_string(),
                severity: AlertSeverity::Critical,
                description: "Known malware signature detected".to_string(),
                metadata: HashMap::from([
                    ("detection_method".to_string(), "signature".to_string()),
                    ("protocol".to_string(), packet.protocol.clone()),
                ]),
            });
        }

        if issues.is_empty() {
            Ok(None)
        } else {
            Ok(Some(issues))
        }
    }

    fn contains_suspicious_patterns(&self, payload: &[u8]) -> bool {
        // Simple pattern matching for demonstration
        let suspicious_strings = [
            "SELECT * FROM",
            "DROP TABLE",
            "../../../",
            "<script>",
            "eval(",
            "cmd.exe",
            "/bin/sh",
        ];

        let payload_str = String::from_utf8_lossy(payload);
        for pattern in &suspicious_strings {
            if payload_str.contains(pattern) {
                return true;
            }
        }

        false
    }

    fn check_malware_signatures(&self, payload: &[u8]) -> bool {
        // Simplified malware signature detection
        let pe_header = b"\x4d\x5a\x90\x00";
        let eicar_sig = b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE";
        
        // Check for PE header
        if payload.len() >= pe_header.len() {
            if payload.windows(pe_header.len()).any(|window| window == pe_header) {
                return true;
            }
        }
        
        // Check for EICAR signature
        if payload.len() >= eicar_sig.len() {
            if payload.windows(eicar_sig.len()).any(|window| window == eicar_sig) {
                return true;
            }
        }

        false
    }
}

#[derive(Debug, Clone)]
struct SecurityIssue {
    issue_type: String,
    severity: AlertSeverity,
    description: String,
    metadata: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct PerformanceMetrics {
    pub packet_per_second: u64,
    pub bytes_per_second: u64,
    pub average_latency_ms: f64,
    pub packet_loss_rate: f64,
    pub jitter_ms: f64,
    pub connection_count: u64,
    pub protocol_distribution: HashMap<String, u64>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send>> {
    println!("Starting Network Analysis Engine");

    // Create channels for communication
    let (packet_tx, packet_rx) = mpsc::channel::<PacketData>(10000);
    let (alert_tx, mut alert_rx) = mpsc::channel::<Alert>(1000);

    // Load configuration
    let config = AnalysisConfig::default();

    // Create and start the analysis engine
    let mut engine = AnalysisEngine::new(packet_rx, alert_tx, config);

    // Start alert handler
    let alert_handler = tokio::spawn(async move {
        while let Some(alert) = alert_rx.recv().await {
            // Handle alerts - could send to external systems, log to database, etc.
            println!("Alert received: {:?}", alert);

            // Example: Send to external monitoring system
            // external_monitor::send_alert(alert).await;
            
            // Example: Store in database
            // database::store_alert(alert).await;
        }
    });

    // Example: Start packet injection for testing
    let packet_injector = tokio::spawn(async move {
        let mut counter = 0;
        let mut interval = interval(Duration::from_millis(10));

        loop {
            interval.tick().await;

            let test_packet = PacketData {
                timestamp: chrono::Utc::now().timestamp() as u64,
                source_ip: format!("192.168.1.{}", counter % 255),
                dest_ip: "10.0.0.1".to_string(),
                source_port: 12345 + (counter % 1000) as u16,
                dest_port: 80,
                protocol: "TCP".to_string(),
                packet_size: 1024 + (counter % 512),
                payload: vec![0u8; 100],
                flags: HashMap::new(),
            };

            if packet_tx.send(test_packet).await.is_err() {
                break;
            }

            counter += 1;

            if counter > 1000 {
                break;        // Stop after sending test packets
            }
        }
    });

    // Start the analysis engine
    let engine_task = tokio::spawn(async move {
        if let Err(e) = engine.start().await {
            eprintln!("Analysis engine error: {}", e);
        }
    });

    // Wait for all tasks to complete
    tokio::select! {
        _ = engine_task => println!("Analysis engine stopped"),
        _ = alert_handler => println!("Alert handler stopped"),
        _ = packet_injector => println!("Packet injector stopped"),
    }

    println!("Network Analysis Engine shutdown complete");
    Ok(())
}
