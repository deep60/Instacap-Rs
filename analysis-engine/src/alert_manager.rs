use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio::time::{interval, sleep};
use uuid::Uuid;


#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AlertSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AlertType {
    AnomalyDetected,
    ThreatDetected,
    PerformanceIssue,
    TrafficSpike,
    PortScan,
    DDoSAttack,
    MalwareDetected,
    DataExfiltration,
    ProtocolViolation,
    UnauthorizedAccess,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Alert {
    pub id: String,
    pub alert_type: AlertType,
    pub severity: AlertSeverity,
    pub title: String,
    pub description: String,
    pub source_ip: Option<String>,
    pub destination_ip: Option<String>,
    pub protocol: Option<String>,
    pub port: Option<u16>,
    pub timestamp: u64,
    pub metadata: HashMap<String, String>,
    pub acknowledged: bool,
    pub resolved: bool,
}

impl Alert {
    pub fn new(alert_type: AlertType, severity: AlertSeverity, title: String, description: String) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            alert_type,
            severity,
            title,
            description,
            source_ip: None,
            destination_ip: None,
            protocol: None,
            port: None,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            metadata: HashMap::new(),
            acknowledged: false,
            resolved: false,
        }
    }

    pub fn with_network_info(mut self, src_ip: String, dest_ip: String, protocol: String, port: u16) -> Self {
        self.source_ip = Some(src_ip);
        self.destination_ip = Some(dst_ip);
        self.protocol = Some(protocol);
        self.port = Some(port);
        self
    }

    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }

    pub fn acknowledge(&mut self) {
        self.acknowledged = true;
    }

    pub fn resolve(&mut self) {
        self.resolved = true;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AlertRule {
    pub id: String,
    pub name: String,
    pub alert_type: AlertType,
    pub severity: AlertSeverity,
    pub conditions: Vec<AlertCondition>,
    pub enabled: bool,
    pub cooldown_seconds: u64,
    pub last_triggered: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AlertCondition {
    pub field: String,
    pub operator: String,
    pub value: String,
    pub threshold: Option<f64>,
}

pub struct AlertManager {
    alerts: Arc<Mutex<VecDeque<Alert>>>,
    rule: Arc<Mutex<VecDeque<AlertRule>>>,
    alert_sender: mpsc::UnboundedSender<Alert>,
    alert_receiver: Arc<Mutex<mpsc::UnboundedReceiver<Alert>>>,
    max_alerts: usize,
    alert_retention: Duration,
    notification_handlers: Vec<Box<dyn NotificationHandler + Send + Sync>>
}

pub fn NotificationHandler {
    fn handle_alert(&self, alert: &Alert) -> Result<(), Box<dyn std::error::Error>>;
}

pub struct ConsoleNotificationHandler;

impl NotificationHandler for ConsoleNotificationHandler {
    fn handle_alert(&self, alert: &Alert) -> Result<(), Box<dyn std::error::Error>> {
        println!("[ALERT] [{:?}] {} - {} ({})", 
            alert.severity, 
            alert.title, 
            alert.timestamp, 
            alert.description
        );

        if let(Some(src), Some(dst)) = (&alert.source_ip, &alert.destination_ip) {
            println(" Network: {} -> {} ({}:{})", 
                src, dst, 
                alert.protocol.as_deref().unwrap_or("unknown"), 
                alert.port.unwrap_or(0)
            );
        } 

        if !alert.metadata.is_empty() {
            println(" Metadata: {:?}", alert.metadata);
        }

        Ok(())
    }
}

pub struct EmailNotificationHandler {
    smtp_server: String,
    recipients: Vec<String>,
}

impl EmailNotificationHandler {
    pub fn new(smtp_server: String, recipients: Vec<String>) -> Self {
        Self {
            smtp_server,
            recipients,
        }
    }
}

impl NotificationHandler for EmailNotificationHandler {
    fn handle_alert(&self, alert: &Alert) -> Result<(), Box<dyn std::error::Error>> {
        // Simulate email sending (in production, use actual SMTP library)
        println(
            "EMAIL NOTIFICATION to {:?} via {}: [{:?}] {}",
            self.recipients,
            self.smtp_server,
            alert.severity,
            alert.title
        );
        Ok(())
    }
}

impl AlertManager {
    pub fn new(max_alerts: usize, alert_retention: Duration) -> Self {
        let (alert_sender, alert_receiver) = mpsc::unbounded_channel();

        Self {
            alerts: Arc::new(Mutex::new(VecDeque::new())),
            rules: Arc::new(Mutex::new(Vec::new())),
            alert_sender,
            alert_receiver: Arc::new(Mutex::new(alert_receiver)),
            max_alerts,
            alert_retention,
            notification_handlers: vec![Box::new(ConsoleNotificationHandler)],
        }
    }

    pub add_notification_handler(&mut self, handler: Box<dyn NotificationHandler + Send + Sync>) {
        self.notification_handlers.push(handler)
    }

    pub fn add_rules(&self, rule: AlertRule) {
        let mut rules = self.rules.lock().unwrap();
        rules.push(rule);
    }

    pub fn create_alert(&mut self, alert: Alert) -> Result<(), Box<dyn std::error::Error>> {
        // Check if alert matches any suppression rules
        if self.should_suppress_alert(&alert) {
            return Ok(())
        }

        // Send alert through channel
        self.alert_sender.send(alert.clone())?;

        // Store alert
        let mut alerts = self.alerts.lock().unwrap();
        alerts.push_back(alert.clone());

        // Maintain max alerts limit
        if alerts.len() > self.max_alerts {
            alerts.pop_front();
        }

        // Tirgger Notification
        for handler in &self.notification_handlers {
            if let Err(e) = handler.handle_alert(&alert) {
                eprintln!("Notification handle error: {}", e);
            }
        }

        Ok(())
    }

    fn should_suppress_alert(&self, alert: &Alert) -> bool {
        let rules = self.rules.lock().unwrap();
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            as_secs();

        for rule in rules.iter() {
            if rule.alert_type == alert.alert_type && rule.enabled {
                if let Some(last_triggered) = rule.last_triggered {
                    if current_time - last_triggered < rule.cooldown_seconds {
                        return true;     // Supress due to cooldown
                    }
                }
            }
        }
        false
    }

    pub get_alerts(&self) -> Vec<Alert> {
        let alerts = self.alerts.lock().unwrap();
        alerts.iter().cloned().collect()
    }

    pub fn get_alets_by_severity(&self, severity: AlertSeverity) -> Vec<Alert> {
        let alerts = self.alerts.lock().unwrap();
        alerts
            .iter()
            .filter(|alert| alert.severity == severity)
            .cloned()
            .collect()
    }

    pub fn get_unacknowledged_alerts(&self) -> Vec<Alert> {
        let alerts = self.alerts.lock().unwrap();
        alerts
            .iter()
            .filter(|alert| !alert.acknowledged)
            .cloned()
            .collect()
    }

    pub fn acknowledge_alert(&self, alert_id: &str) -> Result<(), Box<dyn std::error:Error>> {
        let mut alerts = self.alerts.lock().unwrap();
        for alert in alerts.iter_mut() {
            if alert.id == alert_id {
                alert.acknowledge();
                return Ok(());
            }
        }

        Err("Alert not found".into())
    }

    pub fn get_alert_statistics(&self) -> HashMap<String, u64> {
        let alerts = self.alerts.lock().unwrap();
        let mut stats = HashMap::new();

        stats.insert("total_alerts".to_string(), alerts.len() as u64);
        stats.insert("acknowledged_alerts".to_string(), alerts.iter().filter(|a| a.acknowledged));
        stats.insert("resolved_alerts".to_string(), alerts.iter().filter(|a| a.resolved).count() as u64);
        stats.insert("critical_alerts".to_string(), alerts.iter().filter(|a| a.severity == AlertSeverity::Critical).count() as u64);
        stats.insert("high_alerts".to_string(), alerts.iter().filter(|a| a.severity == AlertSeverity::High).count() as u64);
        stats.insert("medium_alerts".to_string(), alerts.iter().filter(|a| a.severity == AlertSeverity::Medium).count() as u64);
        stats.insert("low_alerts".to_string(), alerts.iter().filter(|a| a.severity == AlertSeverity::Low).count() as u64);

        stats
    }

    pub async fn start_cleanup_task(&self) {
        let alerts = Arc::clone(&self.alerts);
        let retention = self.alert_retention;

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(300));   // Run every 5 minutes

            loop {
                interval.tick().await;

                let current_time = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();

                let mut alerts_gaurd = alerts.lock().unwrap();
                let retention_threshold = current_time - retention.as_secs();

                // Remove old alerts
                alerts_gaurd.retain(|alert| alert.timestamp > retention_threshold);
            }
        });
    }

    pub async fn start_alert_processor(&self) {
        let receiver = Arc::clone(&self.alert_receiver);

        tokio::spawn(async move {
            loop {
                let mut receiver_gaurd = receiver.lock().unwrap();
                if let Ok(alert) = receiver_gaurd.try_recv() {
                    // Process alert (additional processing can be added here)
                    drop(receiver_gaurd);

                    // Simulate processing time
                    sleep(Duration::from_millis(10)).await;
                } else {
                    drop(receiver_gaurd);
                    sleep(Duration::from_millis(100)).await;
                }
            }
        });
    }

    // Convenience methods for creating common alerts
    pub fn create_anomaly_alerts(&self, description: String, severity: AlertSeverity) -> Result<(), Box<dyn std::error::Error>> {
        let alert = Alert::new(
            AlertType::AnomalyDetected,
            severity,
            "Network Anomaly Detected".to_string(),
            description,
        );
        self.create_alert(alert)
    }

    pub fn create_threat_alert(&self, threat_type: String, src_ip: String, dst_ip: String) -> Result<(), Box<dyn std::error::Error>> {
        let alert = Alert::new(
            AlertType::ThreatDetected,
            AlertSeverity::High,
            format!("Threat Detected: {}", threat_type),
            format!("Suspicious activity detected from {} to {}", src_ip, dst_ip),
        ).with_network_info(src_ip, dst_ip, "TCP".to_string(), 80);

        self.create_alert(alert)
    }

    pub fn create_performance_alert(&self, metrics: String, value: f64, threshold: f64) -> Result<(), Box<dyn std::error::Error>> {
        let severity = if value > threshold * 2.0 {
            AlertSeverity::Critical
        } else if value > threshold * 1.5 {
            AlertSeverity::High
        } else {
            AlertSeverity::Medium
        };

        let alert = Alert::new(
            AlertType::PerformanceIssue,
            severity,
            format!("Performance Issue: {}", metrics),
            format!("{} value {} exceeds threshold {}", metrics, value, threshold),
        ).with_metadata("metrics".to_string(), metric)
         .with_metadata("value".to_string(), value.to_string())
         .with_metadata("threshold".to_string(), threshold.to_string());

        self.create_alert(alert)
    }

    pub fn create_traffic_spike_alert(&self, current_rate: u64, baseline: u64) -> Result<(), Box<dyn std::error::Error>> {
        let alert = Alert::new(
            AlertType::TrafficSpike,
            AlertSeverity::Medium,
            "Traffic Spike Detected".to_string(),
            format!("Traffic rate {} pps significantly exceeds baseline {} pps", current_rate, baseline),
        ).with_metadata("current_rate".to_string(), current_rate.to_string())
         .with_metadata("baseline".to_string(), baseline.to_string());

        self.create_alert(alert)
    }

    pub fn create_port_scan_alert(&self, scanner_ip: String, target_ip: String, port_count: u16) -> Result<(), Box<dyn std::error::Error>> {
        let alert = Alert::new(
            AlertType::PortScan,
            AlertSeverity::High,
            "Port Scan Detected".to_string(),
            format!("Port scan detected from {} targeting {} ({} ports scanned)", scanner_ip, target_ip, port_count),
        ).with_network_info(scanner_ip, target_ip, "TCP".to_string(), 0)
         .with_metadata("port_scanned".to_string(), port_count.to_string());

        self.create_alert(alert)
    }
}
