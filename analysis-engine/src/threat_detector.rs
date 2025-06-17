use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatAlert {
    pub id: String,
    pub timestamp: u64,
    pub source_ip: IpAddr,
    pub destination_ip: Option<IpAddr>,
    pub threat_type: ThreatType,
    pub description: String,
    pub severity: Severity,
    pub port: Option<u16>,
    pub protocol: String,
    pub description: String,
    pub evidence: Vec<String>,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatType {
    PortScan,
    DDoSAttack,
    BruteForce,
    Malware,
    DataExfiltration,
    Intrusion,,
    SuspiciousActivity,
    C2Communication,,
    DNSTunneling,,
    ProtocolAnomaly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone)]
pub struct PacketInfo {
    pub timestamp: Instant,
    pub source_ip: IpAddr,
    pub destination_ip: IpAddr,
    pub protocol: String,
    pub destination_port: u16,
    pub payload_size: usize,
    pub flags: Vec<String>,
    pub payload_snippet: Vec<u8>,
}

#[derive(Debug)]
struct ConnectionTracker {
    connections: HashMap<String, ConnectionInfo>,
    port_scan_tracker: HashMap<IpAddr, PortScanInfo>,
    ddos_tracker: HashMap<IpAddr, DDoSInfo>,
    brute_force_tracker: HashMap<IpAddr, BruteForceInfo>,
}

#[derive(Debug)]
struct ConnectionInfo {
    first_seen: Instant,
    last_seen: Instant,
    packet_count: u32,
    byte_count: u64,
    flags_seen: HashSet<String>,
    is_suspicious: bool,
}

#[derive(Debug)]
struct PortScanInfo {
    ports_contacted: HashSet<u16>,
    first_contact: Instant,
    last_contact: Instant,
    scan_rate: f32,
}

#[derive(Debug)]
struct DDoSInfo {
    packet_timestamps: VecDeque<Instant>,
    target_ips: HashSet<IpAddr>,
    peak_rate: f32,
}

#[derive(Debug)]
struct BruteForceInfo {
    attempts: VecDeque<Instant>, // Map of username to attempt count
    failed_attempts: u32,
    target_service: String,
}

pub struct ThreatDetector {
    tracker: ConnectionTracker,
    known_malware_signatures: HashSet<Vec<u8>>,
    suspicious_domains: HashSet<String>,
    c2_indicators: HashSet<String>,
    alert_sender: mpsc::Sender<ThreatAlert>
    config: ThreatDetectorConfig,
}

#[derive(Debug, Clone)]
pub struct ThreatDetectorConfig {
    pub port_scan_threshold: usize,        // Number of unique ports before flagging
    pub port_scan_window: Duration,        // Time window for port scan detection
    pub ddos_packet_threshold: usize,      // Packets per second threshold
    pub ddos_window: Duration,             // Time window for DDoS detection
    pub brute_force_threshold: usize,      // Failed attempts threshold
    pub brute_force_window: Duration,      // Time window for brute force detection
    pub suspicious_payload_min_entropy: f32, // Minimum entropy for suspicious payloads
    pub large_transfer_threshold: u64,     // Bytes threshold for data exfiltration
    pub dns_query_rate_threshold: f32,     // DNS queries per second threshold
}

impl Default for ThreatDetectionConfig {
    fn default() -> Self {
        Self {
            port_scan_threshold: 20,
            port_scan_window: Duration::from_secs(60),
            ddos_packet_threshold: 1000,
            ddos_window: Duration::from_secs(10),
            brute_force_threshold: 10,
            brute_force_window: Duration::from_secs(60 * 5),
            suspicious_payload_min_entropy: 7.5,
            large_transfer_threshold: 100 * 1024 * 1024, // 100 MB
            dns_query_rate_threshold: 50.0, // 5 queries per second
        }
    }
}

impl ThreatDetector {
    pub fn new(alert_sender: mpsc::Sender<ThreatAlert>) -> Self {
        let mut known_malware_signatures = HashSet::new();

        // Add some common malware signatures (simplified examples)
        known_malware_signatures.insert(b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE".to_vec()); // MZ header for PE files
        known_malware_signatures.insert(b"\x4D\x5A\x90\x00".to_vec()); // EICAR test file signature

        let mut suspicious_domains = HashSet::new();
        suspicious_domains.insert("suspicious-domain.com".to_string());
        suspicious_domains.insert("malicious-c2.net".to_string());

        let mut c2_indicators = HashSet::new();
        c2_indicators.insert("beacon".to_string());
        c2_indicators.insert("heartbeat".to_string());
        c2_indicators.insert("checkin".to_string());

        Self {
            tracker: ConnectionTracker {
                connections: HashMap::new(),
                port_scan_tracker: HashMap::new(),
                ddos_tracker: HashMap::new(),
                brute_force_tracker: HashMap::new(),
            },
            known_malware_signatures,
            suspicious_domains,
            c2_indicators,
            alert_sender,
            config: ThreatDetectionConfig::default(),
        }
    }

    pub async fn analyze_packet(&mut self, packet: PacketInfo) -> Result<(), Box<dyn std::error::Error>> {
        // Update connection tracking
        self.update_connection_info(&packet);

        // Run various threat detection alogorithms
        self.detect_port_scan(&packet).await?;
        self.detect_ddos(&packet).await?;
        self.detect_brute_force(&packet).await?;
        self.detect_malware(&packet).await?;
        self.detect_data_exfiltration(&packet).await?;
        self.detect_c2_communication(&packet).await?;
        self.detect_dns_tunneling(&packet).await?;
        self.detect_protocol_anomalies(&packet).await?;

        // Cleanup old entries
        self.cleanup_old_entries();

        Ok(())
    }

    fn update_connection_info(&mut self, packet: &PacketInfo) {
        let connection_key = format!("{}:{}-{}:{}", packet.source_ip, packet.source_port, packet.destination_ip, packet.destination_port);

        let conn_info = self.tracker.connections.entry(connection_key)
            .or_insert_with(|| ConnectionInfo {
                first_seen: packet.timestamp,
                last_seen: packet.timestamp,
                packet_count: 0,
                byte_count: 0,
                flags_seen: HashSet::new(),
                is_suspicious: false,
            });

        conn_info.last_seen = packet.timestamp;
        conn_info.packet_count += 1;
        conn_info.byte_count += packet.payload_size as u64;

        for flag in &packet.flags {
            conn_info.flags_seen.insert(flag.clone());
        }
    }

    async fn detect_port_scan(&mut self, packet: &PacketInfo) -> Result<(), Box<dyn std::error::Error>> {
        let scan_info = self.tracker.port_scan_tracker.entry(packet.source_ip)
            .or_insert_with(|| PortScanInfo {
                ports_contacted: HashSet::new(),
                first_contact: packet.timestamp,
                last_contact: packet.timestamp,
                scan_rate: 0.0,
            });

        scan_info.ports_contacted.insert(packet.destination_port);
        scan_info.last_contact = packet.timestamp;

        let time_diff = scan_info.last_contact.duration_since(scan_info.first_contact);
        if time_diff <= self.config.port_scan_window {
            scan_info.scan_rate = scan_info.ports_contacted.len() as f32 / time_diff.as_secs_f32();
            
            if scan_info.ports_contacted.len() >= self.config.port_scan_threshold {
                let alert = ThreatAlert {
                    id: format!("port_scan_{}", self.generate_alert_id()),
                    timestamp: self.current_timestamp(),
                    threat_type: ThreatType::PortScan,
                    severity: if scan_info.ports_contracted.len() > 100 { Severity::High } else { Severity::Medium },
                    source_ip: packet.source_ip,
                    destination_ip: Some(packet.destination_ip),
                    port: None,
                    protocol: packet.protocol.clone(),
                    description: format!("Port scan detected: {} ports scanned in {:.2} seconds",
                        scan_info.ports_contacted.len(),
                        time_diff.as_secs_f32()),
                    evidence: vec![format!("Ports: {:?}", scan_info.ports_contacted.iter().take(10).collect::<Vec<_>>())],
                    confidence: 0.85,
                };
                self.alert_sender.send(alert).await?;
            }
        }

        Ok(())
    }

    async fn detect_ddos(&mut self, packet: &PacketInfo) -> Result<(), Box<dyn std::error::Error>> {
        let ddos_info = self.tracker.ddos_tracker.entry(packet.source_ip)
            .or_insert_with(|| DDoSInfo {
                packet_timestamps: VecDeque::new(),
                target_ips: HashSet::new(),
                peak_rate: 0.0,
        });

        ddos_info.packet_timestamps.push_back(packet.timestamp);
        ddos_info.target_ips.insert(packet.destination_ip);

        // Remove old timestamps otside the window
        let cutoff = packet.timestamp - self.config.ddos_window;
        while let Some(&timestamp) = ddos_info.packet_timestamps.front() {
            if front_time < cutoff {
                ddos_info.packet_timestamps.pop_front();
            } else {
                break;
            }
        }

        let current_rate = ddos_info.packet_timestamps.len() as f32 / self.config.ddos_window.as_secs_f32();
        ddos_info.peak_rate = ddos_info.peak_rate.max(current_rate);

        if ddos_info.packet_timestamps.len() >= self.config.ddos_packet_threshold {
            let severity = match current_rate {
                r if r > 10000.0 => Severity::Critical,
                r if r > 5000.0 => Severity::High,
                _ => Severity::Medium,
            };

            let alert = ThreatAlert {
                id: format!("ddos_{}", self.generate_alert_id()),
                timestamp: self.current_timestamp(),
                threat_type: ThreatType::DDoSAttack,
                severity,
                source_ip: packet.source_ip,
                destination_ip: Some(packet.destination_ip),
                port: Some(packet.destination_port),
                protocol: packet.protocol.clone(),
                description: format!("DDoS attack detected: {:.2} packets/sec, {} targets", current_rate, ddos_info.target_ips.len()),
                evidence: vec![
                    format!("Packet rate: {:2}/sec", current_rate),
                    format!("Target IPs: {}", ddos_info.target_ips.len()),],
                confidence: 0.90,
            };

            self.alert_sender.send(alert).await?;
        }

        Ok(())
    }

    async fn detect _malware(&mut self, packet: &PacketInfo) -> Result<(), Box<dyn std::error::Error>> {
        // Check for known malware signatures in payload
        for signature in &self.known_malware_signatures {
            if self.contains_signature(&packet.payload_snippet, signature) {
                let alert = ThreatAlert {
                    id: format!("malware_{}", self.generate_alert_id()),
                    timestamp: self.current_timestamp(),
                    threat_type: ThreatType::Malware,
                    severity: Severity::High,
                    source_ip: packet.source_ip,
                    destination_ip: Some(packet.destination_ip),
                    port: Some(packet.destination_port),
                    protocol: packet.protocol.clone(),
                    description: "Known Malware signature detected in network traffic".to_string(),
                    evidence: vec![format!("Signature match: {} bytes", signature.len())],
                    confidence: 0.95,
                };

                self.alert_sender.send(alert).await?;
                break;
            }
        } 

        // Check payload entropy for encrypted/packet malware
        let entropy = self.calculate_entropy(&packet.payload_snippet);
        if entropy < self.config.suspicious_payload_min_entropy && packet.payload_size > 1024 {
            let alert = ThreatAlert {
                id: format!("suspicious_payload_{}", self.generate_alert_id()),
                timestamp: self.current_timestamp(),
                threat_type: ThreatType::SuspiciousTraffic,
                severity: Severity::Medium,
                source_ip: packet.source_ip,
                destination_ip: Some(packet.destination_ip),
                port: Some(packet.destination_port),
                protocol: packet.protocol.clone(),
                description: format!("High entropy payload detected (entropy: {:.2})", entropy),
                evidence: vec![format!("Payload size: {} bytes", packet.payload_size)],
                confidence: 0.70,
            };

            self.alert_sender.send(alert).await?;
        }

        Ok(())
    }

    async fn detect_data_exfiltration(&mut self, packet: &PacketInfo) -> Result<(), Box<dyn std::error::Error>> {
        let connection_key = format!("{}:{}-{}:{}", packet.source_ip, packet.source_port, packet.destination_ip, packet.destination_port);

        if let Some(conn_info) = self.tracker.connections.get(&connection_key) {
            if conn_info.byte_count > self.config.large_transfer_threshold {
                let duration = conn_info.last_seen.duration_since(conn_info.first_seen);
                let transfer_rate = conn_info.byte_count as f32 / duration.as_secs_f32().max(1.0);

                let alert = ThreatAlert {
                    id: format!("data_exfil_{}", self.generate_alert_id()),
                    timestamp: self.current_timestamp(),
                    threat_type: ThreatType::DataExfiltration,
                    severity: if conn_info.byte_count > 1_000_000_000 { Severity::High } else { Severity::Medium },
                    source_ip: packet.source_ip,
                    destination_ip: Some(packet.destination_ip),
                    port: Some(packet.destination_port),
                    protocol: packet.protocol.clone(),
                    description: format!("Large data transfer detected: {:.2} MB", conn_info.byte_count as f32 / (1024 * 1024)),
                    evidence: vec![
                        format!("Transfer rate: {:.2} KB/s", transfer_rate / 1024.0),
                        format!("Duration: {:.2} seconds", duration.as_secs_f32()),
                        ],
                    confidence: 0.75,
                };
                self.alert_sender.send(alert).await?;
            }
        }
        Ok(())
    }

    async fn detect_brute_force(&mut self, packet: &PacketInfo) -> Result<(), Box<dyn std::error::Error>> {
        // Check for common brute force target ports
        let is_auth_service = matches!(packet.destination_port, 22 | 23 | 21 | 25 | 110 | 143 | 993 | 995 | 3389);

        if is_auth_service {
            let service_key = format!("{}:{}", packet.destination_ip, packet.destination_port);
            let brute_info = self.tracker.brute_force_tracker.entry(service_key.clone())
                .or_insert_with(|| BruteForceInfo {
                    attempts: VecDeque::new(),
                    failed_attempts: 0,
                    target_service: self.get_service_name(packet.destination_port),
                });

            brute_info.attempts.push_back(packet.timestamp);

            // Remove old attempts outside the window
            let cutoff = packet.timestamp - self.config.brute_force_window;
            while let Some(&front_time) = brute_info.attempts.front() {
                if front_time < cutoff {
                    brute_info.attempts.pop_front();
                } else {
                    break;       
                }
            }

            // Check for RST flags indicating failed authentication
            if packet.flags.contains(&"RST".to_string()) {
                brute_info.failed_attempts += 1;            
            }

            if brute_info.attempts.len() >= self.config.brute_force_threshold {
                let alert = ThreatAlert {
                    id: format!("brute_force_{}", self.generate_alert_id()),
                    timestamp: self.current_timestamp(),
                    threat_type: ThreatType::BruteForce,
                    severity: if brute_info.attempts.len() > 50 { Severity::High } else { Severity::Medium },
                    source_ip: packet.source_ip,
                    destination_ip: Some(packet.destination_ip),
                    port: Some(packet.destination_port),
                    protocol: packet.protocol.clone(),
                    description: format!("Brute force attack detected against {} service", brute_info.target_service),
                    evidence: vec![
                        format!("Attempts: {} in {:.2} seconds", brute_force.attempts.len(), self.config.brute_force_window.as_secs_f32())
                        format!("Failed attempts: {}", brute_info.failed_attempts),
                        ],
                    confidence: 0.85,
                };
                self.alert_sender.send(alert).await?;
            }
        }

        OK(())
    }

    async fn detect_c2_communication(&mut self, packet: &PacketInfo) -> Result<(), Box<dyn std::error::Error>> {
        // Convert payload to string for pattern matching
        let payload_str = String::from_utf8_lossy(&packet.payload_snippet);

        // Check for C2 indicators in payload
        for indicator in &self.c2_indicators {
            if payload_str.lowercase().contains(indicator) {
                let alert = ThreatAlert {
                    id: format!("c2_comm_{}", self.generate_alert_id()),
                    timestamp: self.current_timestamp(),
                    threat_type: ThreatType::C2Communication,
                    severity: Severity::High,
                    source_ip: packet.source_ip,
                    destination_ip: Some(packet.destination_ip),
                    port: Some(packet.destination_port),
                    protocol: packet.protocol.clone(),
                    description: format!("Potential C2 communication detected (indicator: {})", indicator),
                    evidence: vec![format!("Pattern found in {} protocol traffic", packet.protocol)],
                    confidence: 0.80,
                };
                self.alert_sender.send(alert).await?;
                break;
            }
        }

        // Check if suspicious domain communication
        if packet.protocol == "DNS" {
            let dns_query = String::from_utf8_lossy(&packet.payload_snippet);
            for domain in &self.suspicious_domains {
                if dns_query.contains(domain) {
                    let alert = ThreatAlert {
                        id: format!("c2_dns_{}", self.generate_alert_id()),
                        timestamp: self.current_timestamp(),
                        threat_type: ThreatType::C2Communication,
                        severity: Severity::High,
                        source_ip: packet.source_ip,
                        destination_ip: Some(packet.destination_ip),
                        port: Some(packet.destination_port),
                        protocol: packet.protocol.clone(),
                        description: format!("DNS query to known malicious domain: {}", domain),
                        evidence: vec![format!("DNS query contains: {}", domain)],
                        confidence: 0.90,
                    };
                    self.alert_sender.send(alert).await?;
                    break;
                }
            }
        }

        Ok(())
    }

    async fn detect_dns_tunneling(&mut self, packet: &PacketInfo) -> Result<(), Box<dyn, std::error::Error>> {
        if packet.protocol == "DNS" && packet.destination_port == 53{
            // Check for unusually large DNS queries or responses
            if packet.payload_size > 512 {
                let alert = ThreatAlert {
                    id: format!("dns_tunneling_{}", self.generate_alert_id()),
                    timestamp: self.current_timestamp(),
                    threat_type: ThreatType::DNSTunneling,
                    severity: Severity::Medium,
                    source_ip: packet.source_ip,
                    destination_ip: Some(packet.destination_ip),
                    port: Some(packet.destination_port),
                    protocol: packet.protocol.clone(),
                    description: format!("Potential suspicious DNS query size: {} bytes", packet.payload_size),
                    evidence: vec![format!("DNS packet size exceeds normal threshold")],
                    confidence: 0.65,
                };
                self.alert_sender.send(alert).await?;
            }
        }

        Ok(())
    }

    async fn detect_protocol_anomalies(&mut self, packet: &PacketInfo) -> Result<(), Box<dyn std::error::Error>> {
        // Check for protocol on unexpected ports
        let expected_protocol = self.get_expected_protocol(packet.destination_port);
        if expected_protocol != "Unknown" && expected_protocol != packet.protocol {
            let alert = ThreatAlert {
                id: format!("proto_anomaly_{}", self.generate_alert_id()),
                timestamp: self.current_timestamp(),
                threat_type: ThreatType::ProtocolAnomaly,
                severity: Severity::Low,
                source_ip: packet.source_ip,
                destination_ip: Some(packet.destination_ip),
                port: Some(packet.destination_port),
                protocol: packet.protocol.clone(),
                description: format!("Protocol anomaly: {} traffic on port {} (expected {})", packet.protocol, packet.destination_port, expected_protocol),
                evidence: vec![format!("Non-standard protocol usage detected")],
                confidence: 0.60,
            };
            self.alert_sender.send(alert).await?;
        }

        Ok(())
    }

    fn cleanup_old_entries(&mut self) {
        let now = Instant::now();
        let cleanup_threshold = Duration::from_secs(3600); // 1 hour

        // Cleanup old connections
        self.tracker.connections.retain(|_, conn| {
            now.duration_since(conn.last_seen) < cleanup_threshold
        });

        // Cleanup old port scan trackers
        self.tracker.port_scan_tracker.retain(|_, scan| {
            now.duration_since(scan.last_contact) < cleanup_threshold
        });

        // Cleanup old DDoS trackers
        self.tracker.ddos_tracker.retain(|_, ddos| {
            !ddos.packet_timestamps.is_empty() && now.duration_since(*ddos.packet_timestamps.back().unwrap()) < cleanup_threshold
        });

        // Cleanup old brute force trackers
        self.tracker.brute_force_tracker.retain(|_, brute| {
            !brute.attempts.is_empty() && now.duration_since(*brute.attempts.back().unwrap()) < cleanup_threshold
        });
    }

    // Helper functions
    fn contains_signature(&self, payload: &[u8], signature: &[u8]) -> bool {
        payload.windows(signature.len()).any(|window| window == signature)
    }

    fn calculate_entropy(&self, data: &[u8]) -> f32 {
        if data.is_empty() {
            return 0.0;
        }

        let mut counts = [0u32; 256];
        for &byte in data {
            counts[byte as usize] += 1;
        }

        let len = data.len() as f32;
        let mut entropy = 0.0;

        for &count in &counts {
            if count > 0 {
                let probability = count as f32 / len;
                entropy -= probability * probability.log2();
            }
        }
        entropy
    }

    fn get_service_name(&self, port: u16) -> String {
        match port {
            22 => "SSH".to_string(),
            23 => "Telnet".to_string(),
            21 => "FTP".to_string(),
            25 => "SMTP".to_string(),
            110 => "POP3".to_string(),
            143 => "IMAP".to_string(),
            993 => "IMAPS".to_string(),
            995 => "POP3S".to_string(),
            3389 => "RDP".to_string(),
            _ => format!("Port {}", port),
        }
    }

    fn get_expected_protocol(&self, port: u16) -> &str {
        match port {
            53 => "DNS",
            80 => "HTTP",
            443 => "HTTPS",
            22 => "SSH",
            23 => "Telnet",
            21 => "FTP",
            25 => "SMTP",
            110 => "POP3",
            143 => "IMAP",
            _ => "Unknown",
        }
    }

    fn generate_alert_id(&self) -> String {
        format!("{:x}", fastrand::u64(..))
    }

    fn current_timestamp(&self) -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_port_scan_detection() {
        let (tx, mut rx) = mpsc::channel(100);
        let mut detector = ThreatDetector::new(tx);

        let source_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let dest_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        // Simulate port scan
        for port in 1..=25 {
            let packet = PacketInfo {
                timestamp: Instant::now(),
                source_ip,
                destination_ip: dest_ip,
                source_port: 12345,
                destination_port: port,
                protocol: "TCP".to_string(),
                payload_size: 0,
                flags: vec!["SYN".to_string()],
                payload_snippet: vec![],
            };

            detector.analyze_packet(packet).await.unwrap();
        }

        // Should receive a port scan alert
        let alert = rx.try_recv().unwrap();
        assert!(matches!(alert.threat_type, ThreatType::PortScan));
        assert_eq!(alert.source_ip, source_ip);
    }

    #[test]
    fn test_entropy_calculation() {
        let detector = ThreatDetector::new(mpsc::channel(1).0);
        
        // Low entropy data (all zeros)
        let low_entropy_data = vec![0u8; 100];
        let entropy = detector.calculate_entropy(&low_entropy_data);
        assert!(entropy < 1.0);

        // High entropy data (random-like)
        let high_entropy_data: Vec<u8> = (0..=255).collect();
        let entropy = detector.calculate_entropy(&high_entropy_data);
        assert!(entropy > 7.0);
    }
}
