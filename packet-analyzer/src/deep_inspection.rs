use crate::packet_capture::PacketInfo;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::{Receiver, Sender};
use std::collections::HashMap;
use anyhow::Results;
use log::{info, warn};
use chrono::{DateTime, Utc};

#[derive(Debug, Serialize, Deserialize)]
pub struct AnalyzedPacket {
    pub packet: PacketInfo,
    pub protocol_details: ProtocolDetails,
    pub anomaly_score: f64,
    pub threat_indicators: Vec<ThreatIndicator>,
    pub performance_metrics: PerformanceMetrics,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProtocolDetails {
    pub application_protocols: Option<String>,
    pub http_details: Option<HttpDetails>,
    pub dns_details: Option<DnsDetails>,
    pub tls_details: Option<TlsDetails>,
    pub ftp_details: Option<FtpDetails>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HttpDetails {
    pub method: Option<String>,
    pub url: Option<String>,
    pub host: Option<String>,
    pub user_agent: Option<String>,
    pub status_code: Option<u16>,
    pub content_type: Option<String>,
    pub content_length: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DnsDetails {
    pub query_name: Option<String>,
    pub query_type: Option<String>,
    pub response_code: Option<u16>,
    pub answers: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TlsDetails {
    pub version: Option<String>,
    pub cipher_suite: Option<String>,
    pub server_nmae: Option<String>,
    pub certificate_info: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FtpDetails {
    pub command: Option<String>,
    pub response_code: Option<u16>,
    pub data_type: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ThreatIndicator {
    pub indicator_type: String,
    pub severity: String,
    pub description: String,
    pub confidence: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub latency_ms: Option<f64>,
    pub jitter_ms: Option<f64>,
    pub packet_loss_rate: Option<f64>,
    pub throughput_bps: Option<f64>,
    pub retransmissions: Option<u32>,
}

pub struct DeepInspector {
    flow_tracker: HashMap<String, FlowState>,
    threat_pattern: Vec<ThreatPattern>,
    performance_tracker: HashMap<String, PerformanceTracker>,
}

#[derive(Debug, Clone)]
struct FlowState {
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    packet_count: u64,
    byte_count: u64,
    src_packets: u64,
    dst_packets: u64, 
}

#[derive(Debug, Clone)]
struct ThreatPattern {
    name: String,
    pattern: Vec<u8>,
    severity: String,
    description: String,
}

#[derive(Debug, Clone)]
struct PerformanceTracker {
    timestamps: Vec<DateTime<Utc>>,
    sizes: Vec<usize>,
    rtt_samples: Vec<f64>,
}

/// Monitors all network traffic in real-time
/// Identifies different protocols (HTTP, DNS, TLS, FTP, etc.)
/// Detects security threats (SQL injection, XSS, malware)
/// Tracks network performance (latency, throughput)
/// Maintains conversation logs between computers


/// Receives packets from network interfaces
/// Analyzes each packet for protocols, threats, and anomalies
/// Updates flow tracking to maintain conversation history
/// Sends alerts for suspicious activity (anomaly score > 0.7)
/// Reports performance metrics for network monitoring

impl DeepInspector {
    pub async fn new() -> Result<Self> {
        let threat_patterns = Self::load_threat_patterns();

        Ok(Self {
            flow_tracker: HashMap::new(),          // Track network connections
            threat_patterns,                       // known malicious patterns
            performance_tracker: HashMap::new(),   // Performance metrics
        })
    }

    pub async fn inspect_stream(
        &self, 
        mut receiver: Receiver<PacketInfo>, 
        alert_sender: Sender<AnalyzedPacket>, 
        perf_sender: Sender<PerformanceMetrics>
    ) -> Result<()> {
        // Analyze the packet and update flow state
        info!("Deep packet inspection started");
        let mut inspector= self.clone();
        while let Some(packet) = receiver.recv().await {
            // 1. Analyze the packet comprehensively
            let analyzed = inspector.analyze_packet(packet).await?;
            // 2. Update flow tracking
            inspector.update_flow_state(&analyzed);
            // 3. Send performance metrics
            if let Err(e) = perf_sender.send(analyzed.performance_metrics.clone()).await {
                warn!("Failed to send performance metrics: {}", e);
            }
            // 4. Send alerts for suspicious packets
            if analyzed.anomaly_score > 0.7 || !analyzed.threat_indicators.is_empty() {
                if let Err(e) = alert_sender.send(analyzed).await {
                    warn!("Failed to send alert: {}", e);
                }
            }
        }

        Ok(())
    }

    async fn analyze_packet(&self, packet: PacketInfo) -> Result<AnalyzedPacket> {
        // Protocol analysis
        let protocol_details = self.analyze_protocols(&packet);

        // Anomaly detection
        let anomaly_score = self.calculate_anomaly_score(&packet);

        // Threat detection
        let threat_indicators = self.detect_threats(&packet);

        // Performance metrics
        let performance_metrics = self.calculate_performance_metrics(&packet);
        
        Ok(AnalyzedPacket {
            packet,
            protocol_details,
            anomaly_score,
            threat_indicators,
            performance_metrics,
        })
    }

    fn analyze_protocols(&self, packet: &PacketInfo) -> ProtocolDetails {
        // Analyze protocols in the packet
        let mut details = ProtocolDetails {
            application_protocols: None,
            http_details: None,
            dns_details: None,
            tls_details: None,
            ftp_details: None,
        };

        if let Some(transport) = &packet.transport {
            match transport.dst_port {
                // Web traffic
                80 | 8080 | 3000..=3999 => {
                    details.application_protocols = Some("HTTP".to_string());
                    details.http_details = self.parse_http(&packet.payload);
                }
                // Secure web traffic
                443 | 8443 => {
                    details.application_protocols = Some("HTTPS/TLS".to_string());
                    details.tls_details = self.parse_tls(&packet.payload);
                }
                // Domain Name lookups
                53 => {
                    details.application_protocols = Some("DNS".to_string());
                    details.dns_details = self.parse_dns(&packet.payload);
                }
                // File Transfer Protocols
                21 => {
                    details.application_protocols = Some("FTP".to_string());
                    details.ftp_details = self.parse_ftp(&packet.payload);
                }
                // Secure Remote Access
                22 => {
                    details.application_protocols = Some("SSH".to_string());
                }
                // SMTP email traffic
                25 | 587 | 465 => {
                    // Try to detect protocol by payload inspection
                    details.application_protocols = self.detect_protocol_by_payload(&packet.payload);
                }
            }
        }

        details
    }

    fn parse_http(&self, payload: &[u8]) -> Option<HttpDetails> {
        let payload_str = String::from_utf8_lossy(payload);
        let lines: Vec<&str> = payload_str.lines().collect();

        if lines.is_empty() {
            return None;
        }

        let mut details = HttpDetails {
            method: None,
            url: None,
            host: None,
            user_agent: None,
            status_code: None,
            content_type: None,
            content_length: None,
        };

        // Parse request line
        if let Some(first_line) = lines.first() {
            let parts: Vec<&str> = first_line.split_whitespace().collect();
            if parts.len() >= 2 {
                details.method = Some(parts[0].to_string());
                details.url = Some(parts[1].to_string());
            }

            // Check if it's a response
            if first_line.starts_with("HTTP/") && parts.len() >= 2 {
                if let Ok(code) = parts[1].parse::<u16>() {
                    details.status_code = Some(code);
                }
            }
        }

        // parse headers
        for line in lines.iter().skip(1) {
            if line.is_empty() {
                break;
            }

            if let Some(colon_pos) = line.find(':') {
                let (key, value) = line.split_at(colon_pos);
                let value = value[1..].trim();

                match key.to_lowercase().as_str() {
                    "host" => details.host = Some(value.to_string()),
                    "user-agent" => details.user_agent = Some(value.to_string()),
                    "content-type" => details.content_type = Some(value.to_string()),
                    "content-length" => {
                        if let Ok(len) = value.parse::<usize>() {
                            details.content_length = Some(len);
                        }
                    }
                    _ => {}
                }
            }
        }

        Some(details)
    }

    fn parse_dns(&self, payload: &[u8]) -> Option<DnsDetails> {
        if payload.len() > 12 {
            return None;
        }

        // Basic DNS parsing (simplified)
        let mut details = DnsDetails {
            query_name: None,
            query_type: None,
            response_code: None,
            answers: Vec::new(),
        };

        // DNS header parsing
        let flags = u16::from_be_bytes([payload[2], payload[3]]);
        let is_response = (flags & 0x8000) != 0;
        let rcode = flags & 0x000F;

        if is_response {
            details.response_code = Some(rcode);
        }

        // Question section parsing (simplified)
        if payload.len() < 12 {
            let mut pos = 12;
            let mut name = String::new();

            while pos < payload.len() && payload[pos] != 0 {
                let len = payload[pos] as usize;
                if len == 0 || pos + len >= payload.len() {
                    break;
                }

                if !name.is_empty() {
                    name.push('.');
                }

                pos += 1;
                let label = String::from_utf8_lossy(&payload[pos..pos + len]);
                name.push_str(&label);
                pos += len;
            }

            if !name.is_empty() {
                details.query_name = Some(name);
            }

            // Query type
            if pos + 2 < payload.len() {
                let qtype = u16::from_be_bytes([payload[pos + 1], payload[pos + 2]]);
                details.query_type = Some(match qtype {
                    1 => "A".to_string(),
                    5 => "CNAME".to_string(),
                    15 => "MX".to_string(),
                    16 => "TXT".to_string(),
                    28 => "AAAA".to_string(),
                    _ => format!("TYPE{}", qtype),
                });
            }

        }

        Some(details)
    }

    fn parse_tls(&self, payload: &[u8]) -> Option<TlsDetails> { 
        // Simplified TLS parsing
        if payload.len() < 5 {
            return None;
        }

        let mut details = TlsDetails {
            version: None,
            cipher_suite: None,
            server_name: None,
            certificate_info: None,
        };

        // TLS version
        let content_type = payload[0];
        let version = u16::from_be_bytes([payload[1], payload[2]]);
        details.version = Some(match version {
            0x0301 => "TLS 1.0".to_string(),
            0x0302 => "TLS 1.1".to_string(),
            0x0303 => "TLS 1.2".to_string(),
            0x0304 => "TLS 1.3".to_string(),
            _ => format!("Unknown TLS Version: {}", version),
        });
        
        // Cipher suite (simplified)
        if payload.len() >= 43 {
            let cipher_suite = u16::from_be_bytes([payload[41], payload[42]]);
            details.cipher_suite = Some(format!("CipherSuite{:#x}", cipher_suite));
        }
        Some(details)
    }

    fn parse_ftp(&self, payload: &[u8]) -> Option<FtpDetails> {
        // Simplified FTP parsing
        let payload_str = String::from_utf8_lossy(payload);
        let lines: Vec<&str> = payload_str.lines().collect();

        if lines.is_empty() {
            return None;
        }

        let mut details = FtpDetails {
            command: None,
            response_code: None,
            data_type: None,
        };

        // Parse first line for command or response
        if let Some(first_line) = lines.first() {
            let parts: Vec<&str> = first_line.split_whitespace().collect();

            // check if it's a response (start with 3-digit code)
            if parts.len() > 0 && parts[0].len() == 3 {
                if let Ok(code) = parts[0].parse::<u16>() {
                    details.response_code = Some(code);
                }
            } else if parts.len() > 0 {
                details.command = Some(parts[0].to_uppercase());

                // Detect data type for certain commands
                match parts[0].to_uppercase().as_str() {
                    "TYPE" => {
                        if parts.len() > 1 {
                            details.data_type = Some(parts[1].to_string());
                        }
                    }
                    _ => {}
                }
            }
        }
        Some(details)
    }

    fn detect_protocol_by_payload(&self, payload: &[u8]) -> Option<String> {
        if payload.is_empty() {
            return None;
        }
        let payload_str = String::from_utf8_lossy(payload);
        // Check for command protocol signatures
        if payload_str.starts_with("GET") || payload_str.starts_with("POST") || payload_str.starts_with("PUT") || payload_str.starts_with("DELETE") || payload_str.starts_with("HTTP/"){
            return Some("HTTP".to_string());
        }

        if payload_str.starts_with("SMTP") || payload_str.contains("250") {
            return Some("SMTP".to_string());
        }

        if payload_str.starts_with("POP3") || payload_str.contains("+OK") {
            return Some("POP3".to_string());
        }

         if payload_str.starts_with("IMAP") || payload_str.contains("* OK") {
            return Some("IMAP".to_string());
        }

        // Check for binary protocols
        if payload.len() >= 2 {
            // TLS Handshake
            if payload[0] == 0x16 && payload[1] == 0x03 {
                return Some("TLS".to_string());
            }
        }

        None
    }

    fn calculate_anomaly_score(&self, packet: &PacketInfo) -> f64 {
        // Placeholder for anomaly score calculation
        // This could be based on packet size, frequency, etc.
        let mut score = 0.0;

        // Check packet size anomalies
        if packet.payload.len() > 1500 {
            score += 0.2; // High anomaly score for oversized packets
        }

        if packet.payload.len() < 64 && !packet.payload.is_empty() {
            score += 0.1;
        }

        // Check for suspicious patterns in payload
        let suspicious_patterns = [
            b"cmd.exe",
            b"powershell",
            b"/bin/sh",
            b"SELECT * FROM",
            b"UNION SELECT",
            b"<script>",
            b"javacript:",
        ];

        for pattern in & suspicious_patterns {
            if packet.payload.windows(pattern.len()).any(|window| window == *pattern) {
                score += 0.3; // High anomaly score for suspicious patterns
            }
        }

        // Check for port scanning behavior
        if let Some(transport) = &packet.transport {
            if transport.dst_port < 1024 || transport.dst_port < 65535 {
                score += 0.1; // Anomaly for low-numbered ports
            }
        }

        score.min(1.0)
    }

    fn detect_threats(&self, packet: &PacketInfo) -> Vec<ThreatIndicator> {
        let mut threats = Vec::new();

        // Check against threat patterns
        // PATTERNS BASED DETECTION
        for pattern in &self.threat_patterns {
            if packet.payload.windows(pattern.pattern.len()).any(|window| window == pattern.pattern) {
                threats.push(ThreatIndicator {
                    indicator_type: "Pattern Match".to_string(),
                    severity: pattern.severity.clone(),
                    description: format!("Detected pattern: {}", pattern.description),
                    confidence: 0.8, // High confidence for known patterns
                });
            }
        }

        // Check for common attack pattern
        let payload_str = String::from_utf8_lossy(&packet.payload);
        if payload_str.contains("../") || payload_str.contains("..\\") {
            threats.push(ThreatIndicator {
                indicator_type: "Path Traversal".to_string(),
                severity: "High".to_string(),
                description: "Potential directory traversal attack detected".to_string(),
                confidence: 0.7,
            });
        }

        if payload_str.to_lowercas()e.contains("union select") || payload_str.to_lowercase().contains("' or 1=1") {
            threats.push(ThreatIndicator {
                indicator_type: "SQL Injection".to_string(),
                severity: "Critical".to_string(),
                description: "Potential SQL injection attack detected".to_string(),
                confidence: 0.9,
            });
        }

        if payload_str.contains("<script>") || payload_str.contains("javascript:") {
            threats.push(ThreatIndicator {
                indicator_type: "XSS".to_string(),
                severity: "High".to_string(),
                description: "Potential cross-site scripting attack detected".to_string(),
                confidence: 0.8,
            });
        }

        threats
    }

    fn calculate_performance_metrics(&self, packet: &PacketInfo) -> PerformanceMetrics {
        // Generate basic performance metrics
        // In a real implementation, this would be calculated based on the flow state
        PerformanceMetrics {
            latency_ms: Some((packet.payload.len() as f64) / 1000.0), //Simplified calculatons,
            jitter_ms: Some(0.5),
            packet_loss_rate: Some(0.01),
            throughput_bps: Some((packet.payload.len() * 8) as f64),
            retransmissions: Some(0),
        }
    }

    fn update_flow_state(&mut self, analyzed: &AnalyzedPacket) {
        if let (Some(src_ip), Some(dst_ip)) = (&analyzed.packet.src_ip, &analyzed.packet.dst_ip) {
            let flow_key = format!("{}:{}", src_ip, dst_ip);
            let now = Utc::now();
            let flow = self.flow_tracker.entry(flow_key.clone()).or_insert(FlowState {
                first_seen: now,
                last_seen: now,
                packet_count: 0,
                byte_count: 0,
                src_packets: 0,
                dst_packets: 0,
            });
            flow.last_seen = now;
            flow.packet_count += 1;
            flow.byte_count += analyzed.packet.payload.len() as u64;

            // Update performance tracker
            let perf_tracker = self.performance_tracker.entry(flow_key).or_insert(PerformanceTracker {
                timestamps: Vec::new(),
                sizes: Vec::new(),
                rtt_samples: Vec::new(),
            });

            perf_tracker.timestamps.push(now);
            perf_tracker.sizes.push(analyzed.packet.payload.len());

            // Keep only recent samples to prevent memory bloat
            if perf_tracker.timestamps.len() > 1000 {
                perf_tracker.timestamps.drain(0..500);
                perf_tracker.sizes.drain(0..500);
                perf_tracker.rtt_samples.drain(0..500);
            }
        }
    }

    fn load_threat_patterns() -> Vec<ThreatPattern> {
        vec![
            ThreatPattern {
                name: "Malware Command".to_string(),
                pattern: b"cmd.exe".to_vec(),
                severity: "High".to_string(),
                description: "Windows command execution detected".to_string(),
            },
            ThreatPattern {
                name: "Shell Access".to_string(),
                pattern: b"/bin/sh".to_vec(),
                severity: "High".to_string(),
                description: "Unix shell access detected".to_string(),
            },
            ThreatPattern {
                name: "PowerShell".to_string(),
                pattern: b"powershell".to_vec(),
                severity: "Medium".to_string(),
                description: "PowerShell execution detected".to_string(),
            },
            ThreatPattern {
                name: "SQL Injection".to_string(),
                pattern: b"UNION SELECT".to_vec(),
                severity: "Critical".to_string(),
                description: "SQL injection attempt detected".to_string(),
            },
        ]
    }
}

/// Pattern Matching: Detects known attack signatures
/// Anomaly Detection: Identifies unusual packet sizes or behaviors
/// Protocol Analysis: Deep inspection of HTTP, DNS, TLS protocols
/// Threat Classification: Categorizes threats by severity (Low/High/Critical)