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

impl DeepInspector {
    pub async fn new() -> Result<Self> {
        let threat_patterns = Self::load_threat_patterns();

        Ok(Self {
            flow_tracker: HashMap::new(),
            threat_patterns,
            performance_tracker: HashMap::new(),
        })
    }

    pub async fn inspect_stream(
        &self, 
        mut receiver: Receiver<PacketInfo>, 
        alert_sender: Sender<AnalyzePacket>, 
        perf_sender: Sender<PerformanceMetrics>
    ) -> Results<()> {
        // Analyze the packet and update flow state
        info("Deep packet inspection started");
        let mut inspector= self.clone();
        while let Some(packet) = receiver.recv().await {
            let analyzed = inspector.analyze_packet(packet).await?;

            // Update flow tracking
            inspector.update_flow_state(&analyzed);

            // Send performance metrics
            if let Err(e) = perf_sender.send(analyzed.performance_metrics.clone()).await {
                warn!("Failed to send performance metrics: {}", e);
            }

            // Send alerts for high-risk packets
            if analyzed.anomaly_score > 0.7 || !analyze.threat_indicators.is_empty() {
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
                80 | 8080 | 3000..=3999 => {
                    details.application_protocols = Some("HTTP".to_string());
                    details.http_details = self.parse_http(&packet.payload);
                }

                443 | 8443 => {
                    details.application_protocols = Some("HTTPS/TLS".to_string());
                    details.tls_details = self.parse_tls(&packet.payload);
                }

                53 => {
                    details.application_protocols = Some("DNS".to_string());
                    details.dns_details = self.parse_dns(&packet.payload);
                }

                21 => {
                    details.application_protocols = Some("FTP".to_string());
                    details.ftp_details = self.parse_ftp(&packet.payload);
                }

                22 => {
                    details.application_protocols = Some("SSH".to_string());
                }

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
            retun None;
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
        if payload.len() < 12 {
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
            server_nmae: None,
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
        if payload.len() >= 5 {
            let cipher_suite = u16::from_be_bytes([payload[3], payload[4]]);
            details.cipher_suite = Some(format!("CipherSuite{}", cipher_suite));
        }

        // Server name indication (SNI) and certificate info would require more complex parsing
        // For now, we will leave them as None

        Some(details)
    }
}