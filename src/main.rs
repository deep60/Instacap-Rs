use anyhow::{Context, Ok, Result};
use clap::Parser;
use log::{info, warn, error, debug};
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::thread;
use std::sync::mpsc::{self, Receiver, Sender};
use serde::{Deserialize, Serialize};
use pcap::{Capture, Device, Active};
use pnet::packet::{
    ethernet::{EtherTypes, EthernetPacket},
    ip::IpNextHeaderProtocols,
    ipv4::Ipv4Packet,
    ipv6::Ipv6packet,
    tcp::TcpPacket,
    udp::UdpPacket,
    icmp::IcmpPacket,
    Packet,
};

/// Commmand line arguments for Instaacap-Rs
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about, = None)]

struct Args {
    /// Interface to capture traffic from
    #[clap(short, long, default_value = "eth0")]
    interface: String,

    /// Kafka broker URL
    #[clap(short, long, default_value = "localhost:9092")]
    kafka_broker: String,
    
    /// Elasticsearch URL
    #[clap(short, long, default_value = "http://localhost:9200")]
    elasticsearch_url: String,
    
    /// Enable promiscuous mode
    #[clap(long)]
    promiscuous: bool,
    
    /// Packet capture timeout in milliseconds
    #[clap(long, default_value = "1000")]
    timeout: i32,
    
    /// Buffer size for packet capture
    #[clap(long, default_value = "65536")]
    buffer_size: i32,
    
    /// Enable verbose logging
    #[clap(short, long)]
    verbose: bool,
    
    /// Anomaly detection window size (seconds)
    #[clap(long, default_value = "60")]
    anomaly_window: u64,
    
    /// Traffic threshold for anomaly detection (packets/second)
    #[clap(long, default_value = "1000")]
    traffic_threshold: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PacketInfo {
    timestamp: u64,
    src_ip: String,
    dst_ip: String,
    src_port: u16,
    dst_port: u16,
    protocol: String,
    packet_size: usize,
    payload_size: usize,
    flags: Vec<String>,
    ttl: u8,
    identification: u16, 
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TrafficMetrics {
    timestamp: u64,
    total_packets: u64,
    total_bytes: u64,
    packets_per_second: f64,
    bytes_per_second: f64,
    protocol_distribution: HashMap<String, u64>,
    top_talkers: Vec<(String, u64)>,
    port_activity: HashMap<u16, u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AnomalyAlert {
    timestamp: u64,
    alert_type: String,
    severity: String,
    description: String,
    src_ip: Option<String>,
    dst_ip: Option<String>,
    additional_info: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ThreatIndicator {
    timestamp: u64,
    threat_type: String,
    severity: String,
    src_ip: String,
    dst_ip: String,
    src_port: u16,
    dst_port: u16,
    protocol: String,
    description: String,
    confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PerformanceMetrics {
    timestamp: u64,
    latency_ms: f64,
    jitter_ms: f64,
    packet_loss_percent: f64,
    throughput_mbps: f64,
    connection_count: u64,
    error_rate: f64,
}

struct NetworkAnalyzer {
    packet_buffer: Arc<Mutex<VecDeque<PacketInfo>>>,
    traffic_stats: Arc<Mutex<TrafficMetrics>>,
    anomaly_detector: Arc<Mutex<AnomalyDetector>>,
    threat_detector: Arc<Mutex<ThreatDetector>>,
    performance_monitor: Arc<Mutex<PerformanceMonitor>>,
    alert_sender: Sender<AnomalyAlert>,
    threat_sender: Sender<ThreatIndicator>,
    args: Args,
}

struct AnomalyDetector {
    window_size: Duration,
    traffic_threshold: u64,
    packet_history: VecDeque<(Instant, PacketInfo)>,
    baseline_stats: HashMap<String, f64>,
    suspicious_ips: HashMap<String, u64>,
    port_scan_tracker: HashMap<String, HashMap<u16, Instant>>,
}

struct ThreatDetector {
    malware_signatures: Vec<String>,
    suspicious_patterns: Vec<String>,
    blacklisted_ips: Vec<String>,
    ddos_threshold: u64,
    brute_force_threshold: u64,
    connection_tracker: HashMap<String, u64>,
}

struct PerformanceMonitor {
    latency_samples: VecDeque<f64>,
    throughput_samples: VecDeque<f64>,
    packet_loss_counter: u64,
    total_packets: u64,
    connection_states: HashMap<String, Instant>,
    error_count: u64,
}

impl NetworkAnalyzer {
    fn new(args: Args) -> Result<Self> {
        let (alert_sender, _alert_receiver) = mpsc::channel();
        let (threat_sender, _threat_receiver) = mpsc::channel();

        let analyzer = NetworkAnalyzer {
            packet_buffer: Arc::new(Mutex::new(VecDeque::new())),
            traffic_stats: Arc::new(Mutex::new(TrafficMetrics { 
                timestamp: (), 
                total_packets: (), 
                total_bytes: (), 
                packets_per_second: (), 
                bytes_per_second: (), 
                protocol_distribution: (), 
                top_talkers: (), 
                port_activity: () 
            })),
            anomaly_detector: Arc::new(Mutex::new(AnomalyDetector::new(
                Duration::from_secs(args.anomaly_window), 
                args.traffic_threshold,
            ))),
            threat_detector: Arc::new(Mutex::new(ThreatDetector::new())),
            performance_monitor: Arc::new(Mutex::new(PerformanceMonitor::new())),
            alert_sender,
            threat_sender,
            args,
        };
        Ok(analyzer)
    }

    fn start_capture(&self) -> Result<()> {
        info!("");

        // Find and open the network interface
        let device = Device::list()?.into_iter()
            .find(|d| d.name == self.args.interface)
            .context("Network interface not found")?;

        let mut cap = Capture::from_device(device)? 
            .promisc(self.args.promiscuous)
            .timeout(self.args.timeout)
            .buffer_size(self.args.buffer_size)
            .open()?;
    }
}

