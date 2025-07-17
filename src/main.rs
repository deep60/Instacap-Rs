use anyhow::{Result, Context};
use clap::Parser;
use log::{info, warn, error, debug};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::thread;
use std::sync::mpsc::{self, Sender};
use serde::{Deserialize, Serialize};
use pcap::{Capture, Device};
use pnet::packet::{
    ethernet::{EtherTypes, EthernetPacket},
    ip::IpNextHeaderProtocols,
    ipv4::Ipv4Packet,
    ipv6::Ipv6Packet,
    tcp::TcpPacket,
    udp::UdpPacket,
    icmp::IcmpPacket,
    Packet,
};

/// Command line arguments for Instacap-Rs
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
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
                timestamp: current_timestamp(),
                total_packets: 0,
                total_bytes: 0,
                packets_per_second: 0.0,
                bytes_per_second: 0.0,
                protocol_distribution: HashMap::new(),
                top_talkers: Vec::new(),
                port_activity: HashMap::new(),
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
        info!("Starting packet capture on interface: {}", self.args.interface);
        
        // Find and open the network interface
        let device = Device::list()?.into_iter()
            .find(|d| d.name == self.args.interface)
            .context("Network interface not found")?;
            
        let mut cap = Capture::from_device(device)?
            .promisc(self.args.promiscuous)
            .timeout(self.args.timeout)
            .buffer_size(self.args.buffer_size)
            .open()?;
        
        // Apply capture filter for common protocols
        cap.filter("ip or ip6", true)?;
        
        info!("Packet capture started successfully");
        
        // Start background threads
        self.start_analysis_threads()?;
        
        // Main packet capture loop
        loop {
            match cap.next_packet() {
                Ok(packet) => {
                    if let Some(packet_info) = self.parse_packet(&packet.data) {
                        self.process_packet(packet_info)?;
                    }
                }
                Err(pcap::Error::TimeoutExpired) => {
                    // Timeout is normal, continue
                    continue;
                }
                Err(e) => {
                    error!("Packet capture error: {}", e);
                    continue;
                }
            }
        }
    }
    
    fn parse_packet(&self, data: &[u8]) -> Option<PacketInfo> {
        if let Some(ethernet) = EthernetPacket::new(data) {
            match ethernet.get_ethertype() {
                EtherTypes::Ipv4 => {
                    if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
                        return self.parse_ipv4_packet(&ipv4);
                    }
                }
                EtherTypes::Ipv6 => {
                    if let Some(ipv6) = Ipv6Packet::new(ethernet.payload()) {
                        return self.parse_ipv6_packet(&ipv6);
                    }
                }
                _ => {}
            }
        }
        None
    }
    
    fn parse_ipv4_packet(&self, ipv4: &Ipv4Packet) -> Option<PacketInfo> {
        let mut packet_info = PacketInfo {
            timestamp: current_timestamp(),
            src_ip: ipv4.get_source().to_string(),
            dst_ip: ipv4.get_destination().to_string(),
            src_port: 0,
            dst_port: 0,
            protocol: "IPv4".to_string(),
            packet_size: ipv4.packet().len(),
            payload_size: ipv4.payload().len(),
            flags: Vec::new(),
            ttl: ipv4.get_ttl(),
            identification: ipv4.get_identification(),
        };
        
        match ipv4.get_next_level_protocol() {
            IpNextHeaderProtocols::Tcp => {
                if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                    packet_info.src_port = tcp.get_source();
                    packet_info.dst_port = tcp.get_destination();
                    packet_info.protocol = "TCP".to_string();
                    packet_info.flags = self.parse_tcp_flags(&tcp);
                }
            }
            IpNextHeaderProtocols::Udp => {
                if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                    packet_info.src_port = udp.get_source();
                    packet_info.dst_port = udp.get_destination();
                    packet_info.protocol = "UDP".to_string();
                }
            }
            IpNextHeaderProtocols::Icmp => {
                if let Some(_icmp) = IcmpPacket::new(ipv4.payload()) {
                    packet_info.protocol = "ICMP".to_string();
                }
            }
            _ => {}
        }
        
        Some(packet_info)
    }
    
    fn parse_ipv6_packet(&self, ipv6: &Ipv6Packet) -> Option<PacketInfo> {
        let mut packet_info = PacketInfo {
            timestamp: current_timestamp(),
            src_ip: ipv6.get_source().to_string(),
            dst_ip: ipv6.get_destination().to_string(),
            src_port: 0,
            dst_port: 0,
            protocol: "IPv6".to_string(),
            packet_size: ipv6.packet().len(),
            payload_size: ipv6.payload().len(),
            flags: Vec::new(),
            ttl: ipv6.get_hop_limit(),
            identification: 0, // IPv6 doesn't have identification field
        };
        
        match ipv6.get_next_header() {
            IpNextHeaderProtocols::Tcp => {
                if let Some(tcp) = TcpPacket::new(ipv6.payload()) {
                    packet_info.src_port = tcp.get_source();
                    packet_info.dst_port = tcp.get_destination();
                    packet_info.protocol = "TCP".to_string();
                    packet_info.flags = self.parse_tcp_flags(&tcp);
                }
            }
            IpNextHeaderProtocols::Udp => {
                if let Some(udp) = UdpPacket::new(ipv6.payload()) {
                    packet_info.src_port = udp.get_source();
                    packet_info.dst_port = udp.get_destination();
                    packet_info.protocol = "UDP".to_string();
                }
            }
            _ => {}
        }
        
        Some(packet_info)
    }
    
    fn parse_tcp_flags(&self, tcp: &TcpPacket) -> Vec<String> {
        let mut flags = Vec::new();
        let tcp_flags = tcp.get_flags();
        if tcp_flags & 0x01 != 0 { flags.push("FIN".to_string()); }
        if tcp_flags & 0x02 != 0 { flags.push("SYN".to_string()); }
        if tcp_flags & 0x04 != 0 { flags.push("RST".to_string()); }
        if tcp_flags & 0x08 != 0 { flags.push("PSH".to_string()); }
        if tcp_flags & 0x10 != 0 { flags.push("ACK".to_string()); }
        if tcp_flags & 0x20 != 0 { flags.push("URG".to_string()); }
        flags
    }
    
    fn process_packet(&self, packet_info: PacketInfo) -> Result<()> {
        // Add to packet buffer
        {
            let mut buffer = self.packet_buffer.lock().unwrap();
            buffer.push_back(packet_info.clone());
            if buffer.len() > 10000 { // Limit buffer size
                buffer.pop_front();
            }
        }
        
        // Enhanced packet processing
        self.deep_packet_inspection(&packet_info, &[])?; // In real implementation, pass actual payload
        self.analyze_geolocation(&packet_info)?;
        
        // Update traffic statistics
        self.update_traffic_stats(&packet_info)?;
        
        // Check for anomalies
        self.check_anomalies(&packet_info)?;
        
        // Check for threats
        self.check_threats(&packet_info)?;
        
        // Update performance metrics
        self.update_performance_metrics(&packet_info)?;
        
        // Send to external systems (Kafka/Elasticsearch)
        self.send_to_kafka(&packet_info)?;
        self.send_to_elasticsearch(&packet_info)?;
        
        if self.args.verbose {
            debug!("Processed packet: {} -> {} ({})", 
                   packet_info.src_ip, packet_info.dst_ip, packet_info.protocol);
        }
        
        Ok(())
    }
    
    // Kafka integration
    fn send_to_kafka(&self, packet_info: &PacketInfo) -> Result<()> {
        // In production, implement actual Kafka producer
        // For now, just log the data that would be sent
        if self.args.verbose {
            debug!("Would send to Kafka: {:?}", packet_info);
        }
        Ok(())
    }
    
    // Elasticsearch integration
    fn send_to_elasticsearch(&self, packet_info: &PacketInfo) -> Result<()> {
        // In production, implement actual Elasticsearch client
        // For now, just log the data that would be indexed
        if self.args.verbose {
            debug!("Would index to Elasticsearch: {:?}", packet_info);
        }
        Ok(())
    }
    
    // Enhanced statistics calculation
    fn calculate_advanced_stats(&self) -> Result<()> {
        let buffer = self.packet_buffer.lock().unwrap();
        let mut stats = self.traffic_stats.lock().unwrap();
        
        if buffer.len() < 10 {
            return Ok(());
        }
        
        // Calculate packets per second
        let time_window = 60; // seconds
        let current_time = current_timestamp();
        let recent_packets: Vec<_> = buffer.iter()
            .filter(|p| current_time - p.timestamp < time_window)
            .collect();
        
        stats.packets_per_second = recent_packets.len() as f64 / time_window as f64;
        
        // Calculate bytes per second
        let recent_bytes: usize = recent_packets.iter()
            .map(|p| p.packet_size)
            .sum();
        stats.bytes_per_second = recent_bytes as f64 / time_window as f64;
        
        // Update top talkers
        let mut talker_stats: HashMap<String, u64> = HashMap::new();
        for packet in recent_packets {
            *talker_stats.entry(packet.src_ip.clone()).or_insert(0) += 1;
        }
        
        let mut talkers: Vec<_> = talker_stats.into_iter().collect();
        talkers.sort_by(|a, b| b.1.cmp(&a.1));
        stats.top_talkers = talkers.into_iter().take(10).collect();
        
        Ok(())
    }
    
    fn update_traffic_stats(&self, packet_info: &PacketInfo) -> Result<()> {
        let mut stats = self.traffic_stats.lock().unwrap();
        stats.total_packets += 1;
        stats.total_bytes += packet_info.packet_size as u64;
        
        // Update protocol distribution
        *stats.protocol_distribution.entry(packet_info.protocol.clone()).or_insert(0) += 1;
        
        // Update port activity
        if packet_info.src_port > 0 {
            *stats.port_activity.entry(packet_info.src_port).or_insert(0) += 1;
        }
        if packet_info.dst_port > 0 {
            *stats.port_activity.entry(packet_info.dst_port).or_insert(0) += 1;
        }
        
        stats.timestamp = current_timestamp();
        Ok(())
    }
    
    fn check_anomalies(&self, packet_info: &PacketInfo) -> Result<()> {
        let mut detector = self.anomaly_detector.lock().unwrap();
        
        // Add packet to history
        detector.packet_history.push_back((Instant::now(), packet_info.clone()));
        
        // Remove old packets outside the window
        let cutoff = Instant::now() - detector.window_size;
        while let Some((timestamp, _)) = detector.packet_history.front() {
            if *timestamp < cutoff {
                detector.packet_history.pop_front();
            } else {
                break;
            }
        }
        
        // Check for traffic spikes
        let current_rate = detector.packet_history.len() as u64;
        if current_rate > detector.traffic_threshold {
            let alert = AnomalyAlert {
                timestamp: current_timestamp(),
                alert_type: "TRAFFIC_SPIKE".to_string(),
                severity: "HIGH".to_string(),
                description: format!("Traffic spike detected: {} packets/window", current_rate),
                src_ip: Some(packet_info.src_ip.clone()),
                dst_ip: Some(packet_info.dst_ip.clone()),
                additional_info: HashMap::new(),
            };
            
            warn!("Anomaly detected: {}", alert.description);
            // In a real implementation, send to Kafka/Elasticsearch
        }
        
        // Check for port scanning
        self.check_port_scanning(&mut detector, packet_info)?;
        
        Ok(())
    }
    
    fn check_port_scanning(&self, detector: &mut AnomalyDetector, packet_info: &PacketInfo) -> Result<()> {
        let src_ip = &packet_info.src_ip;
        let dst_port = packet_info.dst_port;
        
        if dst_port > 0 {
            let ports = detector.port_scan_tracker.entry(src_ip.clone()).or_insert_with(HashMap::new);
            ports.insert(dst_port, Instant::now());
            
            // Clean old entries
            let cutoff = Instant::now() - Duration::from_secs(60);
            ports.retain(|_, timestamp| *timestamp > cutoff);
            
            // Check if this looks like port scanning
            if ports.len() > 20 {
                let alert = AnomalyAlert {
                    timestamp: current_timestamp(),
                    alert_type: "PORT_SCAN".to_string(),
                    severity: "MEDIUM".to_string(),
                    description: format!("Possible port scan from {}: {} ports in 60s", src_ip, ports.len()),
                    src_ip: Some(src_ip.clone()),
                    dst_ip: Some(packet_info.dst_ip.clone()),
                    additional_info: HashMap::new(),
                };
                
                warn!("Port scan detected: {}", alert.description);
            }
        }
        
        Ok(())
    }
    
    fn check_threats(&self, packet_info: &PacketInfo) -> Result<()> {
        let mut detector = self.threat_detector.lock().unwrap();
        
        // Check for blacklisted IPs
        if detector.blacklisted_ips.contains(&packet_info.src_ip) {
            let _threat = ThreatIndicator {
                timestamp: current_timestamp(),
                threat_type: "BLACKLISTED_IP".to_string(),
                severity: "HIGH".to_string(),
                src_ip: packet_info.src_ip.clone(),
                dst_ip: packet_info.dst_ip.clone(),
                src_port: packet_info.src_port,
                dst_port: packet_info.dst_port,
                protocol: packet_info.protocol.clone(),
                description: format!("Traffic from blacklisted IP: {}", packet_info.src_ip),
                confidence: 0.95,
            };
            
            error!("Threat detected: {}", _threat.description);
        }
        
        // Check for DDoS patterns
        let connection_key = format!("{}:{}", packet_info.src_ip, packet_info.dst_ip);
        *detector.connection_tracker.entry(connection_key).or_insert(0) += 1;
        
        // Check for brute force attempts (multiple connections to same port)
        if packet_info.dst_port == 22 || packet_info.dst_port == 3389 || packet_info.dst_port == 21 {
            let brute_force_key = format!("{}:{}", packet_info.src_ip, packet_info.dst_port);
            *detector.connection_tracker.entry(brute_force_key.clone()).or_insert(0) += 1;
            
            if let Some(count) = detector.connection_tracker.get(&brute_force_key) {
                if *count > detector.brute_force_threshold {
                    let threat = ThreatIndicator {
                        timestamp: current_timestamp(),
                        threat_type: "BRUTE_FORCE".to_string(),
                        severity: "HIGH".to_string(),
                        src_ip: packet_info.src_ip.clone(),
                        dst_ip: packet_info.dst_ip.clone(),
                        src_port: packet_info.src_port,
                        dst_port: packet_info.dst_port,
                        protocol: packet_info.protocol.clone(),
                        description: format!("Brute force attack detected: {} attempts to port {}", count, packet_info.dst_port),
                        confidence: 0.85,
                    };
                    
                    error!("Brute force attack detected: {}", threat.description);
                }
            }
        }
        
        Ok(())
    }
    
    fn update_performance_metrics(&self, packet_info: &PacketInfo) -> Result<()> {
        let mut monitor = self.performance_monitor.lock().unwrap();
        
        monitor.total_packets += 1;
        
        // Calculate throughput
        let throughput = (packet_info.packet_size as f64 * 8.0) / 1_000_000.0; // Mbps
        monitor.throughput_samples.push_back(throughput);
        
        if monitor.throughput_samples.len() > 100 {
            monitor.throughput_samples.pop_front();
        }
        
        // Track connection states for latency estimation
        let connection_key = format!("{}:{}->{}:{}", 
                                   packet_info.src_ip, packet_info.src_port,
                                   packet_info.dst_ip, packet_info.dst_port);
        
        if packet_info.flags.contains(&"SYN".to_string()) && !packet_info.flags.contains(&"ACK".to_string()) {
            monitor.connection_states.insert(connection_key, Instant::now());
        } else if packet_info.flags.contains(&"SYN".to_string()) && packet_info.flags.contains(&"ACK".to_string()) {
            let reverse_key = format!("{}:{}->{}:{}", 
                                    packet_info.dst_ip, packet_info.dst_port,
                                    packet_info.src_ip, packet_info.src_port);
            
            if let Some(start_time) = monitor.connection_states.remove(&reverse_key) {
                let latency = start_time.elapsed().as_secs_f64() * 1000.0; // Convert to ms
                monitor.latency_samples.push_back(latency);
                
                if monitor.latency_samples.len() > 100 {
                    monitor.latency_samples.pop_front();
                }
            }
        }
        
        Ok(())
    }
    
    fn start_analysis_threads(&self) -> Result<()> {
        // Start statistics reporting thread
        let stats = Arc::clone(&self.traffic_stats);
        let anomaly_detector = Arc::clone(&self.anomaly_detector);
        let performance_monitor = Arc::clone(&self.performance_monitor);
        let packet_buffer = Arc::clone(&self.packet_buffer);
        
        thread::spawn(move || {
            let mut last_report = Instant::now();
            let mut last_flow_analysis = Instant::now();
            
            loop {
                thread::sleep(Duration::from_secs(10));
                
                // Regular statistics reporting
                if last_report.elapsed() >= Duration::from_secs(30) {
                    let stats_guard = stats.lock().unwrap();
                    let perf_guard = performance_monitor.lock().unwrap();
                    let anomaly_guard = anomaly_detector.lock().unwrap();
                    
                    info!("=== Traffic Statistics ===");
                    info!("Total packets: {}", stats_guard.total_packets);
                    info!("Total bytes: {}", stats_guard.total_bytes);
                    info!("Packets/sec: {:.2}", stats_guard.packets_per_second);
                    info!("Bytes/sec: {:.2}", stats_guard.bytes_per_second);
                    info!("Top protocols: {:?}", stats_guard.protocol_distribution);
                    
                    // Performance metrics
                    if !perf_guard.latency_samples.is_empty() {
                        let avg_latency: f64 = perf_guard.latency_samples.iter().sum::<f64>() / perf_guard.latency_samples.len() as f64;
                        let max_latency = perf_guard.latency_samples.iter().fold(0.0f64, |acc, &x| acc.max(x));
                        let min_latency = perf_guard.latency_samples.iter().fold(f64::MAX, |acc, &x| acc.min(x));
                        
                        info!("Latency - Avg: {:.2}ms, Min: {:.2}ms, Max: {:.2}ms", avg_latency, min_latency, max_latency);
                    }
                    
                    if !perf_guard.throughput_samples.is_empty() {
                        let avg_throughput: f64 = perf_guard.throughput_samples.iter().sum::<f64>() / perf_guard.throughput_samples.len() as f64;
                        info!("Average throughput: {:.2} Mbps", avg_throughput);
                    }
                    
                    // Security metrics
                    info!("Suspicious IPs tracked: {}", anomaly_guard.suspicious_ips.len());
                    info!("Port scan sources: {}", anomaly_guard.port_scan_tracker.len());
                    
                    // Packet loss rate
                    if perf_guard.total_packets > 0 {
                        let loss_rate = (perf_guard.packet_loss_counter as f64 / perf_guard.total_packets as f64) * 100.0;
                        info!("Packet loss rate: {:.2}%", loss_rate);
                    }
                    
                    last_report = Instant::now();
                }
                
                // Periodic flow analysis
                if last_flow_analysis.elapsed() >= Duration::from_secs(120) {
                    let buffer_guard = packet_buffer.lock().unwrap();
                    if !buffer_guard.is_empty() {
                        info!("Performing network flow analysis...");
                        // Flow analysis would go here
                        drop(buffer_guard);
                    }
                    last_flow_analysis = Instant::now();
                }
            }
        });
        
        // Start advanced statistics calculation thread
        let stats_clone = Arc::clone(&self.traffic_stats);
        let buffer_clone = Arc::clone(&self.packet_buffer);
        
        thread::spawn(move || {
            loop {
                thread::sleep(Duration::from_secs(15));
                
                // Calculate advanced statistics
                let buffer = buffer_clone.lock().unwrap();
                let mut stats = stats_clone.lock().unwrap();
                
                if buffer.len() < 10 {
                    continue;
                }
                
                // Calculate packets per second
                let time_window = 60; // seconds
                let current_time = current_timestamp();
                let recent_packets: Vec<_> = buffer.iter()
                    .filter(|p| current_time - p.timestamp < time_window)
                    .collect();
                
                stats.packets_per_second = recent_packets.len() as f64 / time_window as f64;
                
                // Calculate bytes per second
                let recent_bytes: usize = recent_packets.iter()
                    .map(|p| p.packet_size)
                    .sum();
                stats.bytes_per_second = recent_bytes as f64 / time_window as f64;
                
                // Update top talkers
                let mut talker_stats: HashMap<String, u64> = HashMap::new();
                for packet in recent_packets {
                    *talker_stats.entry(packet.src_ip.clone()).or_insert(0) += 1;
                }
                
                let mut talkers: Vec<_> = talker_stats.into_iter().collect();
                talkers.sort_by(|a, b| b.1.cmp(&a.1));
                stats.top_talkers = talkers.into_iter().take(10).collect();
                
                stats.timestamp = current_time;
            }
        });
        
        // Start cleanup thread for old data
        let anomaly_detector_clone = Arc::clone(&self.anomaly_detector);
        let threat_detector_clone = Arc::clone(&self.threat_detector);
        let performance_monitor_clone = Arc::clone(&self.performance_monitor);
        
        thread::spawn(move || {
            loop {
                thread::sleep(Duration::from_secs(300)); // Run every 5 minutes
                
                // Clean up old data
                let mut anomaly_guard = anomaly_detector_clone.lock().unwrap();
                let mut threat_guard = threat_detector_clone.lock().unwrap();
                let mut perf_guard = performance_monitor_clone.lock().unwrap();
                
                // Clean old connection states
                let cutoff = Instant::now() - Duration::from_secs(3600); // 1 hour
                perf_guard.connection_states.retain(|_, timestamp| *timestamp > cutoff);
                
                // Clean old port scan tracking
                let scan_cutoff = Instant::now() - Duration::from_secs(300); // 5 minutes
                for (_, ports) in anomaly_guard.port_scan_tracker.iter_mut() {
                    ports.retain(|_, timestamp| *timestamp > scan_cutoff);
                }
                anomaly_guard.port_scan_tracker.retain(|_, ports| !ports.is_empty());
                
                // Reset connection tracker periodically
                if threat_guard.connection_tracker.len() > 10000 {
                    threat_guard.connection_tracker.clear();
                    info!("Cleared connection tracker to prevent memory overflow");
                }
                
                info!("Performed periodic cleanup of tracking data");
            }
        });
        
        Ok(())
    }
}

impl AnomalyDetector {
    fn new(window_size: Duration, traffic_threshold: u64) -> Self {
        AnomalyDetector {
            window_size,
            traffic_threshold,
            packet_history: VecDeque::new(),
            baseline_stats: HashMap::new(),
            suspicious_ips: HashMap::new(),
            port_scan_tracker: HashMap::new(),
        }
    }
}

impl ThreatDetector {
    fn new() -> Self {
        ThreatDetector {
            malware_signatures: vec![
                "malware.exe".to_string(),
                "trojan.bin".to_string(),
            ],
            suspicious_patterns: vec![
                "/etc/passwd".to_string(),
                "SELECT * FROM".to_string(),
            ],
            blacklisted_ips: vec![
                "192.168.1.100".to_string(), // Example blacklisted IP
            ],
            ddos_threshold: 1000,
            brute_force_threshold: 50,
            connection_tracker: HashMap::new(),
        }
    }
}

impl PerformanceMonitor {
    fn new() -> Self {
        PerformanceMonitor {
            latency_samples: VecDeque::new(),
            throughput_samples: VecDeque::new(),
            packet_loss_counter: 0,
            total_packets: 0,
            connection_states: HashMap::new(),
            error_count: 0,
        }
    }
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// Additional protocol analyzers
struct ProtocolAnalyzer {
    http_analyzer: HttpAnalyzer,
    dns_analyzer: DnsAnalyzer,
    ftp_analyzer: FtpAnalyzer,
    smtp_analyzer: SmtpAnalyzer,
}

struct HttpAnalyzer {
    request_tracker: HashMap<String, Vec<HttpRequest>>,
    response_codes: HashMap<u16, u64>,
    suspicious_user_agents: Vec<String>,
}

struct HttpRequest {
    timestamp: u64,
    method: String,
    url: String,
    user_agent: String,
    src_ip: String,
}

struct DnsAnalyzer {
    query_tracker: HashMap<String, u64>,
    suspicious_domains: Vec<String>,
    dns_tunneling_detector: HashMap<String, u64>,
}

struct FtpAnalyzer {
    login_attempts: HashMap<String, u64>,
    file_transfers: Vec<FileTransfer>,
}

struct FileTransfer {
    timestamp: u64,
    src_ip: String,
    filename: String,
    size: u64,
    direction: String,
}

struct SmtpAnalyzer {
    email_volume: HashMap<String, u64>,
    spam_indicators: Vec<String>,
}

impl NetworkAnalyzer {
    // Enhanced deep packet inspection
    fn deep_packet_inspection(&self, packet_info: &PacketInfo, payload: &[u8]) -> Result<()> {
        match packet_info.protocol.as_str() {
            "TCP" => {
                match packet_info.dst_port {
                    80 | 8080 | 443 => self.analyze_http_traffic(packet_info, payload)?,
                    21 => self.analyze_ftp_traffic(packet_info, payload)?,
                    25 | 587 => self.analyze_smtp_traffic(packet_info, payload)?,
                    _ => {}
                }
            }
            "UDP" => {
                match packet_info.dst_port {
                    53 => self.analyze_dns_traffic(packet_info, payload)?,
                    _ => {}
                }
            }
            _ => {}
        }
        Ok(())
    }
    
    fn analyze_http_traffic(&self, packet_info: &PacketInfo, payload: &[u8]) -> Result<()> {
        if let Ok(http_data) = std::str::from_utf8(payload) {
            // Check for HTTP methods
            if http_data.starts_with("GET ") || http_data.starts_with("POST ") || 
               http_data.starts_with("PUT ") || http_data.starts_with("DELETE ") {
                
                let lines: Vec<&str> = http_data.split('\n').collect();
                if let Some(request_line) = lines.first() {
                    let parts: Vec<&str> = request_line.split(' ').collect();
                    if parts.len() >= 3 {
                        let method = parts[0];
                        let url = parts[1];
                        
                        // Check for suspicious patterns
                        if self.is_suspicious_http_request(method, url) {
                            let _threat = ThreatIndicator {
                                timestamp: current_timestamp(),
                                threat_type: "SUSPICIOUS_HTTP".to_string(),
                                severity: "MEDIUM".to_string(),
                                src_ip: packet_info.src_ip.clone(),
                                dst_ip: packet_info.dst_ip.clone(),
                                src_port: packet_info.src_port,
                                dst_port: packet_info.dst_port,
                                protocol: "HTTP".to_string(),
                                description: format!("Suspicious HTTP request: {} {}", method, url),
                                confidence: 0.7,
                            };
                            
                            warn!("Suspicious HTTP request detected: {} {}", method, url);
                        }
                    }
                }
            }
        }
        Ok(())
    }
    
    fn analyze_dns_traffic(&self, packet_info: &PacketInfo, payload: &[u8]) -> Result<()> {
        // Simple DNS analysis - in production, use a proper DNS parser
        if payload.len() > 12 { // Minimum DNS header size
            // Check for DNS tunneling (unusually large DNS queries)
            if payload.len() > 512 {
                let _alert = AnomalyAlert {
                    timestamp: current_timestamp(),
                    alert_type: "DNS_TUNNELING".to_string(),
                    severity: "HIGH".to_string(),
                    description: format!("Suspicious large DNS query: {} bytes", payload.len()),
                    src_ip: Some(packet_info.src_ip.clone()),
                    dst_ip: Some(packet_info.dst_ip.clone()),
                    additional_info: HashMap::new(),
                };
                
                warn!("Possible DNS tunneling detected: {} bytes", payload.len());
            }
        }
        Ok(())
    }
    
    fn analyze_ftp_traffic(&self, packet_info: &PacketInfo, payload: &[u8]) -> Result<()> {
        if let Ok(ftp_data) = std::str::from_utf8(payload) {
            // Check for FTP commands
            if ftp_data.starts_with("USER ") || ftp_data.starts_with("PASS ") {
                // Track login attempts
                warn!("FTP login attempt from {}: {}", packet_info.src_ip, ftp_data.trim());
            } else if ftp_data.starts_with("RETR ") || ftp_data.starts_with("STOR ") {
                // Track file transfers
                info!("FTP file transfer: {}", ftp_data.trim());
            }
        }
        Ok(())
    }
    
    fn analyze_smtp_traffic(&self, packet_info: &PacketInfo, payload: &[u8]) -> Result<()> {
        if let Ok(smtp_data) = std::str::from_utf8(payload) {
            // Check for SMTP commands and responses
            if smtp_data.contains("MAIL FROM:") || smtp_data.contains("RCPT TO:") {
                // Track email volume
                info!("SMTP activity from {}: {}", packet_info.src_ip, smtp_data.trim());
            }
        }
        Ok(())
    }
    
    fn is_suspicious_http_request(&self, _method: &str, url: &str) -> bool {
        // Check for common attack patterns
        let suspicious_patterns = [
            "sql", "union", "select", "drop", "insert", "update", "delete",
            "script", "alert", "onerror", "onload", "javascript:",
            "../", "..\\", "/etc/passwd", "/proc/", "cmd.exe",
            "powershell", "whoami", "netstat", "ipconfig",
        ];
        
        let lower_url = url.to_lowercase();
        suspicious_patterns.iter().any(|pattern| lower_url.contains(pattern))
    }
    
    // Enhanced GeoIP analysis
    fn analyze_geolocation(&self, packet_info: &PacketInfo) -> Result<()> {
        // Simple geolocation analysis - in production, use a proper GeoIP database
        if self.is_suspicious_geolocation(&packet_info.src_ip) {
            let _alert = AnomalyAlert {
                timestamp: current_timestamp(),
                alert_type: "SUSPICIOUS_GEOLOCATION".to_string(),
                severity: "MEDIUM".to_string(),
                description: format!("Traffic from suspicious geolocation: {}", packet_info.src_ip),
                src_ip: Some(packet_info.src_ip.clone()),
                dst_ip: Some(packet_info.dst_ip.clone()),
                additional_info: HashMap::new(),
            };
            
            warn!("Suspicious geolocation detected: {}", packet_info.src_ip);
        }
        Ok(())
    }
    
    fn is_suspicious_geolocation(&self, ip: &str) -> bool {
        // Check for private/local IPs first
        if ip.starts_with("192.168.") || ip.starts_with("10.") || 
           ip.starts_with("172.") || ip == "127.0.0.1" {
            return false;
        }
        
        // In production, check against GeoIP database for high-risk countries
        // This is a simplified example
        false
    }
    
    // Network flow analysis
    fn analyze_network_flows(&self) -> Result<()> {
        let buffer = self.packet_buffer.lock().unwrap();
        let mut flows: HashMap<String, Vec<&PacketInfo>> = HashMap::new();
        
        // Group packets by flow (src_ip:src_port -> dst_ip:dst_port)
        for packet in buffer.iter() {
            let flow_key = format!("{}:{}->{}:{}", 
                                 packet.src_ip, packet.src_port,
                                 packet.dst_ip, packet.dst_port);
            flows.entry(flow_key).or_insert_with(Vec::new).push(packet);
        }
        
        // Analyze each flow
        for (flow_id, packets) in flows {
            if packets.len() > 1000 {
                warn!("High-volume flow detected: {} ({} packets)", flow_id, packets.len());
            }
            
            // Check for beaconing behavior
            if self.is_beaconing_behavior(&packets) {
                warn!("Possible beaconing detected in flow: {}", flow_id);
            }
        }
        
        Ok(())
    }
    
    fn is_beaconing_behavior(&self, packets: &[&PacketInfo]) -> bool {
        if packets.len() < 10 {
            return false;
        }
        
        // Check for regular intervals between packets
        let mut intervals = Vec::new();
        for i in 1..packets.len() {
            let interval = packets[i].timestamp - packets[i-1].timestamp;
            intervals.push(interval);
        }
        
        // Simple check for consistent intervals (beaconing pattern)
        if intervals.len() > 5 {
            let avg_interval = intervals.iter().sum::<u64>() / intervals.len() as u64;
            let variance = intervals.iter()
                .map(|&x| (x as i64 - avg_interval as i64).pow(2))
                .sum::<i64>() / intervals.len() as i64;
            
            // Low variance indicates regular beaconing
            variance < 100
        } else {
            false
        }
    }
    
    // Enhanced statistics and reporting
    fn generate_security_report(&self) -> Result<String> {
        let stats = self.traffic_stats.lock().unwrap();
        let detector = self.anomaly_detector.lock().unwrap();
        let threat_detector = self.threat_detector.lock().unwrap();
        let perf_monitor = self.performance_monitor.lock().unwrap();
        
        let mut report = String::new();
        report.push_str("=== NETWORK SECURITY REPORT ===\n\n");
        
        // Traffic overview
        report.push_str(&format!("Traffic Overview:\n"));
        report.push_str(&format!("- Total packets: {}\n", stats.total_packets));
        report.push_str(&format!("- Total bytes: {}\n", stats.total_bytes));
        report.push_str(&format!("- Protocols: {:?}\n", stats.protocol_distribution));
        report.push_str(&format!("- Top ports: {:?}\n", stats.port_activity));
        
        // Performance metrics
        if !perf_monitor.latency_samples.is_empty() {
            let avg_latency = perf_monitor.latency_samples.iter().sum::<f64>() / perf_monitor.latency_samples.len() as f64;
            report.push_str(&format!("- Average latency: {:.2} ms\n", avg_latency));
        }
        
        if !perf_monitor.throughput_samples.is_empty() {
            let avg_throughput = perf_monitor.throughput_samples.iter().sum::<f64>() / perf_monitor.throughput_samples.len() as f64;
            report.push_str(&format!("- Average throughput: {:.2} Mbps\n", avg_throughput));
        }
        
        // Security events
        report.push_str(&format!("\nSecurity Events:\n"));
        report.push_str(&format!("- Suspicious IPs: {}\n", detector.suspicious_ips.len()));
        report.push_str(&format!("- Port scan attempts: {}\n", detector.port_scan_tracker.len()));
        report.push_str(&format!("- Connection attempts: {}\n", threat_detector.connection_tracker.len()));
        
        // Recommendations
        report.push_str(&format!("\nRecommendations:\n"));
        if detector.suspicious_ips.len() > 10 {
            report.push_str("- Consider implementing IP-based filtering\n");
        }
        if detector.port_scan_tracker.len() > 5 {
            report.push_str("- Review firewall rules for port scanning protection\n");
        }
        
        Ok(report)
    }
}

fn main() -> Result<()> {
    // Initialize logger
    env_logger::init();
    
    // Parse command line arguments
    let args = Args::parse();
    
    info!("Starting Instacap-Rs Network Packet Analyzer");
    info!("Interface: {}", args.interface);
    info!("Kafka broker: {}", args.kafka_broker);
    info!("Elasticsearch: {}", args.elasticsearch_url);
    info!("Promiscuous mode: {}", args.promiscuous);
    info!("Anomaly window: {}s", args.anomaly_window);
    info!("Traffic threshold: {} packets/s", args.traffic_threshold);
    
    // Display available network interfaces
    info!("Available network interfaces:");
    for device in Device::list()? {
        info!("  - {} ({})", device.name, device.desc.unwrap_or("No description".to_string()));
    }
    
    // Create network analyzer
    let analyzer = NetworkAnalyzer::new(args)?;
    
    // Handle Ctrl+C gracefully
    let analyzer_clone = Arc::new(analyzer);
    let analyzer_signal = Arc::clone(&analyzer_clone);
    
    ctrlc::set_handler(move || {
        info!("Received Ctrl+C, generating final report...");
        
        // Generate and display final security report
        if let Ok(report) = analyzer_signal.generate_security_report() {
            println!("\n{}", report);
        }
        
        info!("Shutting down gracefully...");
        std::process::exit(0);
    })?;
    
    // Start packet capture and analysis
    analyzer_clone.start_capture()?;
    
    Ok(())
}