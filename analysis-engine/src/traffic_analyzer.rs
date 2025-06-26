use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketInfo {
    pub timestamp: u64, // Unix timestamp in milliseconds
    pub packet_size: usize,    // Size of the packet in bytes
    pub payload_size: usize, // Protocol type (e.g., TCP, UDP)
    pub src_ip: IpAddr, // Source IP address
    pub dst_ip: IpAddr, // Destination IP address
    pub src_port: u16, // Source port
    pub dst_port: u16, // Destination port
    pub protocol: String, // Protocol type (e.g., TCP, UDP)
    pub flags: Vec<String>, // TCP flags (if applicable)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowStats {
    pub packet_count: u64,
    pub byte_count: u64,
    pub first_seen: u64, // Unix timestamp in milliseconds
    pub last_seen: u64,   // Unix timestamp in milliseconds
    pub avg_packet_size: f64,
    pub duration: u64,
    pub packets_per_second: f64,
    pub bytes_per_second: f64,
}   

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficMetrics {
    pub total_packets: u64,
    pub total_bytes: u64,
    pub packets_per_second: f64,
    pub bytes_per_second: f64,
    pub protocol_distribution: HashMap<String, u64>,
    pub top_talkers: Vec<(IpAddr, u64)>, // (IP address, total bytes)
    pub port_activity: HashMap<u16, u64>, // (port, total bytes)
    pub packet_size_distribution: HashMap<String, u64>, // (String count)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceStats {
    pub latency_ms: f64,
    pub throughput_mbps: f64,
    pub packet_loss_rate: f64,
    pub jitter_ms: f64,
    pub retransmission_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficAnalyzer {
    flows: HashMap<FlowKey, FlowStats>,
    packet_buffer: VecDeque<PacketInfo>,
    start_time: Instant,
    window_size: Duration,
    total_packets: u64,
    total_bytes: u64,
    protocol_stats: HashMap<String, u64>,
    ip_stats: HashMap<IpAddr, u64>,
    port_stats: HashMap<u16, u64>,
    performance_buffer: VecDeque<(u64, usize)>,     // (timestamp, size)
    rtt_samples: VecDeque<f64>, 
    lost_packets: u64,
}

impl TrafficAnalyzer {
    pub fn new(window_size_seconds: u64) -> Self {
        Self {
            flows: HashMap::new(),
            packet_buffer: VecDeque::new(),
            start_time: Instant::now(),
            window_size: Duration::from_secs(window_size_seconds),
            total_packets: 0,
            total_bytes: 0,
            protocol_stats: HashMap::new(),
            ip_stats: HashMap::new(),
            port_stats: HashMap::new(),
            performance_buffer: VecDeque::new(),
            rtt_samples: VecDeque::new(),
            lost_packets: 0,
        }
    }

    pub fn analyze_packet(&mut self, packet: PacketInfo) {
        self.update_flow_stats(&packet);
        self.update_global_stats(&packet);
        self.update_performance_metrics(&packet);

        // Add to sliding window buffer
        self.packet_buffer.push_back(packet);
        self.cleanup_old_data();
    }

    fn update_flow_stats(&mut self, packet: &PacketInfo) {
        let key = FlowKey {
            src_ip: packet.src_ip,
            dst_ip: packet.dst_ip,
            src_port: packet.src_port,
            dst_port: packet.dst_port,
            protocol: packet.protocol.clone(),
        };

        let flow_stats = self.flows.entry(key).or_insert(FlowStats {
            packet_count: 0,
            byte_count: 0,
            first_seen: packet.timestamp,
            last_seen: packet.timestamp,
            avg_packet_size: 0.0,
            duration: 0,
            packets_per_second: 0.0,
            bytes_per_second: 0.0,
        });

        flow_stats.packet_count += 1;
        flow_stats.byte_count += packet.packet_size as u64;
        flow_stats.last_seen = packet.timestamp;
        flow_stats.duration = flow_stats.last_seen - flow_stats.first_seen;
        flow_stats.avg_packet_size = flow_stats.byte_count as f64 / flow_stats.packet_count as f64;

        if flow_stats.duration > 0 {
            flow_stats.packets_per_second = flow_stats.packet_count as f64 / (flow_stats.duration as f64 / 1000.0);
            flow_stats.bytes_per_second = flow_stats.byte_count as f64 / (flow_stats.duration as f64 / 1000.0);
        }
    }

    fn update_global_stats(&mut self, packet: &PacketInfo) {
        self.total_packets += 1;
        self.total_bytes += packet.packet_size as u64;

        // Protocol statistics
        *self.protocol_stats.entry(packet.protocol.clone()).or_insert(0) += 1;

        // IP address statistics
        *self.ip_stats.entry(packet.src_ip).or_insert(0) += packet.packet_size as u64;
        *self.ip_stats.entry(packet.dst_ip).or_insert(0) += packet.packet_size as u64;

        // Port statistics
        *self.port_stats.entry(packet.src_port).or_insert(0) += 1;
        *self.port_stats.entry(packet.dst_port).or_insert(0) += 1;
    }

    fn update_performance_metrics(&mut self, packet: &PacketInfo) {
        self.performance_buffer.push_back((packet.timestamp, packet.packet_size));

        // Simulate RTT calculation (in real implementation, this would track actual RTTs)
        if packet.protocol == "TCP" && packet.flags.contains(&"SYN".to_string()) {
            // Mock RTT calculation
            let rtt = self.calculate_mock_rtt(&packet);
            self.rtt_samples.push_back(rtt);

            // Keep only recent samples
            while self.rtt_samples.len() > 1000 {
                self.rtt_samples.pop_front();
            }
        }

        // Detect packet loss (simplified)
        if packet.flags.contains(&"RST".to_string()) || packet.flags.contains(&"FIN".to_string()) {
            self.lost_packets += 1;
        }
    }

    fn calculate_mock_rtt(&self, _packet: &PacketInfo) -> f64 {
        // Mock RTT calculation - in real implementation, track SYN/ACK pairs
        use rand::Rng;
        let mut rng = rand::thread_rng();
        rng.gen_range(1.0..100.0) // 1-100ms mock RTT
    }

    fn cleanup_old_data(&mut self) {
        let cutoff_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64 - self.window_size.as_millis() as u64;

        // Remove old packets from the buffer
        while let Some(packet) = self.packet_buffer.front() {
            if packet.timestamp < cutoff_time {
                self.packet_buffer.pop_front();
            } else {
                break;
            }
        }

        // Remove old performance data
        while let Some((timestamp, _)) = self.performance_buffer.front() {
            if *timestamp < cutoff_time {
                self.performance_buffer.pop_front();
            } else {
                break;
            }
        }

        // Clean up stale flows
        self.flows.retain(|_, flow| flow.last_seen >= cutoff_time);
    }

    pub fn get_traffic_metrics(&self) -> TrafficMetrics {
        let duration = self.start_time.elapsed().as_secs_f64();
        let packets_per_second = if duration > 0.0 { self.total_packets as f64 / duration } else { 0.0 };
        let bytes_per_second = if duration > 0.0 { self.total_bytes as f64 / duration } else { 0.0 };

        // // Get top talkers(top 10 IPs by bytes)
        let mut top_talkers: Vec<(IpAddr, u64)> = self.ip_stats.iter()
            .map(|(ip, bytes)| (*ip, *bytes))
            .collect();
        top_talkers.sort_by(|a, b| b.1.cmp(&a.1));
        top_talkers.truncate(10);

        // Packet size distrubtion
        let mut packet_size_distribution = HashMap::new();
        for packet in &self.packet_buffer {
            let size_category = match packet.packet_size {
                0..=64 => "0-64",
                65..=128 => "65-128",
                129..=256 => "129-256",
                257..=512 => "257-512",
                513..=1024 => "513-1024",
                1025..=1518 => "1025-1518",
                _ => "1519+",
            };
            *packet_size_distribution.entry(size_category.to_string()).or_insert(0) += 1;
        }

        TrafficMetrics {
            total_packets: self.total_packets,
            total_bytes: self.total_bytes,
            packets_per_second,
            bytes_per_second,
            protocol_distribution: self.protocol_stats.clone(),
            packet_size_distribution
        }
    }

    pub fn get_performance_stats(&self) -> PerformanceStats {
        let latency_ms = if !self.rtt_samples.is_empty() {
            self.rtt_samples.iter().sum::<f64>() / self.rtt_samples.len() as f64
        } else {
            0.0
        };

        let jitter_ms = if send.rtt_samples.len() > 1 {
            let mean = lattency_ms;
            let variance: f64 = self.rtt_samples.iter()
                .map(|x| (x - mean).powi(2))
                .sum::<f64>() / (self.rtt_samples.len() -1) as f64;
            variance.sqrt()
        } else {
            0.0
        };

        let packet_loss_rate = if self.total_packets > 0 {
            self.lost_packets as f64 / self.total_packets as f64 * 100.0
        } else {
            0.0
        };

        let throughput_mbps = if !self.performance_buffer.is_empty() {
            let duration = self.start_time.elapsed().as_secs_f64();
            if duration > 0.0 {
                (self.total_bytes as f64 * 8.0) / (duration * 1_000_000.0)          // Convert to mbps
            } else {
                0.0
            }
        } else {
            0.0
        };

        // Mock retransmission rate calculation
        let retransmission_rate = packet_loss_rate * 0.1;          // Simplified estimation

        PerformanceStats {
            latency_ms,
            jitter_ms,
            packet_loss_rate,
            throughput_mbps,
            retransmission_rate,
        }
    }

    pub fn get_flow_stats(&self) -> &HashMap<FlowKey, FlowStats> {
        &self.flows
    }

    pub fn detect_traffic_anomalies(&self) -> Vec<String> {
        let mut anomalies = Vec::new();
        let metrics = self.get_traffic_metrics();

        // High traffic rate anomaly
        if metrics.packets_per_second > 10000.0 {
            anomalies.push(format!("High packet rate detected: {:.2} pps", metrics.packets_per_second));
        }

        // Unusual protocol distribution
        for (protocol, count) in (&metrics.protocol_distribution) {
            let percentage = (*count as f64 / metrics.total_packets as f64) * 100.0;
            if protocol == "ICMP" && percentage > 20.0 {
                anomalies.push(format!("High ICMP traffic: {:.2}%", percentage));
            }
        }

        // Port scanning detection (many unique destination ports from same source)
        let mut port_scan_candidates: HashMap<IpAddr, Vec<u16>> = HashMap::new();
        for packet in &self.packet_buffer {
            port_scan_candidates.entry(packet.src_ip)
                .or_insert_with(Vec::new)
                .push(packet.dst_port);
        }

        for (ip, ports) in port_scan_candidates {
            let mut unique_ports: Vec<u16> = ports;
            unique_ports.sort_unstable();
            unique_ports.dedup();

            if unique_ports.len() > 50 {
                anomalies.push(format!("Potential port scan from {}: {} unique ports", ip, unique_ports.len()));
            }
        }

        // Large packet size anomaly
        let avg_packet_size = if metrics.total_packets > 0 {
            metrics.total_bytes as f64 / metrics.total_packets as f64
        } else {
            0.0
        };

        if avg_packet_size > 1400.0 {
            anomalies.push(format!("Unusually large avg packet size: {:.2} bytes", avg_packet_size));
        }

        anomalies
    }

    pub fn get_bandwidth_utilization(&self, link_capacity_mbps: f64) -> f64 {
        let performance = self.get_performance_stats();
        (performance_throught_mbps / link_capacity_mbps) * 100.0
    }

    pub fn reset_stats(&mut self) {
        self.flow.clear();
        self.packet_buffer.clear();
        self.start_time = Instant::now();
        self.total_packets = 0;
        self.total_bytes = 0;
        self.protocol_stats.clear();
        self.ip_stats.clear();
        self.port_stats.clear();
        self.performance_buffer.clear();
        self.rtt_samples.clear();
        self.lost_packets = 0;
    }
}