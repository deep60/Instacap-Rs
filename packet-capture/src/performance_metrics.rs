use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex, RwLock};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMetrics {
    pub timestamp: u64,
    pub latency_ms: f64,
    pub jitter_ms: f64,
    pub packet_loss_percent: f64,
    pub throughput_mbps: f64,
    pub packet_per_second: u32,
    pub bandwidth_utilization_percent: f64,
    pub connection_count: u32,
    pub error_rate_percent: f64,
    pub retransmission_rate_percent: f64,
}

#[derive(Debug, Clone)]
pub struct PacketMetrics {
    pub size: usize,
    pub timestamp: Instant,
    pub source_ip: String,
    pub dest_ip: String,
    pub protocol: String,
    pub port: u16,
    pub rtt: Option<Duration>,
}

#[derive(Debug)]
pub struct PerformanceTracker {
    packet_buffer: Arc<Mutex<VecDeque<PacketMetrics>>>,
    metrics_history: Arc<RwLock<VecDeque<NetworkMetrics>>>,
    connection_tracker: Arc<Mutex<HashMap<String, ConnectionMetrics>>>,
    start_time: Instant,
    buffer_size: usize,
    sampling_interval: Duration,
    last_calculation: Arc<Mutex<Instant>>,
}

#[derive(Debug, Clone)]
pub struct ConnectionMetrics {
    packet_sent: u32,
    packet_received: u32,
    bytes_sent: u64,
    bytes_received: u64,
    established_time: Instant,
    last_activity: Instant,
    retransmissions: u32,
    errors: u32,
}

#[derive(Debug)]
pub struct LatencyMeasurement {
    request_line: Instant,
    response_time: Option<Instant>,
    connection_id: String,
}

impl PerformanceTracker {
    pub fn new(buffer_size: usize, sampling_interval: Duration) -> Self {
        Self {
            packet_buffer: Arc::new(Mutex::new(VecDeque::with_capacity(buffer_size))),
            metrics_history: Arc::new(RwLock::new(VecDeque::with_capacity(1000))), // RwLock allows multiple readers or one writer 
            connection_tracker: Arc::new(Mutex::new(HashMap::new())),
            start_time: Instant::now(),
            buffer_size,
            sampling_interval,
            last_calculation: Arc::new(Mutex::new(Instant::now())),
        }
    }

    // Additional methods for tracking packets, calculating metrics, etc. would go here.
    pub fn record_packet(&self, packet: PacketMetrics) {
        let mut buffer = self.packet_buffer.lock().unwrap();

        // implement circular buffer: removes oldest packet when buffer is full
        //Maintain a fixed meomry usage regardless of runtime
        if buffer.len() >= self.buffer_size {
            buffer.pop_front();
        }
        // Update connection metrics
        self.update_connection_metrics(&packet);
        buffer.push_back(packet);
    }

    fn update_connection_metrics(&self, packet: &PacketMetrics) {
        let mut connections = self.connection_tracker.lock().unwrap();
        let connection_key = format!("{}:{}-->{}", packet.protocol, packet.source_ip, packet.dest_ip);

        let connection = connections.entry(connection_key).or_insert_with(|| ConnectionMetrics {
            packet_sent: 0,
            packet_received: 0,
            bytes_sent: 0,
            bytes_received: 0,
            established_time: packet.timestamp,
            last_activity: packet.timestamp,
            retransmissions: 0,
            errors: 0,
        });

        connection.packet_sent += 1;
        connection.bytes_sent += packet.size as u64;
        connection.last_activity = packet.timestamp;
    }

    pub fn calculate_metrics(&self) -> Option<NetworkMetrics> {
        let mut last_calc = self.last_calculation.lock().unwrap();
        let now = Instant::now();
        
        if now.duration_since(*last_calc) < self.sampling_interval {
            return None; // Not enough time has passed since the last calculation
        }

        *last_calc = now;
        drop(last_calc);

        let buffer = self.packet_buffer.lock().unwrap();  // Get a snapshot of current data
        let connections = self.connection_tracker.lock().unwrap();

        if buffer.is_empty() {
            return None; // No packets to analyze
        }

        let packets: Vec<_> = buffer.iter().cloned().collect();
        drop(buffer);

        // Calculate latency, jitter
        let (latency, jitter) = Self::calculate_latency_and_jitter(&packets);

        // Calculate throughput
        let throughput = self.calculate_throughput(&packets);

        // Calculate packet loss
        let packet_loss = self.calculate_packet_loss(&connections);

        // Calculate packets per second
        let pps = self.calculate_packets_per_second(&packets);

        // Calculate bandwidth utilization
        let bandwidth_util = self.calculate_bandwidth_utilization(&packets);

        // Calculate error rates
        let (error_rate, retrans_rate) = self.calculate_error_rates(&connections);

        let metrics = NetworkMetrics {
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            latency_ms: latency,
            jitter_ms: jitter,
            packet_loss_percent: packet_loss,
            throughput_kbps: throughput,
            packet_per_second: pps,
            bandwidth_utilization_percent: bandwidth_util,
            connection_count: connections.len() as u32,
            error_rate_percent: error_rate,
            retransmission_rate_percent: retrans_rate,
        };

        // Store in history
        let mut history = self.metrics_history.write().unwrap();
        if history.len() >= 1000 {
            history.pop_front(); // Maintain a maximum size
        }
        history.push_back(metrics.clone());

        Some(metrics)
    }

    // Extract RTT values from packets that have them 
    fn calculate_latency_and_jitter(&self, packets: &[PacketMetrics]) -> (f64, f64) {
        let rtts: Vec<f64> = packets.iter()
            .filter_map(|p| p.rtt.map(|rtt| rtt.as_secs_f64() * 1000.0)) // Convert seconds to milliseconds
            .collect();

        if rtts.is_empty() {
            return (0.0, 0.0);
        }

        let avg_latency = rtts.iter().sum::<f64>() / rtts.len() as f64;   // calculate average latency across all packet with RTT data

        // Calculate jitter (average deviation from mean)
        // uage sample variance formula (n-1 denominator)
        let jitter = if rtts.len > 1 {
            let variance: f64 = rtts.iter()
                .map(|rtt| (rtt - avg_latency).powi(2))
                .sum::<f64>() / (rtts.len() - 1) as f64;
            variance.sqrt()
        } else {
            0.0
        };

        (avg_latency, jitter)
    }

    fn calculate_throughput(&self, packets: &[PacketMetrics]) -> f64 {
        if packets.is_empty() {
            return 0.0; // No packets to calculate throughput
        }

        let total_bytes: usize = packets.iter().map(|p| p.size);
        let time_window = packets
            .last()
            .unwrap()
            .timestamp
            .duration_since(packets.first().unwrap().timestamp)
            .as_secs_f64();

        if time_window > 0.0 {
            (total_bytes as f64 * 8.0) / (time_window * 1_000_000.0) // Convert to Mbps
        } else {
            0.0
        }
    }

    fn calculate_packet_loss(&self, connections: &HashMap<String, ConnectionMetrics>) -> f64 {
        let total_sent: u32 = connections.values().map(|c| c.packet_sent).sum();
        let total_received: u32 = connections.values().map(|c| c.packet_received).sum();

        if total_sent > 0 {
            ((total_sent - total_received) as f64 / total_sent as f64) * 100.0 // Avoid division by zero
        } else {
            0.0 // No packets sent, no loss
        }
    }

    fn calculate_packets_per_second(&self, packets: &[PacketMetrics]) -> u32 {
        if packets.is_empty() {
            return 0; // No packets to calculate
        }

        let time_window = packets
            .last()
            .unwrap()
            .timestamp
            .duration_since(packets.first().unwrap().timestamp)
            .as_secs_f64();

        if time_window > 0.0 {
            (packets.len() as f64 / time_window) as u32 // Packets per second
        } else {
            0 // Avoid division by zero
        }
    }

    fn calculate_bandwidth_utilization(&self, packets: &[PacketMetrics]) -> f64 {
        // Assuming 1 Gbps link speed for calculation
        const LINK_SPEED_BPS: f64 = 1000.0; 

        let throughput = self.calculate_throughput(packets);
        (throughput / LINK_SPEED_BPS) * 100.0 // Convert to percentage
    }

    // Calculate error and retransmission rates as percentages
    // Provides separate tracking for different types of network issues
    fn calculate_error_rates(&self, connections: &HashMap<String, ConnectionMetrics>) -> (f64, f64) {
        let total_packets: u32 = connections.values().map(|c| c.packet_sent).sum();
        let total_retrans: u32 = connections.values().map(|c| c.retransmissions).sum();
        let total_errors: u32 = connections.values().map(|c| c.errors).sum();

        let error_rate = if total_packets > 0 {
            (total_errors as f64 / total_packets as f64) * 100.0
        } else {
            0.0 // No packets sent, no errors
        };

        let retrans_rate = if total_packets > 0 {
            (total_retrans as f64 / total_packets as f64) * 100.0
        } else {
            0.0 // No packets sent, no retransmissions
        };

        (error_rate, retrans_rate)
    }

    pub fn get_metrics_history(&self, limit: Option<usize>) -> Vec<NetworkMetrics> {
        let history = self.metrics_history.read().unwrap();
        let start_idx = if let Some(limit) = limit {
            history.len().saturating_sub(limit)
        } else {
            0
        };

        history.range(start_idx..).cloned().collect()
    }

    pub fn get_connection_stats(&self) -> HashMap<String, ConnectionMetrics> {
        self.connection_tracker.lock().unwrap().clone()
    }

    pub fn cleanup_old_connections(&self, timeout: Duration) {
        let mut connections = self.connection_tracker.lock().unwrap();
        let now = Instant::now();

        connections.retain(|_, conn| {
            now.duration_since(conn.last_activity) < timeout
        });
    }

    pub fn record_error(&self, connection_key: &str) {
        let mut connections = self.connection_tracker.lock().unwrap();
        if let Some(conn) = connections.get_mut(connection_key) {
            conn.errors += 1;
        }
    }

    pub fn record_retransmission(&self, connection_key: &str) {
        let mut connections = self.connection_tracker.lock().unwrap();
        if let Some(conn) = connections.get_mut(connection_key) {
            conn.retransmissions += 1;
        }
    }

    pub fn get_current_stats(&self) -> Option<NetworkMetrics> {
        self.calculate_metrics()
    }

    pub fn export_metrics_csv(&self) -> String {
        let history = self.metrics_history.read().unwrap();
        let mut csv = String::from("timestamp,latency_ms,jitter_ms,packet_loss_percent,throughput_mbps,packet_per_second,bandwidth_utilization_percent,connection_count,error_rate_percent,retransmission_rate_percent\n"); 

        for metrics in history.iter() {
            csv.push_str(&format!(
                "{},{:.2},{:.2},{:.2},{:.2},{},{:.2},{},{:.2},{:.2}\n",
                metrics.timestamp,
                metrics.latency_ms,
                metrics.jitter_ms,
                metrics.packet_loss_percent,
                metrics.throughput_mbps,
                metrics.packet_per_second,
                metrics.bandwidth_utilization_percent,
                metrics.connection_count,
                metrics.error_rate_percent,
                metrics.retransmission_rate_percent
            ));
        }
        csv
    }

    pub fn get_performance_summary(&self) -> PerformanceSummary {
        let history = self.metrics_history.read().unwrap();

        if history.is_empty() {
            return PerformanceSummary::default();
        }

        let latencies: Vec<f64> = history.iter().map(|m| m.latency_ms).collect();
        let throughputs: Vec<f64> = history.iter().map(|m| m.throughput_mbps).collect();
        let packet_losses: Vec<f64> = history.iter().map(|m| m.packet_loss_percent).collect();

        PerformanceSummary {
            avg_latency: latencies.iter().sum::<f64>() / latencies.len() as f64,
            max_latency: *latencies.iter().fold(0.0, |a, &b| a.max(b)),
            min_latency: *latencies.iter().fold(f64::INFINITY, |a, &b| a.min(b)),
            avg_throughput: throughputs.iter().sum::<f64>() / throughputs.len() as f64,
            max_throughput: throughputs.iter().fold(0.0, |a, &b| a.max(b)),
            avg_packet_loss: packet_losses.iter().sum::<f64>() / packet_losses.len() as f64,
            max_packet_loss: packet_losses.iter().fold(0.0, |a, &b| a.max(b)),
            uptime_seconds: self.start_time.elapsed().as_secs(),
            total_connections: self.connection_tracker.lock().unwrap().len() as u32,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceSummary {
    pub avg_latency: f64,
    pub max_latency: f64,
    pub min_latency: f64,
    pub avg_throughput: f64,
    pub max_throughput: f64,
    pub avg_packet_loss: f64,
    pub max_packet_loss: f64,
    pub uptime_seconds: u64,
    pub total_connections: u32,
}

impl Default for PerformanceSummary {
    fn default() -> Self {
        Self {
            avg_latency: 0.0,
            max_latency: 0.0,
            min_latency: 0.0,
            avg_throughput: 0.0,
            max_throughput: 0.0,
            avg_packet_loss: 0.0,
            max_packet_loss: 0.0,
            uptime_seconds: 0.0,
            total_connections: 0.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_performance_tracker_creation() {
        let tracker = PerformanceTracker::new(1000, Duration::from_secs(1));
        assert_eq!(tracker.buffer_size, 1000); 
    }

    #[test]
    fn test_packet_recording() {
        let tracker = PerformanceTracker::new(10, Duration::from_secs(1));
        let packet = PacketMetrics {
            size: 1500,
            timestamp: Instant::now(),
            source_ip: "192.168.1.1".to_string(),
            dest_ip: "192.168.1.2".to_string(),
            protocol: "TCP".to_string(),
            port: 80,
            rtt: Some(Duration::from_millis(10)),
        };
        tracker.record_packet(packet);

        let buffer = tracker.packet_buffer.lock().unwrap();
        assert_eq!(buffer.len(), 1);
    }

    #[test]
    fn test_metrics_calculation() {
        let tracker = PerformanceTracker::new(10, Duration::from_millis(1));

        for i in 0..5 {
            let packet = PacketMetrics {
                size: 1000,
                timestamp: Instant::now(),
                source_ip: format!("192.168.1.{}", i),
                dest_ip: "192.168.1.100".to_string(),
                protocol: "TCP".to_string(),
                port: 80,
                rtt: Some(Duration::from_millis(5 + i as u64)),
            };
            tracker.record_packet(packet);
            thread::sleep(Duration::from_millis(10)); // Simulate time passing
        }

        thread::sleep(Duration::from_millis(10)); // Allow time for metrics to be calculated
        let metrics = tracker.calculate_metrics();
        assert!(metrics.is_some());

        let metrics = metrics.unwrap();
        assert!(metrics.latency_ms >= 0.0);
        assert!(metrics.throughput_mbps >= 0.0);
    }
}