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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AnomalyType {
}