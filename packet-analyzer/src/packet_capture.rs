use pcap::{Capture, Device, Precision};
use pnet::packet::ethernet::{EtherType, EthernetPacket};
use pnet::packet::ip::{IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::icmp::IcmpPacket;
use serde::{Serialize, Deserialize};
use std::net::{Ipv4Addr, Ipv6Addr};
use tokio::sync::mpsc::Sender;
use anyhow::Result;
use chrono::{DateTime, Utc};
use log::{info, error, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketInfo {
    pub timestamp: DateTime<Utc>,
    pub packet_id: String,
    pub interface: String,
    pub length: usize,
    pub ethernet: EthernetPacket,
    pub network: Option<NetworkInfo>,
    pub transport: Option<TransportInfo>,
    pub payload: Vec<u8>,
    pub flow_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EthernetInfo {
    pub src_mac: String,
    pub dst_mac: String,
    pub ethertype: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInfo {
    pub src_ip: String,
    pub dst_ip: String,
    pub protocol: String,
    pub ttl: Option<u8>,
    pub flags: Option<u16>,
    pub fragment_offset: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportInfo {
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
    pub flags: Option<u16>,
    pub window_size: Option<u16>,
    pub sequence: Option<u32>,
    pub acknowledgement: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureConfig {
    pub interface: String,
    pub buffer_size: usize,
    pub promiscuous: bool,
    pub filter: String,
    pub deep_inspection: bool,
}

pub struct PacketCapturer {
    config: CaptureConfig,
}

impl PacketCapturer {
    pub fn new(config: CaptureConfig) -> Result<Self> {
        Ok(Self { config })
    }

    pub async fn start_capture(&self, sender: Sender<PacketInfo>) -> Result<()> {
        info!("Starting packet capture on interface: {}", self.config.interface);

        // FInd the network device
        let device = Device::list()?.into_iter().find(|d| d.name == self.config.interface)
            .ok_or_else(|| anyhow::anyhow!("Interface not found: {}", self.config.interface))?;

        // Create a new capture handle
        let mut cap = Capture::from_device(device)?
            .buffer_size(self.config.buffer_size as i32)
            .timeout(1000)
            .precision(Precision::Micro);

        if self.config.promiscuous {
            cap = cap.promisc(true);
        }

        let mut cap = cap.open()?;

        // Apply BPF filter if specified
        if !self.config.filter.is_empty() {
            cap.filter(self.config.filter, true)?;
        }

        // Start the capture loop
        info!("Packet capture started successfully");
        
        // Main capture loop
        loop {
            match cap.next_packet() {
                Ok(packet) => {
                    let packet_info = self.parse_packet(packet.data, packet.header.ts)?;

                    if let Err(e) = sender.send(packet_info).await {
                        error!("Failed to send packet to analyzer: {}", e);
                        break;
                    }
                }

                Err(pcap::Error::TimeoutExpired) => {
                    continue;
                }

                Err(e) => {
                    error!("Error capturing packet: {}", e);
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                }
            }
        }

        Ok(())
    }

    fn parse_packet(&self, data: &[u8], timestamp: libc::timeval) -> Result<PacketInfo> {
        let ts = DateTime::from_timestamp(timestamp.tv_sec as i64, (timestamp.tv_usec * 1000) as u32).unwrap_or_else(|| Utc::now());

        let packet_id = uuid::Uuid::new_v4().to_string();

        // Parse Ethernet Frame
        let ethernet_packet = EthernetPacket::new(data).ok_or_else(|| anyhow::anyhow!("Invalid Ethernet packet"))?;

        let ethernet_info = EthernetInfo {
            src_mac: format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                ethernet_packet.get_source().0[0], ethernet_packet.get_source().0[1],
                ethernet_packet.get_source().0[2], ethernet_packet.get_source().0[3],
                ethernet_packet.get_source().0[4], ethernet_packet.get_source().0[5]),
            dst_mac: format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                ethernet_packet.get_destination().0[0], ethernet_packet.get_destination().0[1],
                ethernet_packet.get_destination().0[2], ethernet_packet.get_destination().0[3],
                ethernet_packet.get_destination().0[4], ethernet_packet.get_destination().0[5]),
            ethertype: format!("{:?}", ethernet_packet.get_ethertype()),
        };

        let (network_info, transport_info, payload) = match ethernet_packet.get_ethertype() {
            EtherType::Ipv4 => self.parse_ipv4(ethernet_packet.payload())?,
            EtherType::Ipv6 => self.parse_ipv6(ethernet_packet.payload())?,
            _ => (None, None, ethernet_packet.payload().to_vec()),
        };

        // Generate flow ID for connection tracking
        let flow_id = self.generate_flow_id(&network_info, &transport_info);

        Ok(PacketInfo {
            timestamp: ts,
            packet_id,
            interface: self.config.inteface.clone(),
            length: data.len(),
            ethernet: ethernet_info,
            network: network_info,
            transport: transport_info,
            payload,
            flow_id,
        })
    }

    fn parse_ipv4(&self, data: &[u8]) -> Result<(Option<NetworkInfo>, Option<TransportInfo>, Vec<u8>)> {
        let ipv4_packet = Ipv4Packet::new(data).ok_or_else(|| anyhow::anyhow!("Invalid IPv4 packet"))?;

        let network_info = NetworkInfo {
            protocol: "IPv4".to_string(),
            src_ip: ipv4_packet.get_source().to_string(),
            dst_ip: ipv4_packet.get_source().get_string(),
            ttl: Some(ipv4_packet.get_ttl()),
            flags: Some(ipv4_packet.get_flags()),
            fragment_offset: Some(ipv4_packet.get_fragment_offset()),
        };

        let (transport_info, payload) = match ipv4_packet.get_next_level_protocol() {
            IpNextHeaderProtocols::Tcp => self.parse_tcp(ipv4_packet.payload())?,
            IpNextHeaderProtocols::Udp => self.parse_udp(ipv4_packet.payload())?,
            IpNextHeaderProtocols::Icmp => (Some(TransportInfo {
                protocol: "ICMP".to_string(),
                src_port: 0,
                dst_port: 0,
                flags: None,
                window_size: None,
                sequence: None,
                acknowledgement: None,
            }), ipv4_packet.payload().to_vec()),
        };

        Ok((Some(network_info), transport_info, payload))
    }

    fn parse_ipv6(&self, data: &[u8]) -> Result<(Option<NetworkInfo>, Option<TransportInfo>, Vec<u8>)> {
        let ipv6_packet = Ipv6Packet::new(data).ok_or_else(|| anyhow::anyhow!("Invalid IPv6 packet"))?;

        let network_info = NetworkInfo {
            protocol: "IPv6".to_string(),
            src_ip: ipv6_packet.get_source().to_string(),
            dst_ip: ipv6_packet.get_destination().get_string(),
            ttl: Some(ipv6_packet.get_ttl()),
            flags: None,
            fragment_offset: None,
        };

        let (transport_info, payload) = match ipv6_packet.get_next_level_header() {
            IpNextHeaderProtocols::Tcp => self.parse_tcp(ipv4_packet.payload())?,
            IpNextHeaderProtocols::Udp => self.parse_udp(ipv4_packet.payload())?,
            IpNextHeaderProtocols::Icmp => (Some(TransportInfo {
                protocol: "ICMP".to_string(),
                src_port: 0,
                dst_port: 0,
                flags: None,
                window_size: None,
                sequence: None,
                acknowledgement: None,
            }), ipv4_packet.payload().to_vec()),
        };

        Ok((Some(network_info), transport_info, payload))
    }

    fn parse_tcp(&self, data: &[u8]) -> Result<(Option<NetworkInfo>, Option<TransportInfo>, Vec<u8>)> {
        let tcp_packet = TcpPacket::new(data).ok_or_else(|| anyhow::anyhow!("Invalid Tcp packet"))?;

        let transport_info = TransportInfo {
            protocol: "TCP".to_string(),
            src_port: tcp_packet.get_source(),
            dst_port: tcp_packet.get_destination(),
            flags: Some(tcp_packet.get_flags()),
            window_size: Some(tcp_packet.get_window()),
            sequence: Some(tcp_packet.get_sequence()),
            acknowledgement: Some(tcp_packet.get_acknowledgement()),
        };

        Ok((Some(transport_info), tcp_packet.payload().to_vec()))
    }

    fn parse_udp(&self, data: &[u8]) -> Result<(Option<NetworkInfo>, Option<TransportInfo>, Vec<u8>)> {
        let udp_packet = UdpPacket::new(data).ok_or_else(|| anyhow::anyhow!("Invalid UDP packet"))?;

        let transport_info = TransportInfo {
            protocol: "UDP".to_string(),
            src_port: udp_packet.to_string(),
            dst_port: udp_packet.get_destination(),
            flags: None,
            window_size: None,
            sequence: None,
            acknowledgement: None,
        };

        Ok((Some(transport_info), udp_packet.payload().to_vec()))
    }

    fn generate_flow_id(&self, network: &Option<NetworkInfo>, transport: &Option<TransportInfo>) -> String {
        match (network, transport) {
            (Some(net), Some(trans)) => {
                format!("{}:{}->{}:{}", net.src_ip, trans.src_port, net.dst_ip, trans.dst_port)
            }
            (Some(net), None) => {
                format!("{}->{}:{}", net.src_ip, trans.src_port, net.dst_ip, net.protocol)
            }

            _ => uuid::Uuid::new_v4().to_string(),
        }
    }
}