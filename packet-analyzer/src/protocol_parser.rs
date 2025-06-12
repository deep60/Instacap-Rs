use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ParsedPacket {
    pub timestamp: u64,
    pub ethernet: EthernetHeader,
    pub ip: Option<IpHeader>,
    pub transport: Option<TransportHeader>,
    pub application: Option<ApplicationData>,
    pub packet_size: usize,
    pub payload_size: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EthernetHeader {
    pub src_mac: String,
    pub dst_mac: String,
    pub ether_type: u16,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IpHeader {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Ipv4Addr {
    pub version: u8,
    pub header_length: u8,
    pub tos: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Ipv6Addr {
    pub version: u8,
    pub traffic_class: u8,
    pub flow_label: u32,
    pub payload_length: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub src_ip: Ipv6Addr,
    pub dst_ip: Ipv6Addr,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum TransportHeader {
    Tcp(TcpHeader),
    Udp(UdpHeader),
    Icmp(IcmpHeader),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub sequence: u32,
    pub acknowledgment: u32,
    pub header_length: u8,
    pub flags: TcpFlags,
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
    pub urg: bool,
    pub ece: bool,
    pub cwr: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IcmpHeader {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: u16,
    pub identifier: u16,
    pub sequence_number: u16,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ApplicationData {
    Http(HttpData),
    Dns(DnsData),
    Ftp(FtpData),
    Smtp(SmtpData),
    Unknown(Vec<u8>),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HttpData {
    pub method: Option<String>,
    pub url: Option<String>,
    pub version: Option<String>,
    pub headers: HashMap<String, String>,
    pub body: Option<Vec<u8>>,
    pub is_request: bool,
    pub status_code: Option<u16>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DnsData {
    pub transaction_id: u16,
    pub flags: u16,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsAnswer>,
    pub is_query: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DnsQuestion {
    pub name: String,
    pub query_type: u16,
    pub class: u16,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DnsAnswer {
    pub name: String,
    pub answer_type: u16,
    pub class: u16,
    pub ttl: u32,
    pub data: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FtpData {
    pub command: Option<String>,
    pub message: String,
    pub response_code: Option<u16>,
    pub is_command: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SmtpData {
    pub command: Option<String>,
    pub response_code: Option<u16>,
    pub message: String,
    pub is_command: bool,
}

pub struct ProtocolParser {
    pub stats: ParserStats
}

pub struct ParserStats {
    pub packet_parsed: u64,
    pub ipv4_packets: u64,
    pub ipv6_packets: u64,
    pub tcp_packets: u64,
    pub udp_packets: u64,
    pub icmp_packets: u64,
    pub http_packets: u64,
    pub dns_packets: u64,
    pub ftp_packets: u64,
    pub smtp_packets: u64,
    pub malformed_packets: u64,
}

impl ProtocolParser {
    pub fn new() -> Self {
        Self {
            stats: ParserStats::default(),
        }
    }
    pub fn parse_packet(&mut self, packet_data: &[u8], timestamp: u64) -> Result<ParsedPacket, String> {
        if packet_data.len() < 14 {
            self.stats.malformed_packets += 1;
            return Err("Packet too small for Ethernet header".to_string());
        }
        // Parsing logic goes here
        // For now, we return a dummy ParsedPacket
        self.stats.packet_parsed += 1;
        let ethernet = self.parse_ethernet_header(&packet_data[0..14])?;
        let mut offset = 14;

        let ip = match ethernet.ether_type {
            0x0800 => {
                // IPv4
                if packet_data.len() < offset + 20 {
                    return Err("Packet too small for IPv4 header".to_string());
                }
                self.stats.ipv4_packets += 1;
                Some(IpHeader::V4(self.parse_ipv4_header(&packet_data[offset..offset + 20])?))
            },
            0x86DD => {
                // IPv6
                if packet_data.len() < offset + 40 {
                    return Err("Packet too small for IPv6 header".to_string());
                }
                self.stats.ipv6_packets += 1;
                Some(IpHeader::V6(self.parse_ipv6_header(&packet_data[offset..offset + 40])?))
            }
            _ => None,
        };

        let (transport, payload_offset) = if let Some(ref ip_header) = ip {
            match ip_header {
                IpHeader::V4(ipv4) => {
                    offset += (ipv4.header_length * 4) as usize;
                    self.parse_transport_layer(&packet_data[offset..], ipv4.protocol, offset)?
                },
                IpHeader::V6(ipv6) => {
                    offset += 40;
                    self.parse_transport_layer(&packet_data[offset..], &ipv6.next_header, offset)?
                },
            }
        } else {
            (None, offset)
        };

        let application = if payload_offset < packet_data.len() {
            self.parse_application_layer(&packet_data[payload_offset..], transport_header)?
        } else {
            None
        };

        Ok(ParsedPacket {
            timestamp,
            ethernet,
            ip,
            transport,
            application,
            packet_size: packet_data.len(),
            payload_size: packet_data.len().saturating_sub(payload_offset),
        })
    }

    fn parse_ethernet_header(&self, data: &[u8]) -> Result<EthernetHeader, String> {
        Ok(EthernetHeader {
            dst_mac: format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                data[0], data[1], data[2], data[3], data[4], data[5]),
            src_mac: format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                data[6], data[7], data[8], data[9], data[10], data[11]),
            ether_type: u16::from_be_bytes([data[12], data[13]]),
        })
    }

    fn parse_ipv4_header(&self, data: &[u8]) -> Result<Ipv4Addr, String> {
        if data.len() < 20 {
            return Err("Packet too small for IPv4 header".to_string());
        }
        Ok(Ipv4Addr {
            version: (data[0] & 0x0F) >> 4,
            header_length: data[0] & 0x0F,
            tos: data[1],
            total_length: u16::from_be_bytes([data[2], data[3]]),
            identification: u16::from_be_bytes([data[4], data[5]]),
            flags: (data[6] & 0xE0) >> 5,
            fragment_offset: u16::from_be_bytes([data[6] & 0x1F, data[7]]),
            ttl: data[8],
            protocol: data[9],
            checksum: u16::from_be_bytes([data[10], data[11]]),
            src_ip: Ipv4Addr::new(data[12], data[13], data[14], data[15]),
            dst_ip: Ipv4Addr::new(data[16], data[17], data[18], data[19]),
        })
    }

    fn parse_ipv6_header(&self, data: &[u8]) -> Result<Ipv6Addr, String> {
        let version_traffic_flow = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);

        Ok(Ipv6Addr {
            version: ((version_traffic_flow & 0xF0000000) >> 28) as u8,
            traffic_class: ((version_traffic_flow & 0x0FF00000) >> 20) as u8,
            flow_label: version_traffic_flow & 0x000FFFFF,
            payload_length: u16::from_be_bytes([data[4], data[5]]),
            next_header: data[6],
            hop_limit: data[7],
            src_ip: Ipv6Addr::new(
                u16::from_be_bytes([data[8], data[9]]),
                u16::from_be_bytes([data[10], data[11]]),
                u16::from_be_bytes([data[12], data[13]]),
                u16::from_be_bytes([data[14], data[15]]),
                u16::from_be_bytes([data[16], data[17]]),
                u16::from_be_bytes([data[18], data[19]]),
                u16::from_be_bytes([data[20], data[21]]),
                u16::from_be_bytes([data[22], data[23]]),
            ),
            dst_ip: Ipv6Addr::new(
                u16::from_be_bytes([data[24], data[25]]),
                u16::from_be_bytes([data[26], data[27]]),
                u16::from_be_bytes([data[28], data[29]]),
                u16::from_be_bytes([data[30], data[31]]),
                u16::from_be_bytes([data[32], data[33]]),
                u16::from_be_bytes([data[34], data[35]]),
                u16::from_be_bytes([data[36], data[37]]),
                u16::from_be_bytes([data[38], data[39]]),
            ),
        })
    }

    fn parse_transport_layer(&mut self, data: &[u8], protocol: u8, base_offset: usize) -> Result<(Option<TransportHeader>, usize), String> {
        match protocol {
            6 => { 
                // TCP
                if data.len() < 20 {
                    return Ok((None, base_offset + data.len()));
                }
                self.stats.tcp_packets += 1;
                let tcp_header = self.parse_tcp_header(&data[0..20])?;
                let header_len = (tcp_header.header_length * 4) as usize;
                Ok((Some(TransportHeader::Tcp(tcp_header)), base_offset + header_len))
            },
            17 => { 
                // UDP
                if data.len() < 8 {
                    return Ok((None, base_offset + data.len())));
                }
                self.stats.udp_packets += 1;
                let udp_header = self.parse_udp_header(&data[0..8])?;
                Ok((Some(TransportHeader::Udp(udp_header)), base_offset + 8))
            },
            1 => { // ICMP
                if data.len() < 8 {
                    return Ok((None, base_offset + data.len())));
                }
                self.stats.icmp_packets += 1;
                let icmp_header = self.parse_icmp_header(&data[0..8])?;
                Ok((Some(TransportHeader::Icmp(icmp_header)), base_offset + 8))
            },
            _ => Ok((None, base_offset + data.len())),
        }
    }

    fn parse_tcp_header(&self, data: &[u8]) -> Result<TcpHeader, String> {
        let flag_byte = data[13];

        Ok(TcpHeader {
            src_port: u16::from_be_bytes([data[0], data[1]]),
            dst_port: u16::from_be_bytes([data[2], data[3]]),
            sequence: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
            acknowledgment: u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
            header_length: (data[12] & 0xF0) >> 4,
            flags: TcpFlags {
                fin: (flag_byte & 0x01) != 0,
                syn: (flag_byte & 0x02) != 0,
                rst: (flag_byte & 0x04) != 0,
                psh: (flag_byte & 0x08) != 0,
                ack: (flag_byte & 0x10) != 0,
                urg: (flag_byte & 0x20) != 0,
                ece: (flag_byte & 0x40) != 0,
                cwr: (flag_byte & 0x80) != 0,
            },
            window_size: u16::from_be_bytes([data[14], data[15]]),
            checksum: u16::from_be_bytes([data[16], data[17]]),
            urgent_pointer: u16::from_be_bytes([data[18], data[19]]),
        })
    }

    fn parse_udp_header(&self, data: &[u8]) -> Result<UdpHeader, String> {
        Ok(UdpHeader {
            src_port: u16::from_be_bytes([data[0], data[1]]),
            dst_port: u16::from_be_bytes([data[2], data[3]]),
            length: u16::from_be_bytes([data[4], data[5]]),
            checksum: u16::from_be_bytes([data[6], data[7]]),
        })
    }

    fn parse_icmp_header(&self, data: &[u8]) -> Result<IcmpHeader, String> {
        Ok(IcmpHeader {
            icmp_type: data[0],
            code: data[1],
            checksum: u16::from_be_bytes([data[2], data[3]]),
            identifier: u16::from_be_bytes([data[4], data[5]]),
            sequence_number: u16::from_be_bytes([data[6], data[7]]),
        })
    }

    fn parse_application_layer(&mut self, data: &[u8], transport: &Option<TransportHeader>) -> Result<Option<ApplicationData>, String> {
        if let Some(transport_header) = transport {
            match transport_header {
                TransportHeader::Tcp(tcp) => {
                    match tcp.dst_port {
                    80 | 8080 | 443 => {
                        self.stats.http_packets += 1;
                        Ok(Some(ApplicationData::Http(self.parse_http_data(data)?)))
                    },
                    21 => {
                        self.stats.ftp_packets += 1;
                        Ok(Some(ApplicationData::Ftp(self.parse_ftp_data(data)?)))
                    },
                    25 | 587 => {
                        self.stats.smtp_packets += 1;
                        Ok(Some(ApplicationData::Smtp(self.parse_smtp_data(data)?)))
                    },
                    _ => Ok(Some(ApplicationData::Unknown(data.to_vec()))),
                }
            },
            TransportHeader::Udp(udp) => {
                match udp.dst_port {
                    53 => {
                        self.stats.dns_packets += 1;
                        Ok(Some(ApplicationData::Dns(self.parse_dns_data(data)?)))
                    },
                    _ => Ok(Some(ApplicationData::Unknown(data.to_vec()))),
                }
            },
            _ => Ok(Some(ApplicationData::Unknown(data.to_vec()))),
        }
        } else {
            Ok(None)
        }
    }

    fn parse_http_data(&self, data: &[u8]) -> Result<HttpData, String> {
        // Placeholder for actual HTTP parsing logic
        let text = String::from_utf8_lossy(data);
        let lines: Vec<&str> = text.lines().collect();

        if lines.is_empty() {
            return Ok(HttpData {
                method: None,
                url: None,
                version: None,
                headers: HashMap::new(),
                body: None,
                is_request: false,
                status_code: None,
            });
        }

        let first_line = lines[0];
        let mut headers = HashMap::new();
        let mut body_start = 0;

        // Parse headers
        for (i, line) in lines.iter().enumerate().skip(1) {
            if line.is_empty() {
                body_start = i + 1;
                break;
            }
            if let Some(colon_pos) = line.find(':') {
                let key = line[..colon_pos].trim().to_lowercase();
                let value = line[colon_pos + 1..].trim().to_string();;
                headers.insert(key, value);
            }
        }

        let is_request = first_line.starts_with("GET") || first_line.starts_with("POST") || 
                         first_line.starts_with("PUT") || first_line.starts_with("DELETE") || 
                         first_line.starts_with("HEAD") || first_line.starts_with("OPTIONS");
        let (method, url, version) = if is_request {
            let parts: Vec<&str> = first_line.split_whitespace().collect();
            if parts.len() >= 3 {
                (Some(parts[0].to_string()), Some(parts[1].to_string()), Some(parts[2].to_string()), None)
            } else {
                (None, None, None, None)
            }
        } else {
            // HTTP response
            let parts: Vec<&str> = first_line.split_whitespace().collect();
            if parts.len() < 2 {
                let status = parts[1].parse::<u16>().ok();
                (None, None, Some(parts[0].to_string()), status)
            } else {
                (None, None, Some(parts[0].to_string()))
            }
        };

        let body = if body_start < lines.len() {
            let body_text = lines[body_start..].join("\n");
            if !body_text.is_empty() {
                Some(body_text.into_bytes())
            } else {
                None
            }
        } else {
            None
        };
        Ok(HttpData {
            method,
            url,
            version,
            headers,
            body,
            is_request,
            status_code, // Placeholder for status code
        })
    }

    fn parse_dns_data(&self, data: &[u8]) -> Result<DnsData, String> {
        // Placeholder for actual DNS parsing logic
        if data.len() < 12 {
            return Err("DNS packet too small".to_string());
        }
        let transaction_id = u16::from_be_bytes([data[0], data[1]]);
        let flags = u16::from_be_bytes([data[2], data[3]]);
        let is_query = (flags & 0x8000) == 0;

        // For simplicity, we'll create empty questions and answers vectors
        // In a real implementation, you would parse the full DNS structure
        Ok(DnsData {
            transaction_id,
            flags,
            questions: Vec::new(),
            answers: Vec::new(),
            is_query,
        })
    }

    fn parse_ftp_data(&self, data: &[u8]) -> Result<FtpData, String> {
        // Placeholder for actual FTP parsing logic
        let text = String::from_utf8_lossy(data);
        let line = text.lines().next().unwrap_or("");
        if let Ok(code) = line[..3.min(line.len())].parse::<u16>() {
            // Response
            Ok(FtpData {
                command: None,
                message: line.to_string(),
                response_code: Some(code),
                is_command: false,
            })
        } else {
            // Command
            let parts: Vec<&str> = line.split_whitespace().collect();
            let command = parts.first().map(|s| s.to_uppercase());

            Ok(FtpData {
                command,
                message: line.to_string(),
                response_code: None,
                is_command: true,
            })
        }
    }

    fn parse_smtp_data(&self, data: &[u8]) -> Result<SmtpData, String> {
        // Placeholder for actual SMTP parsing logic
        let text = String::from_utf8_lossy(data);
        let line = text.lines().next().unwrap_or("");

        // SMTP responses star with 3-digit codes
        if let Ok(code) = line[..3.min(line.len())].parse::<u16>() {
            // Response
            Ok(SmtpData {
                command: None,
                response_code: Some(code),
                message: line.to_string(),
                is_command: false,
            })
        } else {
            // Command
            let parts: Vec<&str> = line.split_whitespace().collect();
            let command = parts.first().map(|s| s.to_uppercase());

            Ok(SmtpData {
                command,
                response_code: None,
                message: line.to_string(),
                is_command: true,
            })
        }
    }

    pub fn get_stats(&self) -> &ParserStats {
        &self.stats
    }

    pub fn reset_stats(&mut self) {
        self.stats = ParserStats::default();
    }
}
