//! 数据包解析模块

use anyhow::Result;
use serde::Serialize;
use chrono::{DateTime, Utc};

pub mod ethernet;
pub mod ipv4;
pub mod ipv6;
pub mod tcp;
pub mod udp;
pub mod arp; // 添加 ARP 模块
pub mod application;

/// 解析后的数据包信息
#[derive(Debug, Clone, Serialize)]
pub struct ParsedPacket {
    pub timestamp: DateTime<Utc>,
    pub interface: String,
    pub length: usize,
    pub frame_number: u64,
    pub link_layer: LinkLayer,
    pub network_layer: Option<NetworkLayer>,
    pub transport_layer: Option<TransportLayer>,
    pub application_layer: Option<application::ApplicationLayer>,
    pub session_info: Option<SessionInfo>,

    #[serde(skip)]
    pub transport_payload: Option<Vec<u8>>,
    #[serde(skip)]
    pub raw_data: Vec<u8>,
}

/// 链路层信息
#[derive(Debug, Clone, Serialize)]
pub struct LinkLayer {
    pub protocol: String,
    pub src_mac: Option<String>,
    pub dst_mac: Option<String>,
}

/// 网络层信息
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "protocol")]
pub enum NetworkLayer {
    IPv4 {
        src_ip: String,
        dst_ip: String,
        ttl: u8,
        id: u16,
        flags: Vec<String>,
        fragment_offset: u16,
        total_length: u16,
    },
    IPv6 {
        src_ip: String,
        dst_ip: String,
        hop_limit: u8,
        traffic_class: u8,
        flow_label: u32,
        payload_length: u16,
    },
    ARP {
        operation: String,
        sender_mac: String,
        sender_ip: String,
        target_mac: String,
        target_ip: String,
    },
}

/// 传输层信息
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "protocol")]
pub enum TransportLayer {
    TCP {
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: Vec<String>,
        window: u16,
        checksum: u16,
        urgent_pointer: u16,
    },
    UDP {
        src_port: u16,
        dst_port: u16,
        length: u16,
        checksum: u16,
    },
    ICMP {
        icmp_type: u8,
        icmp_code: u8,
        checksum: u16,
        data: String,
    },
}

impl TransportLayer {
    pub fn name(&self) -> &str {
        match self {
            TransportLayer::TCP { .. } => "TCP",
            TransportLayer::UDP { .. } => "UDP",
            TransportLayer::ICMP { .. } => "ICMP",
        }
    }
}

/// 会话信息
#[derive(Debug, Clone, Serialize)]
pub struct SessionInfo {
    pub session_id: String,
    pub direction: String,  // "request" or "response"
    pub stream_index: u64,
    pub related_packets: Vec<u64>,
    pub total_bytes: u64,
    pub duration_ms: u64,
}

/// 数据包解析器
pub struct PacketParser {
    frame_counter: u64,
}

impl PacketParser {
    pub fn new() -> Self {
        Self { frame_counter: 0 }
    }

    /// 解析原始数据包
    pub fn parse_packet(
        &mut self,
        data: &[u8],
        timestamp: DateTime<Utc>,
        interface: String,
    ) -> Result<ParsedPacket> {
        self.frame_counter += 1;

        // 解析以太网帧
        let (eth_header, mut payload) = ethernet::parse_ethernet_frame(data)?;

        let link_layer = LinkLayer {
            protocol: "Ethernet".to_string(),
            src_mac: Some(format_mac(&eth_header.source)),
            dst_mac: Some(format_mac(&eth_header.destination)),
        };

        let mut network_layer = None;
        let mut transport_layer = None;
        let mut transport_payload = None;

        if eth_header.ether_type == etherparse::EtherType::IPV4 {
            // IPv4
            let (ipv4_header, ipv4_payload) = ipv4::parse_ipv4_packet(payload)?;
            payload = ipv4_payload;
            let protocol = ipv4_header.protocol;
            network_layer = Some(NetworkLayer::IPv4 {
                src_ip: ipv4_header.source.to_string(),
                dst_ip: ipv4_header.destination.to_string(),
                ttl: ipv4_header.ttl,
                id: ipv4_header.identification,
                flags: ipv4::get_ipv4_flags(ipv4_header.flags),
                fragment_offset: ipv4_header.fragment_offset,
                total_length: ipv4_header.total_length,
            });

            if protocol == 6 {
                // TCP
                let (tcp_header, tcp_payload) = tcp::parse_tcp_packet(payload)?;
                transport_layer = Some(TransportLayer::TCP {
                    src_port: tcp_header.source_port,
                    dst_port: tcp_header.destination_port,
                    seq: tcp_header.sequence_number,
                    ack: tcp_header.acknowledgment_number,
                    flags: tcp::get_tcp_flags(tcp_header.flags),
                    window: tcp_header.window_size,
                    checksum: tcp_header.checksum,
                    urgent_pointer: tcp_header.urgent_pointer,
                });
                // 保存应用层数据
                if !tcp_payload.is_empty() {
                    transport_payload = Some(tcp_payload.to_vec());
                }
            } else if protocol == 17 {
                // UDP
                let (udp_header, udp_payload) = udp::parse_udp_packet(payload)?;
                transport_layer = Some(TransportLayer::UDP {
                    src_port: udp_header.source_port,
                    dst_port: udp_header.destination_port,
                    length: udp_header.length,
                    checksum: udp_header.checksum,
                });
                // 保存应用层数据
                if !udp_payload.is_empty() {
                    transport_payload = Some(udp_payload.to_vec());
                }
            }
        } else if eth_header.ether_type == etherparse::EtherType::IPV6 {
            // IPv6
            let (ipv6_header, ipv6_payload) = ipv6::parse_ipv6_packet(payload)?;
            payload = ipv6_payload;
            let next_header = ipv6_header.next_header;
            network_layer = Some(NetworkLayer::IPv6 {
                src_ip: ipv6_header.source.to_string(),
                dst_ip: ipv6_header.destination.to_string(),
                hop_limit: ipv6_header.hop_limit,
                traffic_class: ipv6_header.traffic_class,
                flow_label: ipv6_header.flow_label,
                payload_length: ipv6_header.payload_length,
            });

            if next_header == 6 {
                // TCP
                let (tcp_header, tcp_payload) = tcp::parse_tcp_packet(payload)?;
                transport_layer = Some(TransportLayer::TCP {
                    src_port: tcp_header.source_port,
                    dst_port: tcp_header.destination_port,
                    seq: tcp_header.sequence_number,
                    ack: tcp_header.acknowledgment_number,
                    flags: tcp::get_tcp_flags(tcp_header.flags),
                    window: tcp_header.window_size,
                    checksum: tcp_header.checksum,
                    urgent_pointer: tcp_header.urgent_pointer,
                });
                // 保存应用层数据
                if !tcp_payload.is_empty() {
                    transport_payload = Some(tcp_payload.to_vec());
                }
            } else if next_header == 17 {
                // UDP
                let (udp_header, udp_payload) = udp::parse_udp_packet(payload)?;
                transport_layer = Some(TransportLayer::UDP {
                    src_port: udp_header.source_port,
                    dst_port: udp_header.destination_port,
                    length: udp_header.length,
                    checksum: udp_header.checksum,
                });
                // 保存应用层数据
                if !udp_payload.is_empty() {
                    transport_payload = Some(udp_payload.to_vec());
                }
            }
        } else if eth_header.ether_type == etherparse::EtherType::ARP {
            // ARP
            let arp_header = arp::parse_arp_packet(payload)?;
            network_layer = Some(NetworkLayer::ARP {
                operation: arp::get_arp_operation_name(arp_header.operation),
                sender_mac: arp::format_arp_mac(&arp_header.sender_hardware_addr),
                sender_ip: arp::format_arp_ip(&arp_header.sender_protocol_addr),
                target_mac: arp::format_arp_mac(&arp_header.target_hardware_addr),
                target_ip: arp::format_arp_ip(&arp_header.target_protocol_addr),
            });
        }

        // 尝试解析应用层协议
        let mut application_layer = None;
        if let Some(app_data) = transport_payload.as_deref() {
            if let Some(transport) = &transport_layer {
                match transport {
                    TransportLayer::TCP { src_port, dst_port, .. } => {
                        if let Ok(Some(app_layer)) = application::parse_application_data(
                            app_data,
                            *src_port,
                            *dst_port,
                            true,
                        ) {
                            application_layer = Some(app_layer);
                        }
                    }
                    TransportLayer::UDP { src_port, dst_port, .. } => {
                        if let Ok(Some(app_layer)) = application::parse_application_data(
                            app_data,
                            *src_port,
                            *dst_port,
                            false,
                        ) {
                            application_layer = Some(app_layer);
                        }
                    }
                    _ => {}
                }
            }
        }

        Ok(ParsedPacket {
            timestamp,
            interface,
            length: data.len(),
            frame_number: self.frame_counter,
            link_layer,
            network_layer,
            transport_layer,
            application_layer,
            session_info: None, // 会话信息由会话追踪器提供
            transport_payload,
            raw_data: data.to_vec(),
        })
    }
}

/// 格式化MAC地址
fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_mac() {
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        assert_eq!(format_mac(&mac), "00:11:22:33:44:55");
    }
}