//! 数据包过滤模块

use crate::parser::{ParsedPacket, NetworkLayer, TransportLayer, application::ApplicationLayer};
use std::net::IpAddr;

/// 数据包过滤器
pub struct PacketFilter {
    protocol: Option<String>,
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    port: Option<u16>,
}

impl PacketFilter {
    /// 创建新的过滤器
    pub fn new(
        protocol: Option<String>,
        src_ip: Option<IpAddr>,
        dst_ip: Option<IpAddr>,
        src_port: Option<u16>,
        dst_port: Option<u16>,
        port: Option<u16>,
    ) -> Self {
        Self {
            protocol,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            port,
        }
    }

    /// 检查数据包是否匹配过滤规则
    pub fn matches(&self, packet: &ParsedPacket) -> bool {
        // 每个条件必须满足，或者相应的过滤器未设置。
        let protocol_ok = self.protocol.as_ref().map_or(true, |p| self.matches_protocol(packet, p));
        let ip_ok = self.matches_ip_addresses(packet);
        let port_ok = self.matches_ports(packet);

        protocol_ok && ip_ok && port_ok
    }

    /// 检查协议匹配
    fn matches_protocol(&self, packet: &ParsedPacket, protocol: &str) -> bool {
        match protocol.to_lowercase().as_str() {

            // 传输层协议
            "tcp" => return matches!(&packet.transport_layer, Some(TransportLayer::TCP { .. })),
            "udp" => return matches!(&packet.transport_layer, Some(TransportLayer::UDP { .. })),
            "icmp" => return matches!(&packet.transport_layer, Some(TransportLayer::ICMP { .. })),
            
            // 网络层协议
            "arp" => return matches!(&packet.network_layer, Some(NetworkLayer::ARP { .. })),
            "ipv4" => return matches!(&packet.network_layer, Some(NetworkLayer::IPv4 { .. })),
            "ipv6" => return matches!(&packet.network_layer, Some(NetworkLayer::IPv6 { .. })),
            // 应用层协议
            "http" => return matches!(&packet.application_layer, Some(ApplicationLayer::HTTP { .. })),
            "dns" => return matches!(&packet.application_layer, Some(ApplicationLayer::DNS { .. })),
            "ftp" => return matches!(&packet.application_layer, Some(ApplicationLayer::FTP { .. })),
            "tls" | "https" => return matches!(&packet.application_layer, Some(ApplicationLayer::TLS { .. })),
            
            _ => {}
        }
        false
    }

    /// 检查IP地址匹配
    fn matches_ip_addresses(&self, packet: &ParsedPacket) -> bool {
        if self.src_ip.is_none() && self.dst_ip.is_none() {
            return true;
        }

        match &packet.network_layer {
            Some(NetworkLayer::IPv4 { src_ip, dst_ip, .. }) => {
                if let Some(filter_src) = &self.src_ip {
                    if filter_src.to_string() != *src_ip {
                        return false;
                    }
                }
                if let Some(filter_dst) = &self.dst_ip {
                    if filter_dst.to_string() != *dst_ip {
                        return false;
                    }
                }
                true
            }
            Some(NetworkLayer::IPv6 { src_ip, dst_ip, .. }) => {
                if let Some(filter_src) = &self.src_ip {
                    if filter_src.to_string() != *src_ip {
                        return false;
                    }
                }
                if let Some(filter_dst) = &self.dst_ip {
                    if filter_dst.to_string() != *dst_ip {
                        return false;
                    }
                }
                true
            }
            Some(NetworkLayer::ARP { sender_ip, target_ip, .. }) => {
                if let Some(filter_src) = &self.src_ip {
                    if filter_src.to_string() != *sender_ip {
                        return false;
                    }
                }
                if let Some(filter_dst) = &self.dst_ip {
                    if filter_dst.to_string() != *target_ip {
                        return false;
                    }
                }
                true
            }
            _ => {
                // 如果设置了IP过滤但不是IP或ARP数据包，则不匹配
                self.src_ip.is_none() && self.dst_ip.is_none()
            }
        }
    }

    /// 检查端口匹配
    fn matches_ports(&self, packet: &ParsedPacket) -> bool {
        // 如果没有端口过滤规则，则匹配
        if self.src_port.is_none() &&
           self.dst_port.is_none() &&
           self.port.is_none() {
            return true;
        }

        match &packet.transport_layer {
            Some(TransportLayer::TCP { src_port, dst_port, .. }) |
            Some(TransportLayer::UDP { src_port, dst_port, .. }) => {
                // 检查源端口
                if let Some(filter_src_port) = self.src_port {
                    if *src_port != filter_src_port {
                        return false;
                    }
                }
                
                // 检查目标端口
                if let Some(filter_dst_port) = self.dst_port {
                    if *dst_port != filter_dst_port {
                        return false;
                    }
                }
                
                // 检查任意端口（源或目标）
                if let Some(filter_port) = self.port {
                    if *src_port != filter_port && *dst_port != filter_port {
                        return false;
                    }
                }
                
                true
            }
            _ => {
                // 如果设置了端口过滤但数据包不是TCP/UDP，则不匹配
                // 对于ARP等没有端口的协议，如果设置了端口过滤，则不匹配
                self.src_port.is_none() && self.dst_port.is_none() && self.port.is_none()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{LinkLayer, NetworkLayer, TransportLayer};

    fn create_test_tcp_packet() -> ParsedPacket {
        ParsedPacket {
            timestamp: chrono::Utc::now(),
            interface: "eth0".to_string(),
            length: 100,
            frame_number: 1,
            link_layer: LinkLayer {
                protocol: "Ethernet".to_string(),
                src_mac: Some("00:11:22:33:44:55".to_string()),
                dst_mac: Some("66:77:88:99:AA:BB".to_string()),
            },
            network_layer: Some(NetworkLayer::IPv4 {
                src_ip: "192.168.1.100".to_string(),
                dst_ip: "8.8.8.8".to_string(),
                ttl: 64,
                id: 12345,
                flags: vec![],
                fragment_offset: 0,
                total_length: 60,
            }),
            transport_layer: Some(TransportLayer::TCP {
                src_port: 54321,
                dst_port: 443,
                seq: 1234567890,
                ack: 0,
                flags: vec!["SYN".to_string()],
                window: 65535,
                checksum: 0,
                urgent_pointer: 0,
            }),
            application_layer: None,
            session_info: None,
            transport_payload: None,
            raw_data: vec![],
        }
    }

    fn create_test_ipv6_packet() -> ParsedPacket {
        ParsedPacket {
            timestamp: chrono::Utc::now(),
            interface: "eth0".to_string(),
            length: 100,
            frame_number: 2,
            link_layer: LinkLayer {
                protocol: "Ethernet".to_string(),
                src_mac: Some("00:11:22:33:44:55".to_string()),
                dst_mac: Some("66:77:88:99:AA:BB".to_string()),
            },
            network_layer: Some(NetworkLayer::IPv6 {
                src_ip: "2001:db8::1".to_string(),
                dst_ip: "2001:db8::2".to_string(),
                hop_limit: 64,
                traffic_class: 0,
                flow_label: 0,
                payload_length: 20,
            }),
            transport_layer: Some(TransportLayer::UDP {
                src_port: 12345,
                dst_port: 80,
                length: 20,
                checksum: 0,
            }),
            application_layer: None,
            session_info: None,
            transport_payload: None,
            raw_data: vec![],
        }
    }

    #[test]
    fn test_empty_filter_matches_all() {
        let filter = PacketFilter::new(None, None, None, None, None, None);
        let packet = create_test_tcp_packet();
        
        assert!(filter.matches(&packet));
    }

    #[test]
    fn test_protocol_filter() {
        let filter = PacketFilter::new(Some("tcp".to_string()), None, None, None, None, None);
        let packet = create_test_tcp_packet();
        
        assert!(filter.matches(&packet));
        
        // 测试不匹配的协议
        let filter = PacketFilter::new(Some("udp".to_string()), None, None, None, None, None);
        assert!(!filter.matches(&packet));
    }

    #[test]
    fn test_port_filter() {
        // 测试目标端口过滤
        let filter = PacketFilter::new(None, None, None, None, Some(443), None);
        let packet = create_test_tcp_packet();
        
        assert!(filter.matches(&packet));
        
        // 测试任意端口过滤
        let filter = PacketFilter::new(None, None, None, None, None, Some(54321));
        assert!(filter.matches(&packet));
    }

    #[test]
    fn test_ipv6_filter() {
        use std::net::IpAddr;
        use std::str::FromStr;

        let packet = create_test_ipv6_packet();
        
        // 测试IPv6源地址过滤
        let filter = PacketFilter::new(None, Some(IpAddr::from_str("2001:db8::1").unwrap()), None, None, None, None);
        assert!(filter.matches(&packet));
        
        // 测试IPv6目标地址过滤
        let filter = PacketFilter::new(None, None, Some(IpAddr::from_str("2001:db8::2").unwrap()), None, None, None);
        assert!(filter.matches(&packet));
        
        // 测试不匹配的IPv6地址
        let filter = PacketFilter::new(None, Some(IpAddr::from_str("2001:db8::3").unwrap()), None, None, None, None);
        assert!(!filter.matches(&packet));
    }

    #[test]
    fn test_mixed_ip_filter() {
        use std::net::IpAddr;
        use std::str::FromStr;
        
        // 测试IPv4过滤器不会匹配IPv6数据包
        let filter = PacketFilter::new(None, Some(IpAddr::from_str("192.168.1.1").unwrap()), None, None, None, None);
        let ipv6_packet = create_test_ipv6_packet();
        assert!(!filter.matches(&ipv6_packet));
        
        // 测试IPv6过滤器不会匹配IPv4数据包
        let filter = PacketFilter::new(None, Some(IpAddr::from_str("2001:db8::1").unwrap()), None, None, None, None);
        let ipv4_packet = create_test_tcp_packet();
        assert!(!filter.matches(&ipv4_packet));
    }

    #[test]
    fn test_app_layer_filter() {
        let mut packet = create_test_tcp_packet();
        packet.application_layer = Some(ApplicationLayer::HTTP {
            method: Some("GET".to_string()),
            uri: Some("/".to_string()),
            version: "HTTP/1.1".to_string(),
            status_code: None,
            headers: Default::default(),
            body_preview: None,
        });

        // 测试匹配HTTP
        let filter = PacketFilter::new(Some("http".to_string()), None, None, None, None, None);
        assert!(filter.matches(&packet));

        // 测试不匹配DNS
        let filter = PacketFilter::new(Some("dns".to_string()), None, None, None, None, None);
        assert!(!filter.matches(&packet));
    }
}