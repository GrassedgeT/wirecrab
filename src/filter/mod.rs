//! 数据包过滤模块

use crate::parser::{ParsedPacket, NetworkLayer, TransportLayer};

pub mod rules;

pub use rules::FilterRules;

/// 数据包过滤器
pub struct PacketFilter {
    rules: FilterRules,
}

impl PacketFilter {
    /// 创建新的过滤器
    pub fn new(rules: FilterRules) -> Self {
        Self { rules }
    }

    /// 检查数据包是否匹配过滤规则
    pub fn matches(&self, packet: &ParsedPacket) -> bool {
        // 如果没有设置任何过滤规则，则匹配所有数据包
        if self.rules.is_empty() {
            return true;
        }

        // 检查协议过滤
        if let Some(protocol) = &self.rules.protocol {
            if !self.matches_protocol(packet, protocol) {
                return false;
            }
        }

        // 检查IP地址过滤
        if !self.matches_ip_addresses(packet) {
            return false;
        }

        // 检查端口过滤
        if !self.matches_ports(packet) {
            return false;
        }

        true
    }

    /// 检查协议匹配
    fn matches_protocol(&self, packet: &ParsedPacket, protocol: &str) -> bool {
        match protocol.to_lowercase().as_str() {
            "tcp" => matches!(&packet.transport_layer, Some(TransportLayer::TCP { .. })),
            "udp" => matches!(&packet.transport_layer, Some(TransportLayer::UDP { .. })),
            "icmp" => matches!(&packet.transport_layer, Some(TransportLayer::ICMP { .. })),
            "arp" => matches!(&packet.network_layer, Some(NetworkLayer::ARP { .. })),
            _ => false,
        }
    }

    /// 检查IP地址匹配
    fn matches_ip_addresses(&self, packet: &ParsedPacket) -> bool {
        if self.rules.src_ip.is_none() && self.rules.dst_ip.is_none() {
            return true;
        }

        match &packet.network_layer {
            Some(NetworkLayer::IPv4 { src_ip, dst_ip, .. }) => {
                if let Some(filter_src) = &self.rules.src_ip {
                    if filter_src.to_string() != *src_ip {
                        return false;
                    }
                }
                if let Some(filter_dst) = &self.rules.dst_ip {
                    if filter_dst.to_string() != *dst_ip {
                        return false;
                    }
                }
                true
            }
            Some(NetworkLayer::IPv6 { src_ip, dst_ip, .. }) => {
                if let Some(filter_src) = &self.rules.src_ip {
                    if filter_src.to_string() != *src_ip {
                        return false;
                    }
                }
                if let Some(filter_dst) = &self.rules.dst_ip {
                    if filter_dst.to_string() != *dst_ip {
                        return false;
                    }
                }
                true
            }
            _ => false,
        }
    }

    /// 检查端口匹配
    fn matches_ports(&self, packet: &ParsedPacket) -> bool {
        // 如果没有端口过滤规则，则匹配
        if self.rules.src_port.is_none() && 
           self.rules.dst_port.is_none() && 
           self.rules.port.is_none() {
            return true;
        }

        match &packet.transport_layer {
            Some(TransportLayer::TCP { src_port, dst_port, .. }) |
            Some(TransportLayer::UDP { src_port, dst_port, .. }) => {
                // 检查源端口
                if let Some(filter_src_port) = self.rules.src_port {
                    if *src_port != filter_src_port {
                        return false;
                    }
                }
                
                // 检查目标端口
                if let Some(filter_dst_port) = self.rules.dst_port {
                    if *dst_port != filter_dst_port {
                        return false;
                    }
                }
                
                // 检查任意端口（源或目标）
                if let Some(filter_port) = self.rules.port {
                    if *src_port != filter_port && *dst_port != filter_port {
                        return false;
                    }
                }
                
                true
            }
            _ => {
                // 如果设置了端口过滤但数据包不是TCP/UDP，则不匹配
                false
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
            timestamp: "2024-01-01T00:00:00Z".to_string(),
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
        }
    }

    #[test]
    fn test_empty_filter_matches_all() {
        let rules = FilterRules::new();
        let filter = PacketFilter::new(rules);
        let packet = create_test_tcp_packet();
        
        assert!(filter.matches(&packet));
    }

    #[test]
    fn test_protocol_filter() {
        let mut rules = FilterRules::new();
        rules.protocol = Some("tcp".to_string());
        let filter = PacketFilter::new(rules);
        let packet = create_test_tcp_packet();
        
        assert!(filter.matches(&packet));
        
        // 测试不匹配的协议
        let mut rules = FilterRules::new();
        rules.protocol = Some("udp".to_string());
        let filter = PacketFilter::new(rules);
        assert!(!filter.matches(&packet));
    }

    #[test]
    fn test_port_filter() {
        // 测试目标端口过滤
        let mut rules = FilterRules::new();
        rules.dst_port = Some(443);
        let filter = PacketFilter::new(rules);
        let packet = create_test_tcp_packet();
        
        assert!(filter.matches(&packet));
        
        // 测试任意端口过滤
        let mut rules = FilterRules::new();
        rules.port = Some(54321);
        let filter = PacketFilter::new(rules);
        assert!(filter.matches(&packet));
    }
}