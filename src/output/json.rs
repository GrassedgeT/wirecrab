//! JSON格式输出

use anyhow::Result;
use serde_json;
use crate::parser::ParsedPacket;
use super::OutputFormatter;

/// JSON格式化器
pub struct JsonFormatter {
    pretty: bool,
}

impl JsonFormatter {
    /// 创建新的JSON格式化器
    pub fn new() -> Self {
        Self { pretty: true }
    }

    /// 设置是否美化输出
    pub fn with_pretty(mut self, pretty: bool) -> Self {
        self.pretty = pretty;
        self
    }
}

impl OutputFormatter for JsonFormatter {
    fn format_packet(&self, packet: &ParsedPacket) -> Result<String> {
        if self.pretty {
            Ok(serde_json::to_string_pretty(packet)?)
        } else {
            Ok(serde_json::to_string(packet)?)
        }
    }

    fn format_batch(&self, packets: &[ParsedPacket]) -> Result<String> {
        // 对于JSON，我们可以输出为数组
        if self.pretty {
            Ok(serde_json::to_string_pretty(packets)?)
        } else {
            Ok(serde_json::to_string(packets)?)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{LinkLayer, NetworkLayer, TransportLayer};

    fn create_test_packet() -> ParsedPacket {
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
                flags: vec!["DF".to_string()],
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

    #[test]
    fn test_format_packet() {
        let formatter = JsonFormatter::new();
        let packet = create_test_packet();
        
        let result = formatter.format_packet(&packet);
        assert!(result.is_ok());
        
        let json_str = result.unwrap();
        assert!(json_str.contains("\"timestamp\""));
        assert!(json_str.contains("\"interface\""));
        assert!(json_str.contains("\"IPv4\""));
        assert!(json_str.contains("\"TCP\""));
    }

    #[test]
    fn test_format_batch() {
        let formatter = JsonFormatter::new();
        let packets = vec![create_test_packet(), create_test_packet()];
        
        let result = formatter.format_batch(&packets);
        assert!(result.is_ok());
        
        let json_str = result.unwrap();
        // 应该是一个数组
        assert!(json_str.starts_with('['));
        assert!(json_str.ends_with(']'));
    }

    #[test]
    fn test_compact_format() {
        let formatter = JsonFormatter::new().with_pretty(false);
        let packet = create_test_packet();
        
        let result = formatter.format_packet(&packet);
        assert!(result.is_ok());
        
        let json_str = result.unwrap();
        // 紧凑格式不应该包含多余的空格和换行
        assert!(!json_str.contains("\n"));
    }
}