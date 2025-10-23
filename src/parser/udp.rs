//! UDP协议解析

use anyhow::Result;

/// UDP头部结构
#[derive(Debug, Clone)]
pub struct UdpHeader {
    pub source_port: u16,
    pub destination_port: u16,
    pub length: u16,
    pub checksum: u16,
}

/// 解析UDP数据包
pub fn parse_udp_packet(data: &[u8]) -> Result<(UdpHeader, &[u8])> {
    if data.len() < 8 {
        return Err(anyhow::anyhow!("数据太短，无法解析UDP头部"));
    }

    let source_port = u16::from_be_bytes([data[0], data[1]]);
    let destination_port = u16::from_be_bytes([data[2], data[3]]);
    let length = u16::from_be_bytes([data[4], data[5]]);
    let checksum = u16::from_be_bytes([data[6], data[7]]);

    // UDP头部固定8字节
    let header = UdpHeader {
        source_port,
        destination_port,
        length,
        checksum,
    };

    Ok((header, &data[8..]))
}

/// 判断是否是已知的UDP端口
pub fn get_udp_service(port: u16) -> Option<&'static str> {
    match port {
        53 => Some("DNS"),
        67 => Some("DHCP-Server"),
        68 => Some("DHCP-Client"),
        69 => Some("TFTP"),
        123 => Some("NTP"),
        137 => Some("NetBIOS-NS"),
        138 => Some("NetBIOS-DGM"),
        161 => Some("SNMP"),
        162 => Some("SNMP-Trap"),
        443 => Some("QUIC/HTTP3"),
        500 => Some("IKE"),
        514 => Some("Syslog"),
        520 => Some("RIP"),
        1194 => Some("OpenVPN"),
        1701 => Some("L2TP"),
        1900 => Some("SSDP"),
        4500 => Some("IPSec-NAT"),
        5060 => Some("SIP"),
        5353 => Some("mDNS"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_udp_service() {
        assert_eq!(get_udp_service(53), Some("DNS"));
        assert_eq!(get_udp_service(123), Some("NTP"));
        assert_eq!(get_udp_service(443), Some("QUIC/HTTP3"));
        assert_eq!(get_udp_service(12345), None);
    }

    #[test]
    fn test_parse_udp_packet() {
        // 创建一个UDP头部（8字节）+ 一些数据
        let mut packet = vec![0u8; 16];
        
        // 源端口: 12345
        packet[0] = 0x30;
        packet[1] = 0x39;
        // 目标端口: 53 (DNS)
        packet[2] = 0x00;
        packet[3] = 0x35;
        // 长度: 16 (头部8字节 + 8字节数据)
        packet[4] = 0x00;
        packet[5] = 0x10;
        // 校验和: 0x1234
        packet[6] = 0x12;
        packet[7] = 0x34;
        // 添加一些测试数据
        packet[8..16].copy_from_slice(b"testdata");
        
        let result = parse_udp_packet(&packet);
        assert!(result.is_ok());
        
        let (header, payload) = result.unwrap();
        assert_eq!(header.source_port, 12345);
        assert_eq!(header.destination_port, 53);
        assert_eq!(header.length, 16);
        assert_eq!(header.checksum, 0x1234);
        assert_eq!(payload, b"testdata");
    }
}