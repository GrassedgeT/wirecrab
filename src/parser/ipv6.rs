//! IPv6协议解析

use anyhow::Result;
use std::net::Ipv6Addr;

/// IPv6头部结构
#[derive(Debug, Clone)]
pub struct Ipv6Header {
    pub version: u8,
    pub traffic_class: u8,
    pub flow_label: u32,
    pub payload_length: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub source: Ipv6Addr,
    pub destination: Ipv6Addr,
}

/// 解析IPv6数据包
pub fn parse_ipv6_packet(data: &[u8]) -> Result<(Ipv6Header, &[u8])> {
    if data.len() < 40 {
        return Err(anyhow::anyhow!("数据太短，无法解析IPv6头部"));
    }

    // 第一个字节包含版本(4位)和流量类别的高4位
    let version = (data[0] >> 4) & 0xF;
    if version != 6 {
        return Err(anyhow::anyhow!("不是IPv6数据包"));
    }

    // 流量类别(8位): 第一个字节的低4位 + 第二个字节的高4位
    let traffic_class = ((data[0] & 0x0F) << 4) | ((data[1] >> 4) & 0x0F);
    
    // 流标签(20位): 第二个字节的低4位 + 第三、四个字节
    let flow_label = ((data[1] as u32 & 0x0F) << 16) 
        | ((data[2] as u32) << 8) 
        | (data[3] as u32);
    
    // 负载长度(16位)
    let payload_length = u16::from_be_bytes([data[4], data[5]]);
    
    // 下一个头部(8位)
    let next_header = data[6];
    
    // 跳数限制(8位)
    let hop_limit = data[7];
    
    // 源地址(128位)
    let mut src_bytes = [0u8; 16];
    src_bytes.copy_from_slice(&data[8..24]);
    let source = Ipv6Addr::from(src_bytes);
    
    // 目标地址(128位)
    let mut dst_bytes = [0u8; 16];
    dst_bytes.copy_from_slice(&data[24..40]);
    let destination = Ipv6Addr::from(dst_bytes);

    let header = Ipv6Header {
        version,
        traffic_class,
        flow_label,
        payload_length,
        next_header,
        hop_limit,
        source,
        destination,
    };

    // IPv6头部固定为40字节，剩余的是负载
    Ok((header, &data[40..]))
}

/// 获取下一个头部协议类型的字符串表示
pub fn next_header_to_string(next_header: u8) -> String {
    match next_header {
        0 => "Hop-by-Hop Options".to_string(),
        1 => "ICMPv4".to_string(),
        2 => "IGMPv4".to_string(),
        4 => "IPv4".to_string(),
        6 => "TCP".to_string(),
        17 => "UDP".to_string(),
        41 => "IPv6".to_string(),
        43 => "Routing".to_string(),
        44 => "Fragment".to_string(),
        47 => "GRE".to_string(),
        50 => "ESP".to_string(),
        51 => "AH".to_string(),
        58 => "ICMPv6".to_string(),
        59 => "No Next Header".to_string(),
        60 => "Destination Options".to_string(),
        89 => "OSPF".to_string(),
        132 => "SCTP".to_string(),
        135 => "Mobility Header".to_string(),
        _ => format!("Protocol({})", next_header),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_next_header_to_string() {
        assert_eq!(next_header_to_string(6), "TCP");
        assert_eq!(next_header_to_string(17), "UDP");
        assert_eq!(next_header_to_string(58), "ICMPv6");
        assert_eq!(next_header_to_string(255), "Protocol(255)");
    }

    #[test]
    fn test_parse_ipv6_packet() {
        // 创建一个最小的IPv6头部（40字节）
        let mut packet = vec![0u8; 40];
        
        // 版本(6)和流量类别高4位
        packet[0] = 0x60; // 版本6，流量类别0
        // 流量类别低4位和流标签高4位
        packet[1] = 0x00;
        // 流标签中间8位
        packet[2] = 0x00;
        // 流标签低8位
        packet[3] = 0x00;
        // 负载长度: 0
        packet[4] = 0x00;
        packet[5] = 0x00;
        // 下一个头部: TCP (6)
        packet[6] = 0x06;
        // 跳数限制: 64
        packet[7] = 0x40;
        // 源地址: 2001:db8::1
        packet[8..10].copy_from_slice(&[0x20, 0x01]);
        packet[10..12].copy_from_slice(&[0x0d, 0xb8]);
        packet[12..20].copy_from_slice(&[0x00; 8]);
        packet[22] = 0x00;
        packet[23] = 0x01;
        // 目标地址: 2001:db8::2
        packet[24..26].copy_from_slice(&[0x20, 0x01]);
        packet[26..28].copy_from_slice(&[0x0d, 0xb8]);
        packet[28..36].copy_from_slice(&[0x00; 8]);
        packet[38] = 0x00;
        packet[39] = 0x02;
        
        let result = parse_ipv6_packet(&packet);
        assert!(result.is_ok());
        
        let (header, payload) = result.unwrap();
        assert_eq!(header.version, 6);
        assert_eq!(header.traffic_class, 0);
        assert_eq!(header.flow_label, 0);
        assert_eq!(header.payload_length, 0);
        assert_eq!(header.next_header, 6);
        assert_eq!(header.hop_limit, 64);
        assert_eq!(header.source.to_string(), "2001:db8::1");
        assert_eq!(header.destination.to_string(), "2001:db8::2");
        assert_eq!(payload.len(), 0);
    }

    #[test]
    fn test_parse_ipv6_packet_too_short() {
        let packet = vec![0u8; 39]; // 少于40字节
        let result = parse_ipv6_packet(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_ipv6_packet_wrong_version() {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x40; // 版本4
        let result = parse_ipv6_packet(&packet);
        assert!(result.is_err());
    }
}