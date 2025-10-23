//! IPv4协议解析

use anyhow::Result;
use std::net::Ipv4Addr;

/// IPv4头部结构
#[derive(Debug, Clone)]
pub struct Ipv4Header {
    pub version: u8,
    pub ihl: u8,
    pub dscp: u8,
    pub ecn: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
}

/// 解析IPv4数据包
pub fn parse_ipv4_packet(data: &[u8]) -> Result<(Ipv4Header, &[u8])> {
    if data.len() < 20 {
        return Err(anyhow::anyhow!("数据太短，无法解析IPv4头部"));
    }

    let version = (data[0] >> 4) & 0xF;
    if version != 4 {
        return Err(anyhow::anyhow!("不是IPv4数据包"));
    }

    let ihl = data[0] & 0xF;
    let header_len = (ihl as usize) * 4;
    
    if data.len() < header_len {
        return Err(anyhow::anyhow!("IPv4头部长度不足"));
    }

    let dscp = (data[1] >> 2) & 0x3F;
    let ecn = data[1] & 0x03;
    let total_length = u16::from_be_bytes([data[2], data[3]]);
    let identification = u16::from_be_bytes([data[4], data[5]]);
    let flags = (data[6] >> 5) & 0x07;
    let fragment_offset = u16::from_be_bytes([data[6] & 0x1F, data[7]]);
    let ttl = data[8];
    let protocol = data[9];
    let checksum = u16::from_be_bytes([data[10], data[11]]);
    
    let source = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let destination = Ipv4Addr::new(data[16], data[17], data[18], data[19]);

    let header = Ipv4Header {
        version,
        ihl,
        dscp,
        ecn,
        total_length,
        identification,
        flags,
        fragment_offset,
        ttl,
        protocol,
        checksum,
        source,
        destination,
    };

    Ok((header, &data[header_len..]))
}

/// 获取IPv4标志位的字符串表示
pub fn get_ipv4_flags(flags: u8) -> Vec<String> {
    let mut flag_strings = Vec::new();
    
    if flags & 0x04 != 0 {
        flag_strings.push("Reserved".to_string());
    }
    if flags & 0x02 != 0 {
        flag_strings.push("DF".to_string()); // Don't Fragment
    }
    if flags & 0x01 != 0 {
        flag_strings.push("MF".to_string()); // More Fragments
    }
    
    flag_strings
}

/// 获取IP协议类型的字符串表示
pub fn ip_protocol_to_string(protocol: u8) -> String {
    match protocol {
        1 => "ICMP".to_string(),
        2 => "IGMP".to_string(),
        6 => "TCP".to_string(),
        17 => "UDP".to_string(),
        41 => "IPv6".to_string(),
        47 => "GRE".to_string(),
        50 => "ESP".to_string(),
        51 => "AH".to_string(),
        58 => "ICMPv6".to_string(),
        89 => "OSPF".to_string(),
        132 => "SCTP".to_string(),
        _ => format!("Protocol({})", protocol),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_protocol_to_string() {
        assert_eq!(ip_protocol_to_string(6), "TCP");
        assert_eq!(ip_protocol_to_string(17), "UDP");
        assert_eq!(ip_protocol_to_string(1), "ICMP");
        assert_eq!(ip_protocol_to_string(255), "Protocol(255)");
    }

    #[test]
    fn test_get_ipv4_flags() {
        assert_eq!(get_ipv4_flags(0), Vec::<String>::new());
        assert_eq!(get_ipv4_flags(0x02), vec!["DF"]);
        assert_eq!(get_ipv4_flags(0x03), vec!["DF", "MF"]);
    }

    #[test]
    fn test_parse_ipv4_packet() {
        // 创建一个最小的IPv4头部（20字节）
        let mut packet = vec![0u8; 20];
        
        // 版本(4) 和 IHL(5)
        packet[0] = 0x45;
        // TOS
        packet[1] = 0x00;
        // 总长度: 20
        packet[2] = 0x00;
        packet[3] = 0x14;
        // 标识: 0
        packet[4] = 0x00;
        packet[5] = 0x00;
        // 标志和片偏移: DF标志设置
        packet[6] = 0x40;
        packet[7] = 0x00;
        // TTL: 64
        packet[8] = 0x40;
        // 协议: TCP (6)
        packet[9] = 0x06;
        // 校验和
        packet[10] = 0x00;
        packet[11] = 0x00;
        // 源IP: 192.168.1.1
        packet[12..16].copy_from_slice(&[192, 168, 1, 1]);
        // 目标IP: 8.8.8.8
        packet[16..20].copy_from_slice(&[8, 8, 8, 8]);
        
        let result = parse_ipv4_packet(&packet);
        assert!(result.is_ok());
        
        let (header, payload) = result.unwrap();
        assert_eq!(header.version, 4);
        assert_eq!(header.ihl, 5);
        assert_eq!(header.ttl, 64);
        assert_eq!(header.protocol, 6);
        assert_eq!(header.source, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(header.destination, Ipv4Addr::new(8, 8, 8, 8));
        assert_eq!(payload.len(), 0);
    }
}