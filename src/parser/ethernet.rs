//! 以太网帧解析

use anyhow::Result;
use etherparse::{Ethernet2Header, EtherType};

/// 解析以太网帧
pub fn parse_ethernet_frame(data: &[u8]) -> Result<(Ethernet2Header, &[u8])> {
    if data.len() < 14 {
        return Err(anyhow::anyhow!("数据太短，无法解析以太网帧"));
    }

    // 手动解析以太网头部
    let mut dst_mac = [0u8; 6];
    let mut src_mac = [0u8; 6];
    
    dst_mac.copy_from_slice(&data[0..6]);
    src_mac.copy_from_slice(&data[6..12]);
    
    let ether_type = u16::from_be_bytes([data[12], data[13]]);
    
    let header = Ethernet2Header {
        destination: dst_mac,
        source: src_mac,
        ether_type: EtherType(ether_type),
    };
    
    Ok((header, &data[14..]))
}

/// 获取以太网类型的字符串表示
pub fn ether_type_to_string(ether_type: u16) -> String {
    match ether_type {
        0x0800 => "IPv4".to_string(),
        0x86DD => "IPv6".to_string(),
        0x0806 => "ARP".to_string(),
        0x8100 => "VLAN".to_string(),
        0x88CC => "LLDP".to_string(),
        _ => format!("0x{:04X}", ether_type),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ether_type_to_string() {
        assert_eq!(ether_type_to_string(0x0800), "IPv4");
        assert_eq!(ether_type_to_string(0x86DD), "IPv6");
        assert_eq!(ether_type_to_string(0x0806), "ARP");
        assert_eq!(ether_type_to_string(0x1234), "0x1234");
    }

    #[test]
    fn test_parse_ethernet_frame() {
        // 创建一个测试以太网帧
        let mut frame = vec![0u8; 64];
        
        // 目标MAC: AA:BB:CC:DD:EE:FF
        frame[0..6].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        // 源MAC: 11:22:33:44:55:66
        frame[6..12].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        // 类型: IPv4 (0x0800)
        frame[12..14].copy_from_slice(&[0x08, 0x00]);
        
        let result = parse_ethernet_frame(&frame);
        assert!(result.is_ok());
        
        let (header, _payload) = result.unwrap();
        assert_eq!(header.destination, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        assert_eq!(header.source, [0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        assert_eq!(header.ether_type, EtherType(0x0800));
    }
}