//! ARP协议解析器 (手动实现)

use anyhow::Result;
use std::net::Ipv4Addr;

/// ARP头部结构
#[derive(Debug, Clone)]
pub struct ArpHeader {
    pub hardware_type: u16,
    pub protocol_type: u16,
    pub hardware_len: u8,
    pub protocol_len: u8,
    pub operation: u16,
    pub sender_hardware_addr: [u8; 6],
    pub sender_protocol_addr: [u8; 4],
    pub target_hardware_addr: [u8; 6],
    pub target_protocol_addr: [u8; 4],
}

/// 解析ARP数据包
pub fn parse_arp_packet(data: &[u8]) -> Result<ArpHeader> {
    if data.len() < 28 {
        return Err(anyhow::anyhow!("数据太短，无法解析ARP头部 (需要28字节)"));
    }

    let header = ArpHeader {
        hardware_type: u16::from_be_bytes([data[0], data[1]]),
        protocol_type: u16::from_be_bytes([data[2], data[3]]),
        hardware_len: data[4],
        protocol_len: data[5],
        operation: u16::from_be_bytes([data[6], data[7]]),
        sender_hardware_addr: [data[8], data[9], data[10], data[11], data[12], data[13]],
        sender_protocol_addr: [data[14], data[15], data[16], data[17]],
        target_hardware_addr: [data[18], data[19], data[20], data[21], data[22], data[23]],
        target_protocol_addr: [data[24], data[25], data[26], data[27]],
    };

    Ok(header)
}

/// 获取ARP操作名称
pub fn get_arp_operation_name(op_code: u16) -> String {
    match op_code {
        1 => "Request".to_string(),
        2 => "Reply".to_string(),
        _ => format!("Unknown ({})", op_code),
    }
}

/// 格式化ARP协议中的IP地址
pub fn format_arp_ip(addr: &[u8; 4]) -> String {
    Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]).to_string()
}

/// 格式化ARP协议中的MAC地址
pub fn format_arp_mac(addr: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]
    )
}