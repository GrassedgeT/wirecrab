//! TCP协议解析

use anyhow::Result;

/// TCP头部结构
#[derive(Debug, Clone)]
pub struct TcpHeader {
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence_number: u32,
    pub acknowledgment_number: u32,
    pub data_offset: u8,
    pub flags: u16,
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
}

/// 解析TCP数据包
pub fn parse_tcp_packet(data: &[u8]) -> Result<(TcpHeader, &[u8])> {
    if data.len() < 20 {
        return Err(anyhow::anyhow!("数据太短，无法解析TCP头部"));
    }

    let source_port = u16::from_be_bytes([data[0], data[1]]);
    let destination_port = u16::from_be_bytes([data[2], data[3]]);
    let sequence_number = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let acknowledgment_number = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    
    let data_offset = (data[12] >> 4) & 0xF;
    let header_len = (data_offset as usize) * 4;
    
    if data.len() < header_len {
        return Err(anyhow::anyhow!("TCP头部长度不足"));
    }

    // 标志位
    let flags = u16::from_be_bytes([data[12] & 0x01, data[13]]);
    
    let window_size = u16::from_be_bytes([data[14], data[15]]);
    let checksum = u16::from_be_bytes([data[16], data[17]]);
    let urgent_pointer = u16::from_be_bytes([data[18], data[19]]);

    let header = TcpHeader {
        source_port,
        destination_port,
        sequence_number,
        acknowledgment_number,
        data_offset,
        flags,
        window_size,
        checksum,
        urgent_pointer,
    };

    Ok((header, &data[header_len..]))
}

/// 获取TCP标志位的字符串表示
pub fn get_tcp_flags(flags: u16) -> Vec<String> {
    let mut flag_strings = Vec::new();
    
    if flags & 0x100 != 0 {
        flag_strings.push("NS".to_string());  // ECN-nonce
    }
    if flags & 0x080 != 0 {
        flag_strings.push("CWR".to_string()); // Congestion Window Reduced
    }
    if flags & 0x040 != 0 {
        flag_strings.push("ECE".to_string()); // ECN-Echo
    }
    if flags & 0x020 != 0 {
        flag_strings.push("URG".to_string()); // Urgent
    }
    if flags & 0x010 != 0 {
        flag_strings.push("ACK".to_string()); // Acknowledgment
    }
    if flags & 0x008 != 0 {
        flag_strings.push("PSH".to_string()); // Push
    }
    if flags & 0x004 != 0 {
        flag_strings.push("RST".to_string()); // Reset
    }
    if flags & 0x002 != 0 {
        flag_strings.push("SYN".to_string()); // Synchronize
    }
    if flags & 0x001 != 0 {
        flag_strings.push("FIN".to_string()); // Finish
    }
    
    flag_strings
}

/// 判断是否是已知的TCP端口
pub fn get_tcp_service(port: u16) -> Option<&'static str> {
    match port {
        20 => Some("FTP-DATA"),
        21 => Some("FTP"),
        22 => Some("SSH"),
        23 => Some("Telnet"),
        25 => Some("SMTP"),
        53 => Some("DNS"),
        80 => Some("HTTP"),
        110 => Some("POP3"),
        143 => Some("IMAP"),
        443 => Some("HTTPS"),
        445 => Some("SMB"),
        993 => Some("IMAPS"),
        995 => Some("POP3S"),
        1433 => Some("MSSQL"),
        3306 => Some("MySQL"),
        3389 => Some("RDP"),
        5432 => Some("PostgreSQL"),
        5900 => Some("VNC"),
        8080 => Some("HTTP-Proxy"),
        8443 => Some("HTTPS-Alt"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_tcp_flags() {
        assert_eq!(get_tcp_flags(0x002), vec!["SYN"]);
        assert_eq!(get_tcp_flags(0x012), vec!["ACK", "SYN"]);
        assert_eq!(get_tcp_flags(0x011), vec!["ACK", "FIN"]);
        assert_eq!(get_tcp_flags(0x018), vec!["ACK", "PSH"]);
    }

    #[test]
    fn test_get_tcp_service() {
        assert_eq!(get_tcp_service(80), Some("HTTP"));
        assert_eq!(get_tcp_service(443), Some("HTTPS"));
        assert_eq!(get_tcp_service(22), Some("SSH"));
        assert_eq!(get_tcp_service(12345), None);
    }

    #[test]
    fn test_parse_tcp_packet() {
        // 创建一个最小的TCP头部（20字节）
        let mut packet = vec![0u8; 20];
        
        // 源端口: 54321
        packet[0] = 0xD4;
        packet[1] = 0x31;
        // 目标端口: 443 (HTTPS)
        packet[2] = 0x01;
        packet[3] = 0xBB;
        // 序列号: 1234567890
        packet[4..8].copy_from_slice(&1234567890u32.to_be_bytes());
        // 确认号: 0
        packet[8..12].copy_from_slice(&0u32.to_be_bytes());
        // 数据偏移(5) 和 标志(SYN)
        packet[12] = 0x50;
        packet[13] = 0x02;
        // 窗口大小: 65535
        packet[14] = 0xFF;
        packet[15] = 0xFF;
        
        let result = parse_tcp_packet(&packet);
        assert!(result.is_ok());
        
        let (header, payload) = result.unwrap();
        assert_eq!(header.source_port, 54321);
        assert_eq!(header.destination_port, 443);
        assert_eq!(header.sequence_number, 1234567890);
        assert_eq!(header.data_offset, 5);
        assert_eq!(payload.len(), 0);
    }
}