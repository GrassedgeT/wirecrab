//! TLS/SSL 协议解析模块 (主要用于提取SNI)

use super::ApplicationLayer;
use anyhow::{bail, Result};

// 参考: https://tls12.xargs.org/
// Record Type: Handshake (22)
const TLS_HANDSHAKE: u8 = 22;
// Handshake Type: Client Hello (1)
const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 1;
// Extension Type: server_name (0)
const EXTENSION_SERVER_NAME: u16 = 0;

/// 解析TLS Client Hello并提取SNI
pub fn parse_tls_client_hello(data: &[u8]) -> Result<ApplicationLayer> {
    // 1. 解析记录层头部 (5 bytes)
    if data.len() < 5 {
        bail!("TLS记录太短");
    }
    let record_type = data[0];
    let _record_version = u16::from_be_bytes([data[1], data[2]]);
    let record_length = u16::from_be_bytes([data[3], data[4]]) as usize;

    if record_type != TLS_HANDSHAKE {
        bail!("不是TLS握手协议");
    }
    if data.len() < 5 + record_length {
        bail!("TLS记录长度不足");
    }

    let handshake_data = &data[5..5 + record_length];

    // 2. 解析握手协议头部 (4 bytes)
    if handshake_data.len() < 4 {
        bail!("TLS握手数据太短");
    }
    let handshake_type = handshake_data[0];
    if handshake_type != HANDSHAKE_TYPE_CLIENT_HELLO {
        bail!("不是Client Hello消息");
    }

    // Client Hello 消息体
    // 我们需要跳过很多字段来找到扩展部分
    let mut offset = 4; // 跳过握手类型和长度
    offset += 2; // 跳过版本
    offset += 32; // 跳过随机数
    if offset >= handshake_data.len() { bail!("Client Hello太短 (1)"); }

    // 跳过 Session ID
    let session_id_len = handshake_data[offset] as usize;
    offset += 1 + session_id_len;
    if offset >= handshake_data.len() { bail!("Client Hello太短 (2)"); }

    // 跳过 Cipher Suites
    let cipher_suites_len = u16::from_be_bytes([handshake_data[offset], handshake_data[offset + 1]]) as usize;
    offset += 2 + cipher_suites_len;
    if offset >= handshake_data.len() { bail!("Client Hello太短 (3)"); }

    // 跳过 Compression Methods
    let comp_methods_len = handshake_data[offset] as usize;
    offset += 1 + comp_methods_len;
    if offset >= handshake_data.len() {
        // 没有扩展部分
        bail!("Client Hello中没有扩展");
    }

    // 3. 解析扩展
    let extensions_len = u16::from_be_bytes([handshake_data[offset], handshake_data[offset + 1]]) as usize;
    offset += 2;
    if handshake_data.len() < offset + extensions_len {
        bail!("扩展长度不足");
    }

    let extensions_data = &handshake_data[offset..offset + extensions_len];
    let mut ext_offset = 0;
    while ext_offset < extensions_data.len() {
        let ext_type = u16::from_be_bytes([extensions_data[ext_offset], extensions_data[ext_offset + 1]]);
        let ext_len = u16::from_be_bytes([extensions_data[ext_offset + 2], extensions_data[ext_offset + 3]]) as usize;
        ext_offset += 4;

        if ext_type == EXTENSION_SERVER_NAME {
            // 找到了SNI扩展!
            let sni_data = &extensions_data[ext_offset..ext_offset + ext_len];
            if sni_data.len() < 2 { bail!("SNI扩展格式错误 (1)"); }
            
            let list_len = u16::from_be_bytes([sni_data[0], sni_data[1]]) as usize;
            if sni_data.len() < 2 + list_len { bail!("SNI扩展格式错误 (2)"); }

            // 通常只有一个name
            if sni_data.len() < 5 { bail!("SNI扩展格式错误 (3)"); }
            let name_type = sni_data[2];
            if name_type == 0 { // 0 = host_name
                let name_len = u16::from_be_bytes([sni_data[3], sni_data[4]]) as usize;
                if sni_data.len() < 5 + name_len { bail!("SNI扩展格式错误 (4)"); }
                
                let host_name = std::str::from_utf8(&sni_data[5..5 + name_len])?;
                return Ok(ApplicationLayer::TLS {
                    sni_hostname: Some(host_name.to_string()),
                });
            }
        }

        ext_offset += ext_len;
    }

    bail!("在Client Hello中未找到SNI");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_tls_client_hello_with_sni() {
        // 一个简化的TLS Client Hello报文，包含SNI "example.com"
        let client_hello = vec![
            // Record Header
            0x16, // Handshake
            0x03, 0x01, // Version TLS 1.0
            0x00, 0x51, // Length
            // Handshake Header
            0x01, // Client Hello
            0x00, 0x00, 0x4d, // Length
            // Client Hello Body
            0x03, 0x03, // Version TLS 1.2
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, // Random
            0x00, // Session ID Length
            0x00, 0x02, // Cipher Suites Length
            0xc0, 0x2b, // Cipher Suite
            0x01, // Compression Methods Length
            0x00, // Compression Method
            0x00, 0x1e, // Extensions Length
            // Extension: server_name
            0x00, 0x00, // Type: server_name
            0x00, 0x10, // Length
            0x00, 0x0e, // List Length
            0x00, // Name Type: host_name
            0x00, 0x0b, // Name Length
            0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, // "example.com"
            // Other extensions...
            0x00, 0x0b, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02,
            0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x17,
        ];

        let result = parse_tls_client_hello(&client_hello);
        assert!(result.is_ok());

        if let Ok(ApplicationLayer::TLS { sni_hostname }) = result {
            assert_eq!(sni_hostname, Some("example.com".to_string()));
        } else {
            panic!("Expected TLS packet with SNI");
        }
    }
}