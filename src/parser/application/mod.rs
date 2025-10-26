//! 应用层协议解析模块
//! 
//! 提供各种应用层协议的解析功能，包括HTTP、DNS等。

use anyhow::Result;
use serde::Serialize;
use std::collections::HashMap;

pub mod dns;
pub mod http;
pub mod ftp;
pub mod tls;

/// 应用层协议类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplicationProtocol {
    HTTP,
    TLS,
    DNS,
    FTP,
    SSH,
    Telnet,
    Unknown,
}

/// 应用层数据
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "protocol")]
pub enum ApplicationLayer {
    HTTP {
        method: Option<String>,
        uri: Option<String>,
        version: String,
        status_code: Option<u16>,
        headers: HashMap<String, String>,
        body_preview: Option<String>,
    },
    DNS {
        transaction_id: u16,
        flags: DnsFlags,
        questions: Vec<DnsQuestion>,
        answers: Vec<DnsRecord>,
        authorities: Vec<DnsRecord>,
        additionals: Vec<DnsRecord>,
    },
    FTP {
        command: Option<String>,
        response_code: Option<u16>,
        message: String,
    },
    SSH {
        version: Option<String>,
        encrypted: bool,
    },
    TLS {
        sni_hostname: Option<String>,
    },
}

impl ApplicationLayer {
    pub fn name(&self) -> &str {
        match self {
            ApplicationLayer::HTTP { .. } => "HTTP",
            ApplicationLayer::DNS { .. } => "DNS",
            ApplicationLayer::FTP { .. } => "FTP",
            ApplicationLayer::SSH { .. } => "SSH",
            ApplicationLayer::TLS { .. } => "TLS",
        }
    }
}

/// DNS标志
#[derive(Debug, Clone, Serialize)]
pub struct DnsFlags {
    pub qr: bool,           // Query/Response
    pub opcode: u8,         // Operation code
    pub aa: bool,           // Authoritative Answer
    pub tc: bool,           // Truncated
    pub rd: bool,           // Recursion Desired
    pub ra: bool,           // Recursion Available
    pub rcode: u8,          // Response code
}

/// DNS查询
#[derive(Debug, Clone, Serialize)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

/// DNS记录
#[derive(Debug, Clone, Serialize)]
pub struct DnsRecord {
    pub name: String,
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    pub rdata: String,
}

/// 根据端口号猜测应用层协议
pub fn guess_protocol_by_port(src_port: u16, dst_port: u16) -> ApplicationProtocol {
    // 检查常见的端口
    match (src_port, dst_port) {
        (80, _) | (_, 80) | (8080, _) | (_, 8080) => ApplicationProtocol::HTTP,
        (443, _) | (_, 443) | (8443, _) | (_, 8443) => ApplicationProtocol::TLS,
        (53, _) | (_, 53) => ApplicationProtocol::DNS,
        (21, _) | (_, 21) => ApplicationProtocol::FTP,
        (22, _) | (_, 22) => ApplicationProtocol::SSH,
        (23, _) | (_, 23) => ApplicationProtocol::Telnet,
        _ => ApplicationProtocol::Unknown,
    }
}

/// 解析应用层数据
pub fn parse_application_data(
    data: &[u8],
    src_port: u16,
    dst_port: u16,
    is_tcp: bool,
) -> Result<Option<ApplicationLayer>> {
    // 如果数据太少，无法解析
    if data.is_empty() {
        return Ok(None);
    }

    // 根据端口猜测协议
    let protocol = guess_protocol_by_port(src_port, dst_port);

    match protocol {
        ApplicationProtocol::DNS => {
            // DNS可以在TCP或UDP上运行
            dns::parse_dns_packet(data, is_tcp).map(Some)
        }
        ApplicationProtocol::HTTP => {
            // HTTP只在TCP上运行
            if is_tcp {
                http::parse_http_data(data).map(Some)
            } else {
                Ok(None)
            }
        }
        ApplicationProtocol::FTP => {
            if is_tcp {
                ftp::parse_ftp_data(data).map(Some)
            } else {
                Ok(None)
            }
        }
        ApplicationProtocol::TLS => {
            if is_tcp {
                tls::parse_tls_client_hello(data).map(Some)
            } else {
                Ok(None)
            }
        }
        _ => Ok(None), // 暂不支持其他协议
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_guess_protocol_by_port() {
        assert_eq!(guess_protocol_by_port(80, 12345), ApplicationProtocol::HTTP);
        assert_eq!(guess_protocol_by_port(12345, 443), ApplicationProtocol::TLS);
        assert_eq!(guess_protocol_by_port(53, 12345), ApplicationProtocol::DNS);
        assert_eq!(guess_protocol_by_port(12345, 12346), ApplicationProtocol::Unknown);
    }
}