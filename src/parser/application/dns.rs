//! DNS协议解析模块
//! 
//! 支持解析DNS查询和响应数据包。

use super::{ApplicationLayer, DnsFlags, DnsQuestion, DnsRecord};
use anyhow::{bail, Result};
use std::net::{Ipv4Addr, Ipv6Addr};

/// 解析DNS数据包
pub fn parse_dns_packet(data: &[u8], is_tcp: bool) -> Result<ApplicationLayer> {
    let (dns_data, base_data) = if is_tcp {
        if data.len() < 2 {
            bail!("DNS over TCP数据包太短，缺少长度字段");
        }
        let len = u16::from_be_bytes([data[0], data[1]]) as usize;
        if data.len() < len + 2 {
            bail!("DNS over TCP数据包不完整");
        }
        (&data[2..len + 2], data)
    } else {
        (data, data)
    };

    if dns_data.len() < 12 {
        bail!("DNS数据包太短，至少需要12字节的头部");
    }

    // 解析DNS头部
    let transaction_id = u16::from_be_bytes([dns_data[0], dns_data[1]]);
    let flags_raw = u16::from_be_bytes([dns_data[2], dns_data[3]]);
    let flags = parse_flags(flags_raw);
    
    let question_count = u16::from_be_bytes([dns_data[4], dns_data[5]]);
    let answer_count = u16::from_be_bytes([dns_data[6], dns_data[7]]);
    let authority_count = u16::from_be_bytes([dns_data[8], dns_data[9]]);
    let additional_count = u16::from_be_bytes([dns_data[10], dns_data[11]]);

    let mut offset = 12;

    // 解析问题部分
    let mut questions = Vec::new();
    for _ in 0..question_count {
        let (question, new_offset) = parse_question(dns_data, dns_data, offset)?;
        questions.push(question);
        offset = new_offset;
    }

    // 解析回答部分
    let mut answers = Vec::new();
    for _ in 0..answer_count {
        let (record, new_offset) = parse_resource_record(dns_data, dns_data, offset)?;
        answers.push(record);
        offset = new_offset;
    }

    // 解析权威部分
    let mut authorities = Vec::new();
    for _ in 0..authority_count {
        let (record, new_offset) = parse_resource_record(dns_data, dns_data, offset)?;
        authorities.push(record);
        offset = new_offset;
    }

    // 解析附加部分
    let mut additionals = Vec::new();
    for _ in 0..additional_count {
        let (record, new_offset) = parse_resource_record(dns_data, dns_data, offset)?;
        additionals.push(record);
        offset = new_offset;
    }

    Ok(ApplicationLayer::DNS {
        transaction_id,
        flags,
        questions,
        answers,
        authorities,
        additionals,
    })
}

/// 解析DNS标志
fn parse_flags(flags_raw: u16) -> DnsFlags {
    DnsFlags {
        qr: (flags_raw & 0x8000) != 0,
        opcode: ((flags_raw >> 11) & 0x0F) as u8,
        aa: (flags_raw & 0x0400) != 0,
        tc: (flags_raw & 0x0200) != 0,
        rd: (flags_raw & 0x0100) != 0,
        ra: (flags_raw & 0x0080) != 0,
        rcode: (flags_raw & 0x000F) as u8,
    }
}

/// 解析DNS域名
fn parse_domain_name(data: &[u8], base_data: &[u8], mut offset: usize) -> Result<(String, usize)> {
    let mut parts = Vec::new();

    loop {
        if offset >= data.len() {
            bail!("DNS域名解析越界");
        }

        let len = data[offset] as usize;

        // 检查是否是压缩指针
        if (len & 0xC0) == 0xC0 {
            let pointer = (((len & 0x3F) as usize) << 8) | (data[offset + 1] as usize);
            // The pointer is relative to the start of the base_data
            let (jumped_name, _) = parse_domain_name(base_data, base_data, pointer)?;
            parts.push(jumped_name);
            let final_offset = offset + 2;
            let name = parts.join(".");
            return Ok((name, final_offset));
        }

        offset += 1;

        if len == 0 {
            let final_offset = offset;
            let name = parts.join(".");
            return Ok((name, final_offset));
        }

        if offset + len > data.len() {
            bail!("DNS域名标签长度越界");
        }

        let label = std::str::from_utf8(&data[offset..offset + len])
            .map_err(|_| anyhow::anyhow!("无效的DNS域名标签"))?;
        parts.push(label.to_string());
        offset += len;
    }
}

/// 解析DNS问题
fn parse_question(data: &[u8], base_data: &[u8], offset: usize) -> Result<(DnsQuestion, usize)> {
    let (name, offset) = parse_domain_name(data, base_data, offset)?;
    
    if offset + 4 > data.len() {
        bail!("DNS问题部分不完整");
    }

    let qtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
    let qclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);

    Ok((
        DnsQuestion {
            name,
            qtype,
            qclass,
        },
        offset + 4,
    ))
}

/// 解析DNS资源记录
fn parse_resource_record(data: &[u8], base_data: &[u8], offset: usize) -> Result<(DnsRecord, usize)> {
    let (name, mut offset) = parse_domain_name(data, base_data, offset)?;
    
    if offset + 10 > data.len() {
        bail!("DNS资源记录头部不完整");
    }

    let rtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
    let rclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
    let ttl = u32::from_be_bytes([
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ]);
    let rdlength = u16::from_be_bytes([data[offset + 8], data[offset + 9]]) as usize;
    offset += 10;

    if offset + rdlength > data.len() {
        bail!("DNS资源记录数据不完整");
    }

    let rdata = parse_rdata(data, base_data, offset, rtype, rdlength)?;
    offset += rdlength;

    Ok((
        DnsRecord {
            name,
            rtype,
            rclass,
            ttl,
            rdata,
        },
        offset,
    ))
}

/// 解析资源数据
fn parse_rdata(data: &[u8], base_data: &[u8], offset: usize, rtype: u16, length: usize) -> Result<String> {
    match rtype {
        1 => {
            // A记录 (IPv4地址)
            if length != 4 {
                bail!("A记录长度应为4字节");
            }
            let addr = Ipv4Addr::new(
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            );
            Ok(addr.to_string())
        }
        28 => {
            // AAAA记录 (IPv6地址)
            if length != 16 {
                bail!("AAAA记录长度应为16字节");
            }
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&data[offset..offset + 16]);
            let addr = Ipv6Addr::from(bytes);
            Ok(addr.to_string())
        }
        5 => {
            // CNAME记录
            let (name, _) = parse_domain_name(data, base_data, offset)?;
            Ok(name)
        }
        6 => {
            // SOA记录
            let (mname, offset) = parse_domain_name(data, base_data, offset)?;
            let (rname, offset) = parse_domain_name(data, base_data, offset)?;
            if offset + 20 > data.len() {
                bail!("SOA记录数据不完整");
            }
            let serial = u32::from_be_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            let refresh = u32::from_be_bytes([
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
            ]);
            let retry = u32::from_be_bytes([
                data[offset + 8],
                data[offset + 9],
                data[offset + 10],
                data[offset + 11],
            ]);
            let expire = u32::from_be_bytes([
                data[offset + 12],
                data[offset + 13],
                data[offset + 14],
                data[offset + 15],
            ]);
            let minimum = u32::from_be_bytes([
                data[offset + 16],
                data[offset + 17],
                data[offset + 18],
                data[offset + 19],
            ]);
            Ok(format!(
                "{} {} {} {} {} {} {}",
                mname, rname, serial, refresh, retry, expire, minimum
            ))
        }
        12 => {
            // PTR记录
            let (name, _) = parse_domain_name(data, base_data, offset)?;
            Ok(name)
        }
        15 => {
            // MX记录
            if length < 2 {
                bail!("MX记录太短");
            }
            let preference = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let (exchange, _) = parse_domain_name(data, base_data, offset + 2)?;
            Ok(format!("{} {}", preference, exchange))
        }
        16 => {
            // TXT记录
            let mut txt_data = String::new();
            let mut pos = offset;
            while pos < offset + length {
                let txt_len = data[pos] as usize;
                pos += 1;
                if pos + txt_len > offset + length {
                    bail!("TXT记录数据不完整");
                }
                let txt = std::str::from_utf8(&data[pos..pos + txt_len])
                    .map_err(|_| anyhow::anyhow!("无效的TXT记录数据"))?;
                if !txt_data.is_empty() {
                    txt_data.push(' ');
                }
                txt_data.push_str(txt);
                pos += txt_len;
            }
            Ok(txt_data)
        }
        _ => {
            // 其他类型，显示为十六进制
            let hex = data[offset..offset + length]
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>();
            Ok(format!("0x{}", hex))
        }
    }
}

/// 获取DNS查询类型名称
pub fn get_dns_type_name(qtype: u16) -> &'static str {
    match qtype {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        255 => "ANY",
        _ => "UNKNOWN",
    }
}

/// 获取DNS响应码名称
pub fn get_dns_rcode_name(rcode: u8) -> &'static str {
    match rcode {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        _ => "UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_flags() {
        let flags_raw = 0x8180; // QR=1, RD=1, RA=1
        let flags = parse_flags(flags_raw);
        assert!(flags.qr);
        assert!(flags.rd);
        assert!(flags.ra);
        assert_eq!(flags.opcode, 0);
        assert_eq!(flags.rcode, 0);
    }

    #[test]
    fn test_get_dns_type_name() {
        assert_eq!(get_dns_type_name(1), "A");
        assert_eq!(get_dns_type_name(28), "AAAA");
        assert_eq!(get_dns_type_name(999), "UNKNOWN");
    }

    #[test]
    fn test_simple_dns_query() {
        // 一个简单的DNS查询示例（仅头部）
        let data = vec![
            0x12, 0x34, // Transaction ID
            0x01, 0x00, // Flags: RD=1
            0x00, 0x01, // Questions: 1
            0x00, 0x00, // Answers: 0
            0x00, 0x00, // Authorities: 0
            0x00, 0x00, // Additionals: 0
        ];

        // 这个测试会失败，因为没有问题部分的数据
        let result = parse_dns_packet(&data, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_dns_over_tcp() {
        // 构造一个DNS over TCP报文
        // 前2个字节是长度 (0x00, 0x1c = 28)
        // 后面是标准的DNS查询报文
        let data = vec![
            0x00, 0x1d, // Length
            0xab, 0xcd, // Transaction ID
            0x01, 0x00, // Flags: RD=1
            0x00, 0x01, // Questions: 1
            0x00, 0x00, // Answers: 0
            0x00, 0x00, // Authorities: 0
            0x00, 0x00, // Additionals: 0
            // Query
            0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, // "example"
            0x03, 0x63, 0x6f, 0x6d, // "com"
            0x00, // End of name
            0x00, 0x01, // Type: A
            0x00, 0x01, // Class: IN
        ];

        let result = parse_dns_packet(&data, true);
        assert!(result.is_ok());

        if let Ok(ApplicationLayer::DNS { transaction_id, questions, .. }) = result {
            assert_eq!(transaction_id, 0xabcd);
            assert_eq!(questions.len(), 1);
            assert_eq!(questions[0].name, "example.com");
        } else {
            panic!("Expected DNS packet");
        }
    }
}