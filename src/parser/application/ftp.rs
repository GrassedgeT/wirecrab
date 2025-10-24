//! FTP协议解析模块

use super::ApplicationLayer;
use anyhow::{bail, Result};

/// 解析FTP数据
pub fn parse_ftp_data(data: &[u8]) -> Result<ApplicationLayer> {
    let text = std::str::from_utf8(data).map_err(|_| anyhow::anyhow!("FTP数据包含无效的UTF-8字符"))?;
    let line = text.lines().next().unwrap_or("").trim();

    if line.is_empty() {
        bail!("空的FTP数据");
    }

    // 尝试解析为响应 (e.g., "220 Welcome")
    if line.len() >= 3 && line[..3].chars().all(|c| c.is_digit(10)) {
        let code = line[..3].parse::<u16>()?;
        let message = line[3..].trim().to_string();
        Ok(ApplicationLayer::FTP {
            command: None,
            response_code: Some(code),
            message,
        })
    } else {
        // 尝试解析为命令 (e.g., "USER anonymous")
        let mut parts = line.splitn(2, ' ');
        let command = parts.next().unwrap_or("").to_string();
        let message = parts.next().unwrap_or("").to_string();
        Ok(ApplicationLayer::FTP {
            command: Some(command),
            response_code: None,
            message,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ftp_command() {
        let data = b"USER anonymous\r\n";
        let result = parse_ftp_data(data);
        assert!(result.is_ok());
        if let Ok(ApplicationLayer::FTP { command, response_code, message }) = result {
            assert_eq!(command, Some("USER".to_string()));
            assert_eq!(response_code, None);
            assert_eq!(message, "anonymous");
        } else {
            panic!("Expected FTP command");
        }
    }

    #[test]
    fn test_parse_ftp_response() {
        let data = b"220 Service ready for new user.\r\n";
        let result = parse_ftp_data(data);
        assert!(result.is_ok());
        if let Ok(ApplicationLayer::FTP { command, response_code, message }) = result {
            assert_eq!(command, None);
            assert_eq!(response_code, Some(220));
            assert_eq!(message, "Service ready for new user.");
        } else {
            panic!("Expected FTP response");
        }
    }
}