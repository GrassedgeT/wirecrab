//! 过滤规则定义

use std::net::IpAddr;

/// 过滤规则
#[derive(Debug, Clone, Default)]
pub struct FilterRules {
    pub protocol: Option<String>,
    pub src_ip: Option<IpAddr>,
    pub dst_ip: Option<IpAddr>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub port: Option<u16>,
}

impl FilterRules {
    /// 创建新的过滤规则
    pub fn new() -> Self {
        Self::default()
    }

    /// 检查是否为空规则（没有设置任何过滤条件）
    pub fn is_empty(&self) -> bool {
        self.protocol.is_none()
            && self.src_ip.is_none()
            && self.dst_ip.is_none()
            && self.src_port.is_none()
            && self.dst_port.is_none()
            && self.port.is_none()
    }

    /// 从命令行参数构建过滤规则
    pub fn from_cli_args(
        protocol: Option<String>,
        src_ip: Option<IpAddr>,
        dst_ip: Option<IpAddr>,
        src_port: Option<u16>,
        dst_port: Option<u16>,
        port: Option<u16>,
    ) -> Self {
        Self {
            protocol,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            port,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_empty_rules() {
        let rules = FilterRules::new();
        assert!(rules.is_empty());
    }

    #[test]
    fn test_non_empty_rules() {
        let mut rules = FilterRules::new();
        rules.protocol = Some("tcp".to_string());
        assert!(!rules.is_empty());
    }

    #[test]
    fn test_from_cli_args() {
        let rules = FilterRules::from_cli_args(
            Some("tcp".to_string()),
            Some(IpAddr::from_str("192.168.1.1").unwrap()),
            None,
            Some(80),
            None,
            None,
        );
        
        assert_eq!(rules.protocol, Some("tcp".to_string()));
        assert_eq!(rules.src_ip, Some(IpAddr::from_str("192.168.1.1").unwrap()));
        assert_eq!(rules.src_port, Some(80));
        assert!(rules.dst_ip.is_none());
        assert!(rules.dst_port.is_none());
        assert!(rules.port.is_none());
    }
}