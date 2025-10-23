//! 会话追踪模块
//! 
//! 负责跟踪网络连接的完整会话，重组TCP流，
//! 并为应用层协议解析提供完整的数据流。

use anyhow::Result;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, SystemTime};

pub mod tracker;
pub mod flow;

pub use tracker::SessionTracker;
pub use flow::{TcpFlow, FlowDirection};

/// 会话密钥，用于唯一标识一个会话
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct SessionKey {
    /// 协议类型
    pub protocol: Protocol,
    /// 源IP地址
    pub src_ip: IpAddr,
    /// 目标IP地址
    pub dst_ip: IpAddr,
    /// 源端口（TCP/UDP）
    pub src_port: Option<u16>,
    /// 目标端口（TCP/UDP）
    pub dst_port: Option<u16>,
}

/// 支持的协议类型
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub enum Protocol {
    TCP,
    UDP,
    ICMP,
    ICMPv6,
}

/// 会话信息
#[derive(Debug)]
pub struct Session {
    /// 会话ID
    pub id: String,
    /// 会话密钥
    pub key: SessionKey,
    /// 会话开始时间
    pub start_time: SystemTime,
    /// 最后活动时间
    pub last_activity: SystemTime,
    /// 总字节数
    pub total_bytes: u64,
    /// 数据包计数
    pub packet_count: u64,
    /// TCP流（仅TCP会话）
    pub tcp_flow: Option<TcpFlow>,
    /// 会话状态
    pub state: SessionState,
}

/// 会话状态
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SessionState {
    /// 新建
    New,
    /// 已建立
    Established,
    /// 正在关闭
    Closing,
    /// 已关闭
    Closed,
}

impl SessionKey {
    /// 创建新的会话密钥
    pub fn new(
        protocol: Protocol,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: Option<u16>,
        dst_port: Option<u16>,
    ) -> Self {
        Self {
            protocol,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
        }
    }

    /// 获取反向的会话密钥（用于匹配双向流量）
    pub fn reverse(&self) -> Self {
        Self {
            protocol: self.protocol,
            src_ip: self.dst_ip,
            dst_ip: self.src_ip,
            src_port: self.dst_port,
            dst_port: self.src_port,
        }
    }

    /// 生成会话ID字符串
    pub fn to_session_id(&self) -> String {
        match (self.src_port, self.dst_port) {
            (Some(sp), Some(dp)) => {
                format!("{}:{}:{}-{}:{}", 
                    self.protocol_str(),
                    self.src_ip,
                    sp,
                    self.dst_ip,
                    dp
                )
            }
            _ => {
                format!("{}:{}-{}", 
                    self.protocol_str(),
                    self.src_ip,
                    self.dst_ip
                )
            }
        }
    }

    fn protocol_str(&self) -> &'static str {
        match self.protocol {
            Protocol::TCP => "TCP",
            Protocol::UDP => "UDP",
            Protocol::ICMP => "ICMP",
            Protocol::ICMPv6 => "ICMPv6",
        }
    }
}

impl Session {
    /// 创建新的会话
    pub fn new(key: SessionKey) -> Self {
        let now = SystemTime::now();
        let tcp_flow = if key.protocol == Protocol::TCP {
            Some(TcpFlow::new())
        } else {
            None
        };

        Self {
            id: key.to_session_id(),
            key,
            start_time: now,
            last_activity: now,
            total_bytes: 0,
            packet_count: 0,
            tcp_flow,
            state: SessionState::New,
        }
    }

    /// 更新会话活动时间
    pub fn update_activity(&mut self) {
        self.last_activity = SystemTime::now();
    }

    /// 添加数据包到会话
    pub fn add_packet(&mut self, length: usize) {
        self.update_activity();
        self.total_bytes += length as u64;
        self.packet_count += 1;
    }

    /// 获取会话持续时间
    pub fn duration(&self) -> Duration {
        self.last_activity.duration_since(self.start_time)
            .unwrap_or(Duration::from_secs(0))
    }

    /// 检查会话是否超时
    pub fn is_timeout(&self, timeout: Duration) -> bool {
        SystemTime::now()
            .duration_since(self.last_activity)
            .unwrap_or(Duration::from_secs(0)) > timeout
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_session_key_reverse() {
        let key = SessionKey::new(
            Protocol::TCP,
            IpAddr::from_str("192.168.1.1").unwrap(),
            IpAddr::from_str("8.8.8.8").unwrap(),
            Some(12345),
            Some(80),
        );

        let reversed = key.reverse();
        assert_eq!(reversed.src_ip, key.dst_ip);
        assert_eq!(reversed.dst_ip, key.src_ip);
        assert_eq!(reversed.src_port, key.dst_port);
        assert_eq!(reversed.dst_port, key.src_port);
    }

    #[test]
    fn test_session_creation() {
        let key = SessionKey::new(
            Protocol::TCP,
            IpAddr::from_str("192.168.1.1").unwrap(),
            IpAddr::from_str("8.8.8.8").unwrap(),
            Some(12345),
            Some(443),
        );

        let session = Session::new(key);
        assert_eq!(session.id, "TCP:192.168.1.1:12345-8.8.8.8:443");
        assert_eq!(session.packet_count, 0);
        assert_eq!(session.total_bytes, 0);
        assert!(session.tcp_flow.is_some());
    }
}