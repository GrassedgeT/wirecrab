//! 会话追踪器
//! 
//! 管理所有活动的网络会话，将数据包分配到相应的会话，
//! 并处理会话的生命周期。

use super::{Session, SessionKey, SessionState, Protocol, FlowDirection};
use crate::parser::{ParsedPacket, NetworkLayer, TransportLayer};
use anyhow::Result;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

/// 会话追踪器配置
#[derive(Debug, Clone)]
pub struct TrackerConfig {
    /// TCP会话超时时间
    pub tcp_timeout: Duration,
    /// UDP会话超时时间
    pub udp_timeout: Duration,
    /// ICMP会话超时时间
    pub icmp_timeout: Duration,
    /// 最大会话数
    pub max_sessions: usize,
}

impl Default for TrackerConfig {
    fn default() -> Self {
        Self {
            tcp_timeout: Duration::from_secs(300),    // 5分钟
            udp_timeout: Duration::from_secs(60),     // 1分钟
            icmp_timeout: Duration::from_secs(30),    // 30秒
            max_sessions: 10000,
        }
    }
}

/// 会话追踪器
pub struct SessionTracker {
    /// 配置
    config: TrackerConfig,
    /// 活动会话映射
    sessions: HashMap<SessionKey, Session>,
    /// 会话计数器
    session_counter: u64,
}

impl SessionTracker {
    /// 创建新的会话追踪器
    pub fn new(config: TrackerConfig) -> Self {
        Self {
            config,
            sessions: HashMap::new(),
            session_counter: 0,
        }
    }

    /// 使用默认配置创建会话追踪器
    pub fn with_default_config() -> Self {
        Self::new(TrackerConfig::default())
    }

    /// 处理数据包
    pub fn process_packet(&mut self, packet: &ParsedPacket) -> Result<Option<String>> {
        // 提取会话密钥
        let key = match self.extract_session_key(packet) {
            Some(k) => k,
            None => return Ok(None),
        };

        // 查找或创建会话
        let session_exists = self.sessions.contains_key(&key) || {
            let reverse_key = key.reverse();
            self.sessions.contains_key(&reverse_key)
        };

        let session_id = if session_exists {
            // 更新现有会话
            let session = self.find_session(&key).unwrap();
            let id = session.id.clone();
            self.update_session_by_key(&key, packet)?;
            id
        } else {
            // 创建新会话
            self.create_session(key, packet)?
        };

        // 清理超时的会话
        self.cleanup_expired_sessions();

        Ok(Some(session_id))
    }

    /// 从数据包中提取会话密钥
    fn extract_session_key(&self, packet: &ParsedPacket) -> Option<SessionKey> {
        let (src_ip, dst_ip) = match &packet.network_layer {
            Some(NetworkLayer::IPv4 { src_ip, dst_ip, .. }) => {
                (
                    src_ip.parse::<IpAddr>().ok()?,
                    dst_ip.parse::<IpAddr>().ok()?,
                )
            }
            Some(NetworkLayer::IPv6 { src_ip, dst_ip, .. }) => {
                (
                    src_ip.parse::<IpAddr>().ok()?,
                    dst_ip.parse::<IpAddr>().ok()?,
                )
            }
            _ => return None,
        };

        match &packet.transport_layer {
            Some(TransportLayer::TCP { src_port, dst_port, .. }) => {
                Some(SessionKey::new(
                    Protocol::TCP,
                    src_ip,
                    dst_ip,
                    Some(*src_port),
                    Some(*dst_port),
                ))
            }
            Some(TransportLayer::UDP { src_port, dst_port, .. }) => {
                Some(SessionKey::new(
                    Protocol::UDP,
                    src_ip,
                    dst_ip,
                    Some(*src_port),
                    Some(*dst_port),
                ))
            }
            Some(TransportLayer::ICMP { .. }) => {
                Some(SessionKey::new(
                    if src_ip.is_ipv4() { Protocol::ICMP } else { Protocol::ICMPv6 },
                    src_ip,
                    dst_ip,
                    None,
                    None,
                ))
            }
            _ => None,
        }
    }

    /// 查找会话（检查正向和反向密钥）
    fn find_session(&mut self, key: &SessionKey) -> Option<&mut Session> {
        if self.sessions.contains_key(key) {
            self.sessions.get_mut(key)
        } else {
            let reverse_key = key.reverse();
            self.sessions.get_mut(&reverse_key)
        }
    }

    /// 创建新会话
    fn create_session(&mut self, key: SessionKey, packet: &ParsedPacket) -> Result<String> {
        // 检查会话数限制
        if self.sessions.len() >= self.config.max_sessions {
            // 强制清理一些旧会话
            self.force_cleanup();
        }

        let mut session = Session::new(key.clone());
        session.add_packet(packet.length);

        // 如果是TCP，处理初始的TCP段
        if key.protocol == Protocol::TCP {
            if let Some(TransportLayer::TCP { seq, ack, flags, .. }) = &packet.transport_layer {
                if let Some(ref mut tcp_flow) = session.tcp_flow {
                    // 确定方向（假设发送SYN的是客户端）
                    let direction = if flags.contains(&"SYN".to_string()) && !flags.contains(&"ACK".to_string()) {
                        FlowDirection::ClientToServer
                    } else {
                        FlowDirection::ServerToClient
                    };

                    tcp_flow.add_segment(
                        direction,
                        *seq,
                        *ack,
                        flags,
                        packet.transport_payload.as_deref().unwrap_or(&[]),
                    )?;
                }
            }
        }

        self.session_counter += 1;
        let session_id = session.id.clone();
        self.sessions.insert(key, session);

        Ok(session_id)
    }

    /// 通过密钥更新会话
    fn update_session_by_key(&mut self, key: &SessionKey, packet: &ParsedPacket) -> Result<()> {
        // 先尝试找到会话（检查正向和反向密钥）
        let actual_key = if self.sessions.contains_key(key) {
            key.clone()
        } else {
            key.reverse()
        };

        // 先计算方向（避免借用冲突）
        let direction = if actual_key.protocol == Protocol::TCP {
            Some(self.determine_flow_direction(&actual_key, packet))
        } else {
            None
        };

        if let Some(session) = self.sessions.get_mut(&actual_key) {
            session.add_packet(packet.length);

            // 如果是TCP会话，更新TCP流
            if session.key.protocol == Protocol::TCP {
                if let Some(TransportLayer::TCP { seq, ack, flags, .. }) = &packet.transport_layer {
                    if let Some(ref mut tcp_flow) = session.tcp_flow {
                        // 使用预先计算的方向
                        let dir = direction.unwrap_or(FlowDirection::ClientToServer);
                        
                        // TODO: 提取TCP负载数据
                        let tcp_data = packet.transport_payload.as_deref().unwrap_or(&[]);
                        
                        tcp_flow.add_segment(
                            dir,
                            *seq,
                            *ack,
                            flags,
                            tcp_data,
                        )?;

                        // 更新会话状态
                        let tcp_state = tcp_flow.state();
                        session.state = match tcp_state {
                            super::flow::TcpState::Established => SessionState::Established,
                            super::flow::TcpState::Closed => SessionState::Closed,
                            super::flow::TcpState::FinWait1 |
                            super::flow::TcpState::FinWait2 |
                            super::flow::TcpState::Closing |
                            super::flow::TcpState::LastAck => SessionState::Closing,
                            _ => session.state,
                        };
                    }
                }
            }
        }

        Ok(())
    }

    /// 确定TCP流的方向
    fn determine_flow_direction(&self, session_key: &SessionKey, packet: &ParsedPacket) -> FlowDirection {
        // 从数据包中提取源IP和端口
        let (packet_src_ip, packet_src_port) = match (&packet.network_layer, &packet.transport_layer) {
            (
                Some(NetworkLayer::IPv4 { src_ip, .. }) | Some(NetworkLayer::IPv6 { src_ip, .. }),
                Some(TransportLayer::TCP { src_port, .. }) | Some(TransportLayer::UDP { src_port, .. })
            ) => {
                (src_ip.parse::<IpAddr>().ok(), Some(*src_port))
            }
            _ => (None, None),
        };

        // 如果数据包的源地址匹配会话的源地址，则是客户端到服务器
        if packet_src_ip == Some(session_key.src_ip) && packet_src_port == session_key.src_port {
            FlowDirection::ClientToServer
        } else {
            FlowDirection::ServerToClient
        }
    }

    /// 清理超时的会话
    fn cleanup_expired_sessions(&mut self) {
        let _now = SystemTime::now();
        let mut expired_keys = Vec::new();

        for (key, session) in &self.sessions {
            let timeout = match key.protocol {
                Protocol::TCP => self.config.tcp_timeout,
                Protocol::UDP => self.config.udp_timeout,
                Protocol::ICMP | Protocol::ICMPv6 => self.config.icmp_timeout,
            };

            if session.is_timeout(timeout) || session.state == SessionState::Closed {
                expired_keys.push(key.clone());
            }
        }

        for key in expired_keys {
            self.sessions.remove(&key);
        }
    }

    /// 强制清理旧会话（当达到会话数限制时）
    fn force_cleanup(&mut self) {
        // 按最后活动时间排序，删除最旧的10%
        let mut sessions_vec: Vec<(SessionKey, SystemTime)> = self.sessions
            .iter()
            .map(|(k, v)| (k.clone(), v.last_activity))
            .collect();

        sessions_vec.sort_by_key(|(_, time)| *time);

        let remove_count = self.sessions.len() / 10;
        for (key, _) in sessions_vec.into_iter().take(remove_count) {
            self.sessions.remove(&key);
        }
    }

    /// 获取会话信息
    pub fn get_session(&self, session_id: &str) -> Option<&Session> {
        self.sessions.values().find(|s| s.id == session_id)
    }

    /// 获取所有活动会话
    pub fn get_active_sessions(&self) -> Vec<&Session> {
        self.sessions.values().collect()
    }

    /// 获取会话统计信息
    pub fn get_stats(&self) -> TrackerStats {
        let mut tcp_count = 0;
        let mut udp_count = 0;
        let mut icmp_count = 0;
        let mut total_bytes = 0u64;

        for (key, session) in &self.sessions {
            total_bytes += session.total_bytes;
            match key.protocol {
                Protocol::TCP => tcp_count += 1,
                Protocol::UDP => udp_count += 1,
                Protocol::ICMP | Protocol::ICMPv6 => icmp_count += 1,
            }
        }

        TrackerStats {
            total_sessions: self.sessions.len(),
            tcp_sessions: tcp_count,
            udp_sessions: udp_count,
            icmp_sessions: icmp_count,
            total_bytes,
            sessions_created: self.session_counter,
        }
    }
}

/// 会话追踪器统计信息
#[derive(Debug)]
pub struct TrackerStats {
    pub total_sessions: usize,
    pub tcp_sessions: usize,
    pub udp_sessions: usize,
    pub icmp_sessions: usize,
    pub total_bytes: u64,
    pub sessions_created: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::LinkLayer;
    use std::str::FromStr;

    fn create_test_tcp_packet(src_ip: &str, dst_ip: &str, src_port: u16, dst_port: u16) -> ParsedPacket {
        ParsedPacket {
            timestamp: chrono::Utc::now(),
            interface: "eth0".to_string(),
            length: 100,
            frame_number: 1,
            link_layer: LinkLayer {
                protocol: "Ethernet".to_string(),
                src_mac: Some("00:11:22:33:44:55".to_string()),
                dst_mac: Some("66:77:88:99:AA:BB".to_string()),
            },
            network_layer: Some(NetworkLayer::IPv4 {
                src_ip: src_ip.to_string(),
                dst_ip: dst_ip.to_string(),
                ttl: 64,
                id: 12345,
                flags: vec![],
                fragment_offset: 0,
                total_length: 60,
            }),
            transport_layer: Some(TransportLayer::TCP {
                src_port,
                dst_port,
                seq: 1000,
                ack: 0,
                flags: vec!["SYN".to_string()],
                window: 65535,
                checksum: 0,
                urgent_pointer: 0,
            }),
            application_layer: None,
            session_info: None,
            transport_payload: None,
            raw_data: vec![],
        }
    }

    #[test]
    fn test_session_creation() {
        let mut tracker = SessionTracker::with_default_config();
        let packet = create_test_tcp_packet("192.168.1.1", "8.8.8.8", 12345, 80);
        
        let session_id = tracker.process_packet(&packet).unwrap();
        assert!(session_id.is_some());
        
        let stats = tracker.get_stats();
        assert_eq!(stats.total_sessions, 1);
        assert_eq!(stats.tcp_sessions, 1);
    }

    #[test]
    fn test_bidirectional_session() {
        let mut tracker = SessionTracker::with_default_config();
        
        // 客户端到服务器
        let packet1 = create_test_tcp_packet("192.168.1.1", "8.8.8.8", 12345, 80);
        let session_id1 = tracker.process_packet(&packet1).unwrap();
        
        // 服务器到客户端（反向）
        let packet2 = create_test_tcp_packet("8.8.8.8", "192.168.1.1", 80, 12345);
        let session_id2 = tracker.process_packet(&packet2).unwrap();
        
        // 应该是同一个会话
        assert_eq!(session_id1, session_id2);
        
        let stats = tracker.get_stats();
        assert_eq!(stats.total_sessions, 1);
    }
}