//! TCP流重组模块
//! 
//! 负责将TCP分片重组成完整的数据流，
//! 处理乱序包、重传等情况。

use anyhow::Result;
use std::collections::BTreeMap;

/// TCP流方向
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FlowDirection {
    /// 客户端到服务器
    ClientToServer,
    /// 服务器到客户端
    ServerToClient,
}

/// TCP流
#[derive(Debug)]
pub struct TcpFlow {
    /// 客户端到服务器的数据流
    client_to_server: TcpStream,
    /// 服务器到客户端的数据流
    server_to_client: TcpStream,
    /// TCP连接状态
    state: TcpState,
}

/// TCP连接状态
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TcpState {
    /// 初始状态
    Init,
    /// SYN已发送
    SynSent,
    /// SYN已接收
    SynReceived,
    /// 连接已建立
    Established,
    /// FIN等待1
    FinWait1,
    /// FIN等待2
    FinWait2,
    /// 关闭等待
    CloseWait,
    /// 正在关闭
    Closing,
    /// 最后确认
    LastAck,
    /// 时间等待
    TimeWait,
    /// 已关闭
    Closed,
}

/// TCP数据流
#[derive(Debug)]
struct TcpStream {
    /// 初始序列号
    initial_seq: Option<u32>,
    /// 下一个期望的序列号
    next_seq: u32,
    /// 缓冲的数据段（按序列号排序）
    segments: BTreeMap<u32, Vec<u8>>,
    /// 已重组的数据
    reassembled_data: Vec<u8>,
    /// 是否收到FIN
    fin_received: bool,
}

impl TcpFlow {
    /// 创建新的TCP流
    pub fn new() -> Self {
        Self {
            client_to_server: TcpStream::new(),
            server_to_client: TcpStream::new(),
            state: TcpState::Init,
        }
    }

    /// 添加TCP段到流中
    pub fn add_segment(
        &mut self,
        direction: FlowDirection,
        seq: u32,
        ack: u32,
        flags: &[String],
        data: &[u8],
    ) -> Result<()> {
        // 更新TCP状态机
        self.update_state(direction, flags)?;

        // 获取对应方向的流
        let stream = match direction {
            FlowDirection::ClientToServer => &mut self.client_to_server,
            FlowDirection::ServerToClient => &mut self.server_to_client,
        };

        // 处理SYN标志（初始化序列号）
        if flags.contains(&"SYN".to_string()) {
            stream.initial_seq = Some(seq);
            stream.next_seq = seq.wrapping_add(1);
            return Ok(());
        }

        // 如果有数据，添加到流中
        if !data.is_empty() {
            stream.add_data(seq, data)?;
        }

        // 处理FIN标志
        if flags.contains(&"FIN".to_string()) {
            stream.fin_received = true;
        }

        Ok(())
    }

    /// 更新TCP状态机
    fn update_state(&mut self, direction: FlowDirection, flags: &[String]) -> Result<()> {
        let has_syn = flags.contains(&"SYN".to_string());
        let has_ack = flags.contains(&"ACK".to_string());
        let has_fin = flags.contains(&"FIN".to_string());
        let has_rst = flags.contains(&"RST".to_string());

        if has_rst {
            self.state = TcpState::Closed;
            return Ok(());
        }

        match self.state {
            TcpState::Init => {
                if has_syn && !has_ack {
                    self.state = TcpState::SynSent;
                }
            }
            TcpState::SynSent => {
                if has_syn && has_ack {
                    self.state = TcpState::SynReceived;
                }
            }
            TcpState::SynReceived => {
                if has_ack && !has_syn {
                    self.state = TcpState::Established;
                }
            }
            TcpState::Established => {
                if has_fin {
                    self.state = TcpState::FinWait1;
                }
            }
            TcpState::FinWait1 => {
                if has_ack {
                    self.state = TcpState::FinWait2;
                }
                if has_fin {
                    self.state = TcpState::Closing;
                }
            }
            TcpState::FinWait2 => {
                if has_fin {
                    self.state = TcpState::TimeWait;
                }
            }
            TcpState::Closing => {
                if has_ack {
                    self.state = TcpState::TimeWait;
                }
            }
            _ => {}
        }

        Ok(())
    }

    /// 获取重组的数据
    pub fn get_reassembled_data(&self, direction: FlowDirection) -> &[u8] {
        match direction {
            FlowDirection::ClientToServer => &self.client_to_server.reassembled_data,
            FlowDirection::ServerToClient => &self.server_to_client.reassembled_data,
        }
    }

    /// 获取TCP连接状态
    pub fn state(&self) -> TcpState {
        self.state
    }

    /// 检查是否有新的完整数据可用
    pub fn has_new_data(&mut self, direction: FlowDirection) -> bool {
        match direction {
            FlowDirection::ClientToServer => self.client_to_server.reassemble(),
            FlowDirection::ServerToClient => self.server_to_client.reassemble(),
        }
    }
}

impl TcpStream {
    /// 创建新的TCP流
    fn new() -> Self {
        Self {
            initial_seq: None,
            next_seq: 0,
            segments: BTreeMap::new(),
            reassembled_data: Vec::new(),
            fin_received: false,
        }
    }

    /// 添加数据到流中
    fn add_data(&mut self, seq: u32, data: &[u8]) -> Result<()> {
        // 如果还没有初始序列号，无法处理
        if self.initial_seq.is_none() {
            return Err(anyhow::anyhow!("未初始化的TCP流"));
        }

        // 将数据段添加到缓冲区
        self.segments.insert(seq, data.to_vec());

        Ok(())
    }

    /// 尝试重组数据
    fn reassemble(&mut self) -> bool {
        let mut has_new_data = false;
        
        // 尝试从缓冲区中按序取出数据
        while let Some((&seq, data)) = self.segments.iter().next() {
            if seq == self.next_seq {
                // 这是我们期望的下一个序列号
                let data_len = data.len();
                self.reassembled_data.extend_from_slice(data);
                self.next_seq = self.next_seq.wrapping_add(data_len as u32);
                self.segments.remove(&seq);
                has_new_data = true;
            } else if seq < self.next_seq {
                // 这是重传的数据，已经处理过了
                self.segments.remove(&seq);
            } else {
                // 这是乱序的数据，等待中间的数据包
                break;
            }
        }

        has_new_data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_flow_creation() {
        let flow = TcpFlow::new();
        assert_eq!(flow.state, TcpState::Init);
    }

    #[test]
    fn test_tcp_state_transitions() {
        let mut flow = TcpFlow::new();
        
        // SYN
        flow.add_segment(
            FlowDirection::ClientToServer,
            1000,
            0,
            &vec!["SYN".to_string()],
            &[],
        ).unwrap();
        assert_eq!(flow.state, TcpState::SynSent);
        
        // SYN+ACK
        flow.add_segment(
            FlowDirection::ServerToClient,
            2000,
            1001,
            &vec!["SYN".to_string(), "ACK".to_string()],
            &[],
        ).unwrap();
        assert_eq!(flow.state, TcpState::SynReceived);
        
        // ACK
        flow.add_segment(
            FlowDirection::ClientToServer,
            1001,
            2001,
            &vec!["ACK".to_string()],
            &[],
        ).unwrap();
        assert_eq!(flow.state, TcpState::Established);
    }

    #[test]
    fn test_tcp_data_reassembly() {
        let mut flow = TcpFlow::new();
        
        // 初始化连接
        flow.client_to_server.initial_seq = Some(1000);
        flow.client_to_server.next_seq = 1000;
        
        // 添加有序数据
        flow.add_segment(
            FlowDirection::ClientToServer,
            1000,
            0,
            &vec![],
            b"Hello",
        ).unwrap();
        
        // 重组数据
        assert!(flow.has_new_data(FlowDirection::ClientToServer));
        assert_eq!(
            flow.get_reassembled_data(FlowDirection::ClientToServer),
            b"Hello"
        );
        
        // 添加下一段数据
        flow.add_segment(
            FlowDirection::ClientToServer,
            1005,
            0,
            &vec![],
            b" World",
        ).unwrap();
        
        // 重组数据
        assert!(flow.has_new_data(FlowDirection::ClientToServer));
        assert_eq!(
            flow.get_reassembled_data(FlowDirection::ClientToServer),
            b"Hello World"
        );
    }
}