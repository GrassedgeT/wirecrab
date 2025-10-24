//! 数据包捕获模块

use anyhow::Result;
use pcap::Capture;
use std::sync::mpsc::Sender;
use std::thread;

pub mod device;

/// 捕获的数据包
#[derive(Debug, Clone)]
pub struct CapturedPacket {
    pub timestamp: std::time::SystemTime,
    pub data: Vec<u8>,
    pub length: usize,
    pub interface: String,
}

/// 数据包捕获器
pub struct PacketCapture {
    device_name: String,
    capture: Option<Capture<pcap::Active>>,
    packet_sender: Option<Sender<CapturedPacket>>,
}

impl PacketCapture {
    /// 创建新的数据包捕获器
    pub fn new(device_name: String) -> Self {
        Self {
            device_name,
            capture: None,
            packet_sender: None,
        }
    }

    /// 初始化捕获器
    pub fn init(&mut self) -> Result<()> {
        let cap = Capture::from_device(self.device_name.as_str())?
            .promisc(true)
            .snaplen(65535)
            .timeout(1000)
            .open()?;

        self.capture = Some(cap);
        Ok(())
    }

    /// 开始捕获数据包
    pub fn start_capture(&mut self, sender: Sender<CapturedPacket>) -> Result<()> {
        let device_name = self.device_name.clone();
        let mut cap = self.capture.take().ok_or_else(|| anyhow::anyhow!("捕获器未初始化"))?;

        thread::spawn(move || {
            loop {
                match cap.next_packet() {
                    Ok(packet) => {
                        let captured_packet = CapturedPacket {
                            timestamp: std::time::SystemTime::now(),
                            data: packet.data.to_vec(),
                            length: packet.header.len as usize,
                            interface: device_name.clone(),
                        };
                        if sender.send(captured_packet).is_err() {
                            // 接收端已关闭，停止捕获
                            break;
                        }
                    }
                    Err(pcap::Error::TimeoutExpired) => {
                        // 在Windows上，超时是正常的，继续等待
                        continue;
                    }
                    Err(e) => {
                        eprintln!("捕获数据包时发生错误: {}", e);
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    /// 停止捕获
    pub fn stop_capture(&mut self) {
        // TODO: 实现停止逻辑
        println!("停止数据包捕获");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_capture_creation() {
        let capture = PacketCapture::new("eth0".to_string());
        assert_eq!(capture.device_name, "eth0");
    }
}