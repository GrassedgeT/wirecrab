use crate::capture::CapturedPacket;
use crate::parser::{PacketParser, ParsedPacket};
use std::collections::{HashMap, VecDeque};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc::Receiver,
    Arc, Mutex,
};
use std::thread;

/// PacketProcessor负责在一个单独的线程中处理数据包的解析和存储。
pub struct PacketProcessor {
    packets: Arc<Mutex<VecDeque<ParsedPacket>>>,
    protocol_counts: Arc<Mutex<HashMap<String, u64>>>,
    is_running: Arc<AtomicBool>,
    packet_receiver: Receiver<CapturedPacket>,
    parser: PacketParser,
}

impl PacketProcessor {
    /// 创建一个新的PacketProcessor实例。
    ///
    /// # Arguments
    /// * `is_running` - 一个原子布尔值，用于控制处理循环的运行状态。
    /// * `packet_receiver` - 用于接收捕获到的原始数据包的通道接收端。
    /// * `packets` - 用于存储已解析数据包的共享数据结构。
    ///
    /// # Returns
    ///一个新的 `PacketProcessor` 实例。
    pub fn new(
        is_running: Arc<AtomicBool>,
        packet_receiver: Receiver<CapturedPacket>,
        packets: Arc<Mutex<VecDeque<ParsedPacket>>>,
        protocol_counts: Arc<Mutex<HashMap<String, u64>>>,
    ) -> Self {
        Self {
            packets,
            protocol_counts,
            is_running,
            packet_receiver,
            parser: PacketParser::new(),
        }
    }

    /// 启动数据包处理循环。
    ///
    /// 这个方法会持续从 `packet_receiver` 接收原始数据包，
    /// 使用 `PacketParser` 对其进行解析，然后将解析后的数据包
    /// 添加到共享的 `packets` VecDeque中。
    ///
    /// 循环会一直运行，直到 `is_running` 标志位被设置为 `false`。
    pub fn run(mut self) {
        while self.is_running.load(Ordering::Relaxed) {
            if let Ok(packet) = self.packet_receiver.try_recv() {
                let timestamp = chrono::Utc::now();
                match self
                    .parser
                    .parse_packet(&packet.data, timestamp, packet.interface)
                {
                    Ok(parsed_packet) => {
                        let protocols = parsed_packet.get_protocols();
                        if let Ok(mut counts) = self.protocol_counts.lock() {
                            for protocol in protocols {
                                *counts.entry(protocol.to_string()).or_insert(0) += 1;
                            }
                        }

                        if let Ok(mut packets) = self.packets.lock() {
                            packets.push_back(parsed_packet);
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to parse packet: {}", e);
                    }
                }
            } else {
                // 当没有数据包时，短暂休眠以避免CPU占用过高
                thread::sleep(std::time::Duration::from_millis(10));
            }
        }
    }
}