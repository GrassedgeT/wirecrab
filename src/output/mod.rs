//! 输出格式化模块

use anyhow::Result;
use crate::parser::ParsedPacket;

pub mod json;

/// 输出格式类型
#[derive(Debug, Clone, Copy)]
pub enum OutputFormat {
    Json,
    // 未来可以支持更多格式
    // Csv,
    // Text,
}

/// 输出格式化器trait
pub trait OutputFormatter {
    /// 格式化单个数据包
    fn format_packet(&self, packet: &ParsedPacket) -> Result<String>;
    
    /// 格式化数据包批次
    fn format_batch(&self, packets: &[ParsedPacket]) -> Result<String> {
        let mut results = Vec::new();
        for packet in packets {
            results.push(self.format_packet(packet)?);
        }
        Ok(results.join("\n"))
    }
}

/// 创建输出格式化器
pub fn create_formatter(format: OutputFormat) -> Box<dyn OutputFormatter> {
    match format {
        OutputFormat::Json => Box::new(json::JsonFormatter::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_formatter() {
        let formatter = create_formatter(OutputFormat::Json);
        // 仅测试是否能创建
        assert!(true);
    }
}