use anyhow::Result;
use clap::Parser;
use std::net::IpAddr;
use std::sync::mpsc;
use std::thread;
use wirecrab::{
    capture::{device, PacketCapture},
    filter::{FilterRules, PacketFilter},
    output::{create_formatter, OutputFormat},
    parser::PacketParser,
};

/// WireCrab - 网络数据包嗅探工具
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// 网络接口名称 (默认: 自动选择第一个可用接口)
    #[arg(short, long)]
    interface: Option<String>,

    /// 捕获数据包数量 (默认: 无限)
    #[arg(short, long)]
    count: Option<usize>,

    /// 输出到文件 (默认: stdout)
    #[arg(short, long)]
    output: Option<String>,

    /// 协议类型过滤 (tcp|udp|arp|icmp|igmp)
    #[arg(long)]
    protocol: Option<String>,

    /// 源IP地址过滤
    #[arg(long)]
    src_ip: Option<IpAddr>,

    /// 目标IP地址过滤
    #[arg(long)]
    dst_ip: Option<IpAddr>,

    /// 源端口过滤 (仅TCP/UDP)
    #[arg(long)]
    src_port: Option<u16>,

    /// 目标端口过滤 (仅TCP/UDP)
    #[arg(long)]
    dst_port: Option<u16>,

    /// 端口过滤 (源或目标)
    #[arg(long)]
    port: Option<u16>,

    /// 列出所有网络接口
    #[arg(short, long)]
    list_interfaces: bool,

    /// 详细输出模式
    #[arg(short, long)]
    verbose: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.list_interfaces {
        list_network_interfaces()?;
        return Ok(());
    }

    let interface_name = match cli.interface {
        Some(iface) => iface,
        None => device::get_default_device()?.name,
    };

    println!("正在接口 {} 上启动嗅探...", interface_name);

    let (tx, rx) = mpsc::channel();

    let capture_handle = thread::spawn(move || {
        let mut capture = PacketCapture::new(interface_name);
        if let Err(e) = capture.init() {
            eprintln!("初始化捕获失败: {}", e);
            return;
        }
        if let Err(e) = capture.start_capture(tx) {
            eprintln!("启动捕获失败: {}", e);
        }
    });

    let filter_rules = FilterRules::from_cli_args(
        cli.protocol,
        cli.src_ip,
        cli.dst_ip,
        cli.src_port,
        cli.dst_port,
        cli.port,
    );
    let filter = PacketFilter::new(filter_rules);
    let mut parser = PacketParser::new();
    let formatter = create_formatter(OutputFormat::Json);
    let mut packet_count = 0;

    for packet in rx {
        let timestamp = chrono::Utc::now().to_rfc3339();
        match parser.parse_packet(&packet.data, timestamp, packet.interface) {
            Ok(parsed_packet) => {
                if filter.matches(&parsed_packet) {
                    let output = formatter.format_packet(&parsed_packet)?;
                    println!("{}", output);
                    packet_count += 1;
                    if let Some(count) = cli.count {
                        if packet_count >= count {
                            break;
                        }
                    }
                }
            }
            Err(e) => {
                if cli.verbose {
                    eprintln!("解析数据包失败: {}", e);
                }
            }
        }
    }

    // 等待捕获线程结束 (虽然在当前实现中它会一直运行)
    capture_handle.join().unwrap();

    Ok(())
}

/// 列出所有可用的网络接口
fn list_network_interfaces() -> Result<()> {
    println!("可用的网络接口:");
    let devices = device::list_devices()?;
    for (index, device) in devices.iter().enumerate() {
        println!(
            "  {}. {} - {}",
            index + 1,
            device.name,
            device.desc.as_ref().unwrap_or(&"无描述".to_string())
        );
        for address in &device.addresses {
            println!("     地址: {:?}", address.addr);
        }
    }
    Ok(())
}