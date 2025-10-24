use anyhow::Result;
use clap::Parser;
use std::net::IpAddr;
use std::sync::mpsc;
use std::thread;
use wirecrab::{
    capture::{device, PacketCapture},
    filter::{FilterRules, PacketFilter},
    output::{create_formatter, OutputFormat},
    parser::{PacketParser, ParsedPacket},
    session::{SessionTracker, tracker::TrackerConfig},
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

    /// 协议类型过滤 (tcp|udp|arp|icmp|igmp|http|dns)
    #[arg(long)]
    protocol: Option<String>,
    
    /// 应用层协议过滤 (http|dns)
    #[arg(long)]
    app_protocol: Option<String>,

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
    
    /// 启用会话追踪
    #[arg(long)]
    follow_stream: bool,
    
    /// 会话超时时间（秒）
    #[arg(long, default_value = "300")]
    session_timeout: u64,
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
    
    // 创建会话追踪器（如果启用）
    let mut session_tracker = if cli.follow_stream {
        let mut config = TrackerConfig::default();
        config.tcp_timeout = std::time::Duration::from_secs(cli.session_timeout);
        config.udp_timeout = std::time::Duration::from_secs(cli.session_timeout / 5);
        Some(SessionTracker::new(config))
    } else {
        None
    };

    for packet in rx {
        let timestamp = chrono::Utc::now().to_rfc3339();
        match parser.parse_packet(&packet.data, timestamp, packet.interface) {
            Ok(mut parsed_packet) => {
                // 应用基本过滤
                if filter.matches(&parsed_packet) {
                    // 会话追踪（如果启用）
                    if let Some(ref mut tracker) = session_tracker {
                        if let Ok(Some(session_id)) = tracker.process_packet(&parsed_packet) {
                            // 添加会话信息
                            if let Some(session) = tracker.get_session(&session_id) {
                                let direction = {
                                    let mut is_request = false;
                                    if let Some(net_layer) = &parsed_packet.network_layer {
                                        let src_ip_str = match net_layer {
                                            wirecrab::parser::NetworkLayer::IPv4 { src_ip, .. } => src_ip,
                                            wirecrab::parser::NetworkLayer::IPv6 { src_ip, .. } => src_ip,
                                            _ => "",
                                        };

                                        if src_ip_str == session.client_ip.to_string() {
                                            if let Some(transport_layer) = &parsed_packet.transport_layer {
                                                let src_port = match transport_layer {
                                                    wirecrab::parser::TransportLayer::TCP { src_port, .. } => Some(*src_port),
                                                    wirecrab::parser::TransportLayer::UDP { src_port, .. } => Some(*src_port),
                                                    _ => None,
                                                };

                                                if src_port == session.client_port {
                                                    is_request = true;
                                                }
                                            }
                                        }
                                    }
                                    if is_request { "request".to_string() } else { "response".to_string() }
                                };

                                parsed_packet.session_info = Some(wirecrab::parser::SessionInfo {
                                    session_id: session.id.clone(),
                                    direction,
                                    stream_index: session.packet_count,
                                    related_packets: vec![],
                                    total_bytes: session.total_bytes,
                                    duration_ms: session.duration().as_millis() as u64,
                                });
                            }
                        }
                    }
                    
                    // 应用层协议过滤（应用层已在解析器中解析）
                    if let Some(ref app_proto) = cli.app_protocol {
                        if !matches_app_protocol(&parsed_packet, app_proto) {
                            continue;
                        }
                    }
                    
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

/// 检查是否匹配应用层协议
fn matches_app_protocol(packet: &ParsedPacket, protocol: &str) -> bool {
    match &packet.application_layer {
        Some(app_layer) => {
            use wirecrab::parser::application::ApplicationLayer;
            match (protocol.to_lowercase().as_str(), app_layer) {
                ("http", ApplicationLayer::HTTP { .. }) => true,
                ("dns", ApplicationLayer::DNS { .. }) => true,
                _ => false,
            }
        }
        None => false,
    }
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