use eframe::{egui, App, Frame};
use egui_json_tree::JsonTree;
use egui_plot::{Line, Plot, Legend};
use pcap::Device;
use crate::{capture::{device, PacketCapture}, filter::PacketFilter, parser::{ParsedPacket, PacketParser}, session::PacketProcessor};
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::{mpsc, Arc, atomic::{AtomicBool, Ordering}, Mutex};
use std::thread;
use egui_extras::{TableBuilder, Column};
use std::collections::{VecDeque, HashMap};
use std::time::Instant;

#[derive(PartialEq)]
enum Tab {
    Capture,
    Statistics,
}

#[derive(PartialEq, Clone, Copy)]
enum CacheLimit {
    Limit(usize),
    Unlimited,
}

impl std::fmt::Display for CacheLimit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CacheLimit::Limit(n) => write!(f, "{}", n),
            CacheLimit::Unlimited => write!(f, "Unlimited"),
        }
    }
}

#[derive(PartialEq)]
enum ChartView {
    Line,
    Pie,
}

pub struct WireCrabApp {
    active_tab: Tab,
    devices: Vec<Device>,
    selected_device_index: Option<usize>,
    is_capturing: bool,
    protocol_filter: String,
    src_ip_filter: String,
    dst_ip_filter: String,
    src_port_filter: String,
    dst_port_filter: String,
    port_filter: String,
    packets: Arc<Mutex<VecDeque<ParsedPacket>>>,
    filtered_packets: Vec<usize>,
    active_filter: Option<PacketFilter>,
    selected_packet_index: Option<usize>,
    capture_handle: Option<thread::JoinHandle<()>>,
    processor_handle: Option<thread::JoinHandle<()>>,
    is_running: Arc<AtomicBool>,
    packet_cache_limit: CacheLimit,

    // Statistics
    protocol_counts: Arc<Mutex<HashMap<String, u64>>>,
    time_series: HashMap<String, VecDeque<[f64; 2]>>,
    start_time: Instant,
    last_update: Instant,
    active_chart: ChartView,
}

impl Default for WireCrabApp {
    fn default() -> Self {
        Self {
            active_tab: Tab::Capture,
            devices: device::list_devices().unwrap_or_default(),
            selected_device_index: None,
            is_capturing: false,
            protocol_filter: String::new(),
            src_ip_filter: String::new(),
            dst_ip_filter: String::new(),
            src_port_filter: String::new(),
            dst_port_filter: String::new(),
            port_filter: String::new(),
            packets: Arc::new(Mutex::new(VecDeque::new())),
            filtered_packets: Vec::new(),
            active_filter: None,
            selected_packet_index: None,
            capture_handle: None,
            processor_handle: None,
            is_running: Arc::new(AtomicBool::new(false)),
            packet_cache_limit: CacheLimit::Unlimited,
            protocol_counts: Arc::new(Mutex::new(HashMap::new())),
            time_series: HashMap::new(),
            start_time: Instant::now(),
            last_update: Instant::now(),
            active_chart: ChartView::Line,
        }
    }
}

impl App for WireCrabApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut Frame) {
        if self.is_capturing {
            ctx.request_repaint();
        }
        
        egui::TopBottomPanel::top("tabs").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.active_tab, Tab::Capture, "Capture");
                ui.selectable_value(&mut self.active_tab, Tab::Statistics, "Statistics");
            });
        });

        match self.active_tab {
            Tab::Capture => {
                self.show_capture_tab(ctx);
            }
            Tab::Statistics => {
                self.show_statistics_tab(ctx);
            }
        }
    }
}

impl WireCrabApp {
    fn show_capture_tab(&mut self, ctx: &egui::Context) {
        // 顶部控制面板
        egui::TopBottomPanel::top("capture_controls").show(ctx, |ui| {
            ui.horizontal(|ui| {
                // 网络适配器选择
                egui::ComboBox::from_label("Interface")
                    .selected_text(
                        self.selected_device_index
                            .map(|i| self.devices[i].name.clone())
                            .unwrap_or_else(|| "Select an adapter".to_string()),
                    )
                    .show_ui(ui, |ui| {
                        for (i, device) in self.devices.iter().enumerate() {
                            let response = ui.selectable_value(
                                &mut self.selected_device_index,
                                Some(i),
                                &device.name,
                            );
                            let mut hover_text = device.desc.as_ref().cloned().unwrap_or_else(|| "No description".to_string());
                            for addr in &device.addresses {
                                hover_text.push_str(&format!("\nAddress: {}", addr.addr));
                                if let Some(netmask) = addr.netmask {
                                    hover_text.push_str(&format!("\n  Mask: {}", netmask));
                                }
                            }
                            response.clone().on_hover_text(hover_text);
                            if response.changed() {
                                if let Ok(mut packets) = self.packets.lock() {
                                    packets.clear();
                                }
                                self.selected_packet_index = None;
                            }
                        }
                    });

                // 开始/停止捕获按钮
                if self.is_capturing {
                    if ui.button("Stop Capture").clicked() {
                        self.is_capturing = false;
                        self.is_running.store(false, Ordering::Relaxed);
                        if let Some(handle) = self.capture_handle.take() {
                            handle.join().unwrap();
                        }
                        if let Some(handle) = self.processor_handle.take() {
                            handle.join().unwrap();
                        }
                    }
                } else {
                    if ui.button("Start Capture").clicked() {
                        if let Some(index) = self.selected_device_index {
                            self.is_capturing = true;
                            self.is_running.store(true, Ordering::Relaxed);
                            let (raw_tx, raw_rx) = mpsc::channel();
                            let device_name = self.devices[index].name.clone();
                            let is_running_capture = self.is_running.clone();
                            
                            self.capture_handle = Some(thread::spawn(move || {
                                let mut capture = PacketCapture::new(device_name);
                                if let Err(e) = capture.init() {
                                    eprintln!("Failed to initialize capture: {}", e);
                                    return;
                                }
                                if let Err(e) = capture.start_capture(raw_tx) {
                                    eprintln!("Failed to start capture: {}", e);
                                }
                            }));

                            let is_running_processor = self.is_running.clone();
                            let packets_clone = self.packets.clone();
                            let protocol_counts_clone = self.protocol_counts.clone();
                            self.processor_handle = Some(thread::spawn(move || {
                                let processor = PacketProcessor::new(is_running_processor, raw_rx, packets_clone, protocol_counts_clone);
                                processor.run();
                            }));
                        }
                    }
                }
                if ui.button("Clear").clicked() {
                    if let Ok(mut packets) = self.packets.lock() {
                        packets.clear();
                    }
                    self.filtered_packets.clear();
                    self.selected_packet_index = None;
                    if let Ok(mut counts) = self.protocol_counts.lock() {
                        counts.clear();
                    }
                    self.time_series.clear();
                }

                ui.separator();

                egui::ComboBox::from_label("Cache")
                    .selected_text(self.packet_cache_limit.to_string())
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.packet_cache_limit, CacheLimit::Unlimited, "Unlimited");
                        ui.selectable_value(&mut self.packet_cache_limit, CacheLimit::Limit(50), "50");
                        ui.selectable_value(&mut self.packet_cache_limit, CacheLimit::Limit(100), "100");
                        ui.selectable_value(&mut self.packet_cache_limit, CacheLimit::Limit(500), "500");
                        ui.selectable_value(&mut self.packet_cache_limit, CacheLimit::Limit(1000), "1000");
                    });
            });
            
            // 过滤器输入
            ui.group(|ui| {
                ui.horizontal(|ui| {
                    ui.heading("Filter Options");

                    egui::ComboBox::from_label("Protocol")
                        .selected_text(if self.protocol_filter.is_empty() { "Any" } else { &self.protocol_filter })
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut self.protocol_filter, "".to_string(), "Any");
                            ui.selectable_value(&mut self.protocol_filter, "tcp".to_string(), "TCP");
                            ui.selectable_value(&mut self.protocol_filter, "udp".to_string(), "UDP");
                            ui.selectable_value(&mut self.protocol_filter, "arp".to_string(), "ARP");
                            ui.selectable_value(&mut self.protocol_filter, "ipv4".to_string(), "IPv4");
                            ui.selectable_value(&mut self.protocol_filter, "ipv6".to_string(), "IPv6");
                            ui.selectable_value(&mut self.protocol_filter, "icmp".to_string(), "ICMP");
                            ui.selectable_value(&mut self.protocol_filter, "igmp".to_string(), "IGMP");
                            ui.selectable_value(&mut self.protocol_filter, "http".to_string(), "HTTP");
                            ui.selectable_value(&mut self.protocol_filter, "https".to_string(), "HTTPS");
                            ui.selectable_value(&mut self.protocol_filter, "dns".to_string(), "DNS");
                        });

                    ui.label("Src IP:");
                    ui.add(egui::TextEdit::singleline(&mut self.src_ip_filter).desired_width(150.0));
                    ui.label("Dst IP:");
                    ui.add(egui::TextEdit::singleline(&mut self.dst_ip_filter).desired_width(150.0));
                    ui.label("Src Port:");
                    ui.add(egui::TextEdit::singleline(&mut self.src_port_filter).desired_width(60.0));
                    ui.label("Dst Port:");
                    ui.add(egui::TextEdit::singleline(&mut self.dst_port_filter).desired_width(60.0));
                    ui.label("Port:");
                    ui.add(egui::TextEdit::singleline(&mut self.port_filter).desired_width(60.0));

                    if ui.button("Apply").clicked() {
                        let protocol = if self.protocol_filter.is_empty() { None } else { Some(self.protocol_filter.clone()) };
                        let src_ip = IpAddr::from_str(&self.src_ip_filter).ok();
                        let dst_ip = IpAddr::from_str(&self.dst_ip_filter).ok();
                        let src_port = self.src_port_filter.parse::<u16>().ok();
                        let dst_port = self.dst_port_filter.parse::<u16>().ok();
                        let port = self.port_filter.parse::<u16>().ok();

                        let filter = PacketFilter::new(protocol, src_ip, dst_ip, src_port, dst_port, port);
                        self.active_filter = Some(filter);
                        self.apply_filter();
                    }
                    if ui.button("Clear").clicked() {
                        self.protocol_filter.clear();
                        self.src_ip_filter.clear();
                        self.dst_ip_filter.clear();
                        self.src_port_filter.clear();
                        self.dst_port_filter.clear();
                        self.port_filter.clear();
                        self.active_filter = None;
                        self.apply_filter();
                    }
                });
            });
        });

        // 左侧面板（数据包列表）
        egui::SidePanel::left("left_panel")
            .resizable(true)
            .show(ctx, |ui| {
                let table = TableBuilder::new(ui)
                    .striped(true)
                    .resizable(true)
                    .column(Column::exact(120.0))
                    .column(Column::exact(150.0))
                    .column(Column::exact(150.0))
                    .column(Column::exact(80.0))
                    .column(Column::exact(70.0))
                    .sense(egui::Sense::click());

                table
                    .header(20.0, |mut header| {
                        header.col(|ui| { ui.strong("Timestamp"); });
                        header.col(|ui| { ui.strong("Source"); });
                        header.col(|ui| { ui.strong("Destination"); });
                        header.col(|ui| { ui.strong("Protocol"); });
                        header.col(|ui| { ui.strong("Length"); });
                    })
                    .body(|mut body| {
                        let packets = self.packets.lock().unwrap();
                        let row_height = 18.0;
                        let num_rows = if self.active_filter.is_some() {
                            self.filtered_packets.len()
                        } else {
                            packets.len()
                        };

                        body.rows(row_height, num_rows, |mut row| {
                            let row_index = row.index();
                            let (packet_index, packet) = if let Some(filter) = &self.active_filter {
                                let packet_idx = self.filtered_packets[row_index];
                                (packet_idx, &packets[packet_idx])
                            } else {
                                (row_index, &packets[row_index])
                            };

                            let is_selected = self.selected_packet_index == Some(packet_index);
                            row.set_selected(is_selected);
                            
                            row.col(|ui| {
                                ui.label(packet.timestamp.format("%H:%M:%S").to_string());
                            });
                            row.col(|ui| {
                                ui.label(
                                    packet.network_layer.as_ref().map_or("N/A", |l| match l {
                                        crate::parser::NetworkLayer::IPv4 { src_ip, .. } => src_ip.as_str(),
                                        crate::parser::NetworkLayer::IPv6 { src_ip, .. } => src_ip.as_str(),
                                        crate::parser::NetworkLayer::ARP { sender_mac, .. } => sender_mac.as_str(),
                                        _ => "N/A",
                                    }),
                                );
                            });
                            row.col(|ui| {
                                ui.label(
                                    packet.network_layer.as_ref().map_or("N/A", |l| match l {
                                        crate::parser::NetworkLayer::IPv4 { dst_ip, .. } => dst_ip.as_str(),
                                        crate::parser::NetworkLayer::IPv6 { dst_ip, .. } => dst_ip.as_str(),
                                        crate::parser::NetworkLayer::ARP { target_mac, .. } => target_mac.as_str(),
                                        _ => "N/A",
                                    }),
                                );
                            });
                            row.col(|ui| {
                                let protocol = if let Some(transport) = &packet.transport_layer {
                                    transport.name().to_string()
                                } else if let Some(network) = &packet.network_layer {
                                    match network {
                                        crate::parser::NetworkLayer::ARP { .. } => "ARP".to_string(),
                                        crate::parser::NetworkLayer::IPv4 { .. } => "IPv4".to_string(),
                                        crate::parser::NetworkLayer::IPv6 { .. } => "IPv6".to_string(),
                                        _ => "N/A".to_string(),
                                    }
                                } else {
                                    "N/A".to_string()
                                };
                                ui.label(protocol);
                            });
                            row.col(|ui| {
                                ui.label(packet.length.to_string());
                            });

                            if row.response().clicked() {
                                self.selected_packet_index = if is_selected { None } else { Some(packet_index) };
                            }
                        });
                    });
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            if let Some(index) = self.selected_packet_index {
                let packets = self.packets.lock().unwrap();
                if let Some(packet) = packets.get(index) {
                    let available_height = ui.available_height();
                    let available_width = ui.available_width();
                    
                    // Details view
                    egui::Frame::group(ui.style()).show(ui, |ui| {
                        ui.set_min_width(available_width);
                        egui::ScrollArea::vertical()
                            .id_salt("details_scroll")
                            .max_height(available_height * 0.5 - 5.0) // Allocate space, minus separator
                            .show(ui, |ui| {
                                let json_value = serde_json::to_value(packet).unwrap_or_default();
                                JsonTree::new("packet_details", &json_value)
                                    .show(ui);
                            });
                    });

                    ui.separator();

                    // Raw data view
                    egui::Frame::group(ui.style()).show(ui, |ui| {
                        ui.set_min_width(available_width);
                        ui.monospace("Offset    00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F  ASCII");
                        ui.separator();
                        egui::ScrollArea::vertical()
                            .id_salt("raw_data_scroll")
                            .show(ui, |ui| {
                                for (i, chunk) in packet.raw_data.chunks(16).enumerate() {
                                    let offset = i * 16;
                                    let hex = chunk.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
                                    let ascii: String = chunk.iter().map(|&b| if b.is_ascii_graphic() { b as char } else { '.' }).collect();
                                    ui.monospace(format!("{:08x}  {:<48} {}", offset, hex, ascii));
                                }
                            });
                    });
                }
            } else {
                ui.label("Select a packet to view details.");
            }
        });
    }

    fn show_statistics_tab(&mut self, ctx: &egui::Context) {
        if self.last_update.elapsed().as_secs_f32() > 1.0 {
            let now = self.start_time.elapsed().as_secs_f64();
            if let Ok(counts) = self.protocol_counts.lock() {
                for (protocol, count) in counts.iter() {
                    let series = self.time_series.entry(protocol.clone()).or_default();
                    series.push_back([now, *count as f64]);
                    if series.len() > 100 { // Keep a limited history
                        series.pop_front();
                    }
                }
            }
            self.last_update = Instant::now();
            ctx.request_repaint();
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Protocol Statistics");

            let plot = Plot::new("protocol_stats")
                .legend(Legend::default())
                .height(ui.available_height() - 100.0);

            plot.show(ui, |plot_ui| {
                for (protocol, series) in &self.time_series {
                    if !series.is_empty() {
                        let points = series.iter().copied().collect::<Vec<_>>();
                        let line = Line::new(protocol, points);
                        plot_ui.line(line);
                    }
                }
            });
        });
    }
    fn apply_filter(&mut self) {
        self.filtered_packets.clear();
        if let Some(filter) = &self.active_filter {
            let packets = self.packets.lock().unwrap();
            for (i, packet) in packets.iter().enumerate() {
                if filter.matches(packet) {
                    self.filtered_packets.push(i);
                }
            }
        }
        self.selected_packet_index = None;
    }
}
