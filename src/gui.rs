use eframe::{egui, App, Frame};
use pcap::Device;
use crate::{capture::{device, PacketCapture}, parser::{ParsedPacket, PacketParser}, create_formatter, OutputFormat};
use std::sync::{mpsc, Arc, atomic::{AtomicBool, Ordering}};
use std::thread;
use egui_extras::{TableBuilder, Column};
use std::collections::VecDeque;

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

pub struct WireCrabApp {
    active_tab: Tab,
    devices: Vec<Device>,
    selected_device_index: Option<usize>,
    is_capturing: bool,
    filter_text: String,
    packets: VecDeque<ParsedPacket>,
    selected_packet_index: Option<usize>,
    packet_receiver: Option<mpsc::Receiver<ParsedPacket>>,
    capture_handle: Option<thread::JoinHandle<()>>,
    is_running: Arc<AtomicBool>,
    packet_cache_limit: CacheLimit,
}

impl Default for WireCrabApp {
    fn default() -> Self {
        Self {
            active_tab: Tab::Capture,
            devices: device::list_devices().unwrap_or_default(),
            selected_device_index: None,
            is_capturing: false,
            filter_text: String::new(),
            packets: VecDeque::new(),
            selected_packet_index: None,
            packet_receiver: None,
            capture_handle: None,
            is_running: Arc::new(AtomicBool::new(false)),
            packet_cache_limit: CacheLimit::Limit(50),
        }
    }
}

impl App for WireCrabApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut Frame) {
        if let Some(rx) = &self.packet_receiver {
            while let Ok(packet) = rx.try_recv() {
                self.packets.push_back(packet);
                if let CacheLimit::Limit(limit) = self.packet_cache_limit {
                    if self.packets.len() > limit {
                        self.packets.pop_front();
                        if let Some(selected) = self.selected_packet_index {
                            if selected > 0 {
                                self.selected_packet_index = Some(selected - 1);
                            } else {
                                self.selected_packet_index = None;
                            }
                        }
                    }
                }
            }
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
        let formatter = create_formatter(OutputFormat::Json);
 
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
                            response.clone().on_hover_text(
                                device
                                    .desc
                                    .as_ref()
                                    .unwrap_or(&"No description".to_string()),
                            );
                            if response.changed() {
                                self.packets.clear();
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
                    }
                } else {
                    if ui.button("Start Capture").clicked() {
                        if let Some(index) = self.selected_device_index {
                            self.is_capturing = true;
                            self.is_running.store(true, Ordering::Relaxed);
                            let (tx, rx) = mpsc::channel();
                            self.packet_receiver = Some(rx);
                            let device_name = self.devices[index].name.clone();
                            let is_running = self.is_running.clone();

                            self.capture_handle = Some(thread::spawn(move || {
                                let mut capture = PacketCapture::new(device_name);
                                if let Err(e) = capture.init() {
                                    eprintln!("Failed to initialize capture: {}", e);
                                    return;
                                }
                                let (raw_tx, raw_rx) = mpsc::channel();
                                let capture_thread = thread::spawn(move || {
                                    if let Err(e) = capture.start_capture(raw_tx) {
                                        eprintln!("Failed to start capture: {}", e);
                                    }
                                });

                                let mut parser = PacketParser::new();
                                while is_running.load(Ordering::Relaxed) {
                                    if let Ok(packet) = raw_rx.try_recv() {
                                        let timestamp = chrono::Utc::now();
                                        match parser.parse_packet(&packet.data, timestamp, packet.interface) {
                                            Ok(parsed_packet) => {
                                                if tx.send(parsed_packet).is_err() {
                                                    break;
                                                }
                                            }
                                            Err(e) => {
                                                eprintln!("Failed to parse packet: {}", e);
                                            }
                                        }
                                    }
                                }
                                // capture_thread.join().unwrap();
                            }));
                        }
                    }
                }
                if ui.button("Clear").clicked() {
                    self.packets.clear();
                    self.selected_packet_index = None;
                }

                ui.separator();

                egui::ComboBox::from_label("Cache")
                    .selected_text(self.packet_cache_limit.to_string())
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.packet_cache_limit, CacheLimit::Limit(50), "50");
                        ui.selectable_value(&mut self.packet_cache_limit, CacheLimit::Limit(100), "100");
                        ui.selectable_value(&mut self.packet_cache_limit, CacheLimit::Limit(500), "500");
                        ui.selectable_value(&mut self.packet_cache_limit, CacheLimit::Limit(1000), "1000");
                        ui.selectable_value(&mut self.packet_cache_limit, CacheLimit::Unlimited, "Unlimited");
                    });
            });
            
            // 过滤器输入
            ui.add(egui::TextEdit::singleline(&mut self.filter_text).hint_text("Enter filter..."));
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
                        for (i, packet) in self.packets.iter().enumerate() {
                            let is_selected = self.selected_packet_index == Some(i);
                            body.row(18.0, |mut row| {
                                row.set_selected(is_selected);
                                row.col(|ui| { ui.label(packet.timestamp.format("%H:%M:%S").to_string()); });
                                row.col(|ui| {
                                    ui.label(packet.network_layer.as_ref().map_or("N/A", |l| match l {
                                        crate::parser::NetworkLayer::IPv4 { src_ip, .. } => src_ip,
                                        crate::parser::NetworkLayer::IPv6 { src_ip, .. } => src_ip,
                                        _ => "N/A",
                                    }));
                                });
                                row.col(|ui| {
                                    ui.label(packet.network_layer.as_ref().map_or("N/A", |l| match l {
                                        crate::parser::NetworkLayer::IPv4 { dst_ip, .. } => dst_ip,
                                        crate::parser::NetworkLayer::IPv6 { dst_ip, .. } => dst_ip,
                                        _ => "N/A",
                                    }));
                                });
                                row.col(|ui| { ui.label(packet.transport_layer.as_ref().map_or("N/A", |l| l.name())); });
                                row.col(|ui| { ui.label(packet.length.to_string()); });
                                
                                if row.response().clicked() {
                                    self.selected_packet_index = if is_selected {
                                        None
                                    } else {
                                        Some(i)
                                    };
                                }
                            });
                        }
                    });
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            if let Some(index) = self.selected_packet_index {
                if let Some(packet) = self.packets.get(index) {
                    let available_height = ui.available_height();
                    let available_width = ui.available_width();
                    
                    // Details view
                    egui::Frame::group(ui.style()).show(ui, |ui| {
                        ui.set_min_width(available_width);
                        egui::ScrollArea::vertical()
                            .id_salt("details_scroll")
                            .max_height(available_height * 0.5 - 5.0) // Allocate space, minus separator
                            .show(ui, |ui| {
                                ui.label(formatter.format_packet(packet).unwrap_or("Failed to format packet".to_string()));
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
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Statistics");
            ui.label("This feature is not yet implemented.");
        });
    }
}