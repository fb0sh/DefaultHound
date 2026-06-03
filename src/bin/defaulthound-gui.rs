//! # DefaultHound GUI
//!
//! 三栏布局 (egui):
//! - Panel A (左): 目标管理
//! - Panel B (中): 扫描结果（实时日志 + 漏洞表格 双视图）
//! - Panel C (右): 详情/统计
//!
//! 使用 eframe/egui，零系统依赖。

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use defaulthound::CheckResult;
use defaulthound::checkers;

// ─────────────────────────────────────────────
// 共享扫描状态（跨线程）
// ─────────────────────────────────────────────

#[derive(Clone, serde::Serialize)]
struct ScanEntry {
    service: String,
    ip: String,
    port: u16,
    status: &'static str,
    detail: String,
    vulnerable: bool,
    timestamp: String,
}

struct ScanState {
    is_scanning: AtomicBool,
    stop_requested: AtomicBool,
    progress_current: AtomicUsize,
    progress_total: AtomicUsize,
    results: Mutex<Vec<ScanEntry>>,
}

unsafe impl Send for ScanState {}
unsafe impl Sync for ScanState {}

impl ScanState {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            is_scanning: AtomicBool::new(false),
            stop_requested: AtomicBool::new(false),
            progress_current: AtomicUsize::new(0),
            progress_total: AtomicUsize::new(0),
            results: Mutex::new(Vec::new()),
        })
    }
}

fn timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let s = d.as_secs();
    format!("{:02}:{:02}:{:02}", (s / 3600) % 24, (s / 60) % 60, s % 60)
}

// ─────────────────────────────────────────────
// 主应用
// ─────────────────────────────────────────────

#[derive(PartialEq)]
enum ViewMode {
    Log,
    VulnTable,
}

struct TargetRow {
    raw: String,
    enabled: bool,
}

pub struct DefaultHoundApp {
    // 目标
    targets: Vec<TargetRow>,
    target_input: String,

    // 扫描
    scan_state: Arc<ScanState>,
    rate: usize,

    // 视图
    view_mode: ViewMode,
    vuln_only: bool,
    search_text: String,

    // ── 主题 ──
    dark_mode: bool,

    // UI 线程缓存
    cached_results: Vec<ScanEntry>,
    cached_progress: (usize, usize),
    cached_scanning: bool,
}

impl DefaultHoundApp {
    pub fn new() -> Self {
        Self {
            targets: vec![TargetRow {
                raw: "127.0.0.1".into(),
                enabled: true,
            }],
            target_input: String::new(),
            scan_state: ScanState::new(),
            rate: 30,
            view_mode: ViewMode::Log,
            vuln_only: false,
            search_text: String::new(),
            dark_mode: false,
            cached_results: vec![],
            cached_progress: (0, 0),
            cached_scanning: false,
        }
    }

    fn sync_cache(&mut self) {
        let s = &self.scan_state;
        if let Ok(results) = s.results.lock() {
            self.cached_results = results.clone();
        }
        self.cached_progress = (
            s.progress_current.load(Ordering::Acquire),
            s.progress_total.load(Ordering::Acquire),
        );
        self.cached_scanning = s.is_scanning.load(Ordering::Acquire);
    }

    fn vuln_results(&self) -> impl Iterator<Item = &ScanEntry> {
        self.cached_results.iter().filter(|e| e.vulnerable)
    }

    fn stop_scan(&mut self) {
        self.scan_state
            .stop_requested
            .store(true, Ordering::Release);
    }

    fn start_scan(&mut self) {
        if self.cached_scanning {
            return;
        }
        let targets: Vec<String> = self
            .targets
            .iter()
            .filter(|t| t.enabled)
            .map(|t| t.raw.clone())
            .collect();
        if targets.is_empty() {
            return;
        }

        let state = self.scan_state.clone();
        let rate = self.rate;
        state.is_scanning.store(true, Ordering::Release);
        state.stop_requested.store(false, Ordering::Release);
        state.progress_current.store(0, Ordering::Release);
        if let Ok(mut results) = state.results.lock() {
            results.clear();
        }

        let checkers = checkers::all_checkers();
        let total_checks = targets.len() * checkers.len();
        state.progress_total.store(total_checks, Ordering::Release);

        tokio::spawn(async move {
            // 构建所有任务（同 CLI 的 flat_map 模式）
            let mut tasks = Vec::new();
            for target_line in &targets {
                let parsed = parse_target_line(target_line);
                let (service_filter, ip, ports) = match parsed {
                    Some(p) => p,
                    None => continue,
                };
                for checker in &checkers {
                    let svc = checker.service_name().to_lowercase();
                    if let Some(ref filter) = service_filter {
                        if filter != &svc {
                            continue;
                        }
                    }
                    let check_ports = if ports.is_empty() {
                        vec![checker.default_port()]
                    } else {
                        ports.clone()
                    };
                    for port in check_ports {
                        let ip = ip.clone();
                        let svc_name = checker.service_name().to_string();
                        tasks.push(async move {
                            let result = checker.check(&ip, Some(port)).await;
                            (svc_name, ip, port, result)
                        });
                    }
                }
            }

            // 更新总数（实际任务数）
            let actual_total = tasks.len();
            state.progress_total.store(actual_total, Ordering::Release);

            // 并发执行（同 CLI 的 buffer_unordered）
            use futures::StreamExt;
            let stream = futures::stream::iter(tasks).buffer_unordered(rate);
            tokio::pin!(stream);

            while let Some((svc_name, ip, port, result)) = stream.next().await {
                if state.stop_requested.load(Ordering::Acquire) {
                    break;
                }

                let ts = timestamp();
                let entry = match &result {
                    CheckResult::Secure(reason) => ScanEntry {
                        service: svc_name,
                        ip,
                        port,
                        status: "安全",
                        detail: reason.clone(),
                        vulnerable: false,
                        timestamp: ts,
                    },
                    CheckResult::Vulnerable {
                        credentials,
                        details,
                    } => ScanEntry {
                        service: svc_name,
                        ip,
                        port,
                        status: "高危",
                        detail: format!("凭据「{}」: {}", credentials, details),
                        vulnerable: true,
                        timestamp: ts,
                    },
                    CheckResult::Error(e) => ScanEntry {
                        service: svc_name,
                        ip,
                        port,
                        status: "错误",
                        detail: e.clone(),
                        vulnerable: false,
                        timestamp: ts,
                    },
                };
                if let Ok(mut results) = state.results.lock() {
                    results.push(entry);
                }
                state.progress_current.fetch_add(1, Ordering::Release);
            }
            state.is_scanning.store(false, Ordering::Release);
        });
    }
}

/// 解析目标行，返回 (service_filter, ip, ports)
///
/// 支持格式:
/// - `ip`                         所有服务使用默认端口
/// - `ip:port`                    所有服务使用指定端口
/// - `ip:port1,port2`             所有服务使用多个端口
/// - `service^ip`                 指定服务，默认端口
/// - `service^ip:port`            指定服务 + 端口
/// - `ip:service^port`            指定服务 + 端口（等同上一行）
/// - `ip:service^`                指定服务，默认端口
fn parse_target_line(line: &str) -> Option<(Option<String>, String, Vec<u16>)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }

    if let Some(caret_pos) = line.find('^') {
        let (left, right) = (&line[..caret_pos], &line[caret_pos + 1..]);

        // `:` 在 `^` 之前 → 格式: ip:service^port
        if let Some(colon_pos) = left.rfind(':') {
            let ip = left[..colon_pos].trim().to_string();
            let service = left[colon_pos + 1..].trim().to_lowercase();
            let ports: Vec<u16> = if right.is_empty() {
                vec![]
            } else {
                right
                    .split(',')
                    .filter_map(|p| p.trim().parse().ok())
                    .collect()
            };
            Some((Some(service), ip, ports))
        } else {
            // 格式: service^ip 或 service^ip:port
            let service = left.trim().to_lowercase();
            if let Some((ip, port_part)) = right.split_once(':') {
                let ports: Vec<u16> = port_part
                    .split(',')
                    .filter_map(|p| p.trim().parse().ok())
                    .collect();
                Some((Some(service), ip.to_string(), ports))
            } else {
                Some((Some(service), right.to_string(), vec![]))
            }
        }
    } else {
        // 无 `^`：纯 ip 或 ip:port 格式
        if let Some((ip, port_part)) = line.split_once(':') {
            let ports: Vec<u16> = port_part
                .split(',')
                .filter_map(|p| p.trim().parse().ok())
                .collect();
            Some((None, ip.to_string(), ports))
        } else {
            Some((None, line.to_string(), vec![]))
        }
    }
}

// ─────────────────────────────────────────────
// eframe::App 实现
// ─────────────────────────────────────────────

impl eframe::App for DefaultHoundApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.sync_cache();

        // ── macOS 窗口快捷键透传 ──
        // 让 Cmd+W（关闭）、Cmd+M（最小化）等系统快捷键不被 egui 拦截
        #[cfg(target_os = "macos")]
        {
            use egui::Key;
            let input = ctx.input(|i| {
                (
                    i.modifiers.command,
                    i.key_pressed(Key::W),
                    i.key_pressed(Key::M),
                    i.key_pressed(Key::Q),
                )
            });
            let (cmd, w, m, q) = input;
            if cmd && w {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            if cmd && m {
                ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true));
            }
            if cmd && q {
                // Cmd+Q 由 macOS 原生处理，这里确保不拦截
            }
        }

        // ── 应用主题 ──
        if self.dark_mode {
            ctx.set_visuals(egui::Visuals::dark());
        } else {
            ctx.set_visuals(egui::Visuals::light());
        }

        if self.cached_scanning {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }

        // ── 顶部控制栏 ──
        egui::TopBottomPanel::top("control_bar")
            .min_height(40.0)
            .show(ctx, |ui| {
                egui::ScrollArea::horizontal().show(ui, |ui| {
                    ui.horizontal(|ui| {
                        if self.cached_scanning {
                            ui.spinner();
                            ui.label("Scanning...");
                            if ui.button("Stop").clicked() {
                                self.stop_scan();
                            }
                        } else {
                            if ui.button("> Start Scan").clicked() {
                                self.start_scan();
                            }
                        }

                        ui.separator();

                        let log_label = format!("Log ({})", self.cached_results.len());
                        if ui
                            .selectable_label(self.view_mode == ViewMode::Log, log_label)
                            .clicked()
                        {
                            self.view_mode = ViewMode::Log;
                        }
                        let vc = self.vuln_results().count();
                        let vuln_label = format!("Vulns ({vc})");
                        if ui
                            .selectable_label(self.view_mode == ViewMode::VulnTable, vuln_label)
                            .clicked()
                        {
                            self.view_mode = ViewMode::VulnTable;
                        }

                        ui.separator();

                        if ui.button("Clear").clicked() {
                            self.cached_results.clear();
                            self.scan_state.results.lock().unwrap().clear();
                            self.scan_state.progress_current.store(0, Ordering::Release);
                            self.scan_state.progress_total.store(0, Ordering::Release);
                        }
                        if ui.button("Export CSV").clicked() {
                            if let Some(path) = rfd::FileDialog::new()
                                .add_filter("CSV", &["csv"])
                                .set_file_name("defaulthound_results.csv")
                                .save_file()
                            {
                                let results = self.cached_results.clone();
                                if let Ok(mut wtr) = csv::Writer::from_path(&path) {
                                    let _ = wtr.write_record([
                                        "service",
                                        "ip",
                                        "port",
                                        "status",
                                        "detail",
                                        "vulnerable",
                                    ]);
                                    for e in &results {
                                        let _ = wtr.write_record([
                                            &e.service,
                                            &e.ip,
                                            &e.port.to_string(),
                                            e.status,
                                            &e.detail,
                                            &e.vulnerable.to_string(),
                                        ]);
                                    }
                                    let _ = wtr.flush();
                                }
                            }
                        }

                        ui.toggle_value(&mut self.vuln_only, "Vulns only");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.search_text)
                                .hint_text("Search...")
                                .desired_width(150.0),
                        );

                        ui.separator();
                        let label = if self.dark_mode { "Night" } else { "Light" };
                        if ui.button(label).on_hover_text("Toggle theme").clicked() {
                            self.dark_mode = !self.dark_mode;
                        }
                    });
                });
            });

        // ── 左侧：目标管理 ──
        egui::SidePanel::left("target_panel")
            .resizable(true)
            .default_width(260.0)
            .min_width(180.0)
            .show(ctx, |ui| {
                ui.heading("Targets");
                ui.add_space(4.0);

                // 输入框只能上下拉动（高度可调，宽度固定）
                let avail_w = ui.available_width();
                egui::Resize::default()
                    .id_salt("target_input_resize")
                    .min_size(egui::vec2(avail_w, 80.0))
                    .max_size(egui::vec2(avail_w, f32::INFINITY))
                    .show(ui, |ui| {
                        ui.set_width(avail_w);
                        ui.add_sized(
                            ui.available_size(),
                            egui::TextEdit::multiline(&mut self.target_input)
                                .hint_text("172.20.0.2           # scan all services (default ports)\n172.20.0.2:11211    # scan specific port\n172.20.0.2:27017,3306 # scan multiple ports\n172.20.0.2:redis^5984   # Redis custom port\n172.20.0.2:redis^       # Redis default port"),
                        );
                    });
                ui.horizontal(|ui| {
                    if ui.button("+ Add").clicked() {
                        for line in self.target_input.lines() {
                            let line = line.trim();
                            if !line.is_empty() && !line.starts_with('#') {
                                self.targets.push(TargetRow { raw: line.to_string(), enabled: true });
                            }
                        }
                        self.target_input.clear();
                    }
                    if ui.button("Clear").clicked() {
                        self.targets.clear();
                    }
                });

                ui.add_space(8.0);
                ui.separator();
                ui.add_space(4.0);

                let total = self.targets.len();
                let enabled = self.targets.iter().filter(|t| t.enabled).count();

                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        let mut remove_idx: Option<usize> = None;
                        for (i, target) in self.targets.iter_mut().enumerate() {
                            let raw = target.raw.clone();
                            ui.horizontal(|ui| {
                                ui.checkbox(&mut target.enabled, "");
                                let lbl = ui.add(egui::Label::new(&raw).selectable(true));
                                lbl.context_menu(move |ui| {
                                    if ui.button("复制目标").clicked() {
                                        ui.ctx().copy_text(raw.clone());
                                        ui.close_menu();
                                    }
                                });
                                if ui.button("x").clicked() {
                                    remove_idx = Some(i);
                                }
                            });
                        }
                        if let Some(idx) = remove_idx {
                            self.targets.remove(idx);
                        }
                    });

                ui.add_space(4.0);
                ui.label(format!("Total: {total} | Active: {enabled}"));
            });

        // ── 右侧：详情/统计 ──
        egui::SidePanel::right("detail_panel")
            .resizable(false)
            .default_width(280.0)
            .min_width(200.0)
            .show(ctx, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    ui.heading("Statistics");
                    ui.add_space(8.0);

                    let vuln = self.vuln_results().count();
                    let secure = self
                        .cached_results
                        .iter()
                        .filter(|e| !e.vulnerable && e.status == "安全")
                        .count();
                    let err = self
                        .cached_results
                        .iter()
                        .filter(|e| e.status == "错误")
                        .count();
                    let total = self.cached_results.len();

                    let card =
                        |ui: &mut egui::Ui, label: &str, count: usize, color: egui::Color32| {
                            egui::Frame::NONE
                                .fill(color.linear_multiply(0.15))
                                .corner_radius(4.0)
                                .show(ui, |ui| {
                                    ui.horizontal(|ui| {
                                        ui.strong(label);
                                        ui.with_layout(
                                            egui::Layout::right_to_left(egui::Align::Center),
                                            |ui| {
                                                ui.colored_label(color, count.to_string());
                                            },
                                        );
                                    });
                                });
                        };

                    card(ui, "VULNERABLE", vuln, egui::Color32::RED);
                    card(ui, "Secure", secure, egui::Color32::from_rgb(0, 140, 0));

                    ui.add_space(8.0);
                    card(ui, "Error", err, egui::Color32::from_rgb(200, 120, 0));

                    ui.add_space(12.0);
                    ui.label(format!("Total checks: {total}"));

                    if self.cached_scanning {
                        ui.add_space(8.0);
                        ui.label("Scanning...");
                        let (cur, tot) = self.cached_progress;
                        if tot > 0 {
                            ui.add(
                                egui::ProgressBar::new(cur as f32 / tot as f32)
                                    .text(format!("{cur}/{tot}")),
                            );
                        }
                    }
                });
            });

        // ── 中央：扫描结果 ──
        egui::CentralPanel::default().show(ctx, |ui| match self.view_mode {
            ViewMode::Log => self.show_log_view(ui),
            ViewMode::VulnTable => self.show_vuln_table(ui),
        });

        // ── 底部状态栏 ──
        egui::TopBottomPanel::bottom("status_bar")
            .min_height(24.0)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    let (cur, tot) = self.cached_progress;
                    let vuln = self.vuln_results().count();

                    if self.cached_scanning && tot > 0 {
                        ui.add(
                            egui::ProgressBar::new(cur as f32 / tot as f32)
                                .desired_width(120.0)
                        );
                        ui.label(format!("{:.1}%", cur as f64 / tot as f64 * 100.0));
                    }

                    ui.label(format!("Checked: {cur}/{tot}"));
                    ui.colored_label(egui::Color32::RED, format!("Vulns: {vuln}"));
                    ui.label("Rate:");
                    ui.add(
                        egui::DragValue::new(&mut self.rate)
                            .range(1..=1000)
                            .speed(1.0)
                            .prefix(" ")
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label("DefaultHound v0.8.0 | <fb0sh@outlook.com> https://github.com/fb0sh/DefaultHound");
                    });
                });
            });
    }
}

// ── 视图渲染 ──

impl DefaultHoundApp {
    fn show_log_view(&self, ui: &mut egui::Ui) {
        let search = self.search_text.to_lowercase();
        let results: Vec<&ScanEntry> = self
            .cached_results
            .iter()
            .filter(|e| {
                if self.vuln_only && !e.vulnerable {
                    return false;
                }
                if search.is_empty() {
                    return true;
                }
                e.service.to_lowercase().contains(&search)
                    || e.ip.contains(&search)
                    || e.port.to_string().contains(&search)
            })
            .collect();

        if results.is_empty() {
            ui.vertical_centered(|ui| {
                ui.add_space(40.0);
                ui.label("No results yet. Click 'Start Scan' to begin.");
            });
            return;
        }

        egui::ScrollArea::vertical()
            .stick_to_bottom(true)
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for entry in results.iter().rev() {
                    let (color, prefix) = if entry.vulnerable {
                        (egui::Color32::RED, "[VULN]")
                    } else if entry.status == "错误" {
                        (egui::Color32::from_rgb(200, 120, 0), "[ERR]")
                    } else {
                        (egui::Color32::from_rgb(0, 140, 0), "[OK]")
                    };

                    let entry_ip = entry.ip.clone();
                    let entry_port = entry.port;
                    let entry_detail = entry.detail.clone();
                    let entry_service = entry.service.clone();

                    let inner = ui.horizontal(|ui| {
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(format!(
                                    "{prefix}[{entry_service}] {entry_ip}:{entry_port}"
                                ))
                                .color(color),
                            )
                            .selectable(true),
                        );
                        ui.add(egui::Label::new(&entry_detail).selectable(true));
                    });
                    inner.response.context_menu(move |ui| {
                        if ui.button("复制 IP:Port").clicked() {
                            ui.ctx().copy_text(format!("{entry_ip}:{entry_port}"));
                            ui.close_menu();
                        }
                        if ui.button("复制服务标识").clicked() {
                            ui.ctx().copy_text(format!(
                                "{prefix}[{entry_service}] {entry_ip}:{entry_port}  {entry_detail}"
                            ));
                            ui.close_menu();
                        }
                        if ui.button("复制详细信息").clicked() {
                            ui.ctx().copy_text(entry_detail.clone());
                            ui.close_menu();
                        }
                    });
                }
            });
    }

    fn show_vuln_table(&self, ui: &mut egui::Ui) {
        let vulns: Vec<&ScanEntry> = self.vuln_results().collect();

        if vulns.is_empty() {
            ui.vertical_centered(|ui| {
                ui.add_space(40.0);
                ui.label("No vulnerabilities found!");
            });
            return;
        }

        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                egui::Grid::new("vuln_table")
                    .striped(true)
                    .min_col_width(60.0)
                    .show(ui, |ui| {
                        ui.strong("Service");
                        ui.strong("IP");
                        ui.strong("Port");
                        ui.strong("Creds");
                        ui.strong("Detail");
                        ui.end_row();

                        for entry in &vulns {
                            let en_ip = entry.ip.clone();
                            let en_port = entry.port;
                            let en_svc = entry.service.clone();
                            let en_detail = entry.detail.clone();
                            let cred = entry
                                .detail
                                .split('»')
                                .next()
                                .unwrap_or(&entry.detail)
                                .to_string();

                            let svc_label = ui.add(
                                egui::Label::new(
                                    egui::RichText::new(&en_svc).color(egui::Color32::RED),
                                )
                                .selectable(true),
                            );
                            ui.add(egui::Label::new(&en_ip).selectable(true));
                            ui.add(egui::Label::new(en_port.to_string()).selectable(true));
                            ui.add(egui::Label::new(&cred).selectable(true));
                            ui.add(egui::Label::new(&en_detail).selectable(true));
                            ui.end_row();

                            svc_label.context_menu(move |ui| {
                                if ui.button("复制 IP:Port").clicked() {
                                    ui.ctx().copy_text(format!("{en_ip}:{en_port}"));
                                    ui.close_menu();
                                }
                                if ui.button("复制凭据").clicked() {
                                    ui.ctx().copy_text(cred.clone());
                                    ui.close_menu();
                                }
                                if ui.button("复制全部").clicked() {
                                    ui.ctx().copy_text(format!(
                                        "[{en_svc}] {en_ip}:{en_port} — {cred}"
                                    ));
                                    ui.close_menu();
                                }
                            });
                        }
                    });
            });
    }
}

// ─────────────────────────────────────────────
// 入口：配置中英文字体 + emoji 回退
// ─────────────────────────────────────────────

fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1280.0, 800.0])
            .with_min_inner_size([900.0, 600.0])
            .with_title("DefaultHound v0.8.0"),
        ..Default::default()
    };

    let rt = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");
    let _guard = rt.enter();

    eframe::run_native(
        "defaulthound-gui",
        options,
        Box::new(|cc| {
            // 配置字体：加载系统 emoji 和中文字体
            configure_fonts(&cc.egui_ctx);
            Ok(Box::new(DefaultHoundApp::new()))
        }),
    )
}

fn configure_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();

    // 先试系统已有 TTC 字体（取第一字重），再试其他路径
    let cjk_candidates: &[&str] = &[
        // macOS 常见中文字体路径
        "/System/Library/Fonts/STHeiti Medium.ttc",
        "/System/Library/Fonts/Hiragino Sans GB.ttc",
        "/System/Library/Fonts/STHeiti Light.ttc",
        "/System/Library/Fonts/Supplemental/Songti.ttc",
        // macOS AssetsV2 中的 PingFang
        "/System/Library/AssetsV2/com_apple_MobileAsset_Font8/86ba2c91f017a3749571a82f2c6d890ac7ffb2fb.asset/AssetData/PingFang.ttc",
        // Windows
        "C:\\Windows\\Fonts\\msyh.ttc",
        "C:\\Windows\\Fonts\\simsun.ttc",
        // Linux
        "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
        "/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttc",
        "/usr/share/fonts/noto-cjk/NotoSansCJK-Regular.ttc",
        "/usr/share/fonts/truetype/wqy/wqy-microhei.ttc",
        "/usr/share/fonts/truetype/droid/DroidSansFallbackFull.ttf",
    ];

    for path in cjk_candidates {
        if let Ok(data) = std::fs::read(path) {
            fonts
                .font_data
                .insert("cjk".into(), egui::FontData::from_owned(data).into());
            if let Some(family) = fonts.families.get_mut(&egui::FontFamily::Proportional) {
                family.push("cjk".into());
            }
            break;
        }
    }

    // Emoji 字体（各平台）
    let emoji_candidates: &[&str] = &[
        "/System/Library/Fonts/Apple Color Emoji.ttc",
        "C:\\Windows\\Fonts\\seguiemj.ttf",
        "/usr/share/fonts/truetype/noto/NotoColorEmoji.ttf",
        "/usr/share/fonts/noto/NotoColorEmoji.ttf",
    ];
    for path in emoji_candidates {
        if let Ok(data) = std::fs::read(path) {
            fonts
                .font_data
                .insert("emoji".into(), egui::FontData::from_owned(data).into());
            if let Some(family) = fonts.families.get_mut(&egui::FontFamily::Proportional) {
                family.push("emoji".into());
            }
            break;
        }
    }

    ctx.set_fonts(fonts);
}
