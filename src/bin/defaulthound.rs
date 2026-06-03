use std::collections::HashSet;
use std::io::{IsTerminal, Read};
use std::path::PathBuf;

use clap::Parser;
use futures::StreamExt;
use serde::Serialize;

use defaulthound::CheckResult;
use defaulthound::checkers;

const MAX_CONCURRENT: usize = 30;

// ── ANSI color helpers ──
/// Check if stdout is a terminal (for color output)
fn is_colorful() -> bool {
    std::io::stdout().is_terminal()
}

macro_rules! colored {
    ($code:expr, $s:expr) => {{
        if is_colorful() {
            format!("\x1b[{}m{}\x1b[0m", $code, $s)
        } else {
            $s.to_string()
        }
    }};
}

macro_rules! red {
    ($s:expr) => {
        colored!("31", $s)
    };
}
macro_rules! green {
    ($s:expr) => {
        colored!("32", $s)
    };
}
macro_rules! yellow {
    ($s:expr) => {
        colored!("33", $s)
    };
}
macro_rules! cyan {
    ($s:expr) => {
        colored!("36", $s)
    };
}
macro_rules! bold {
    ($s:expr) => {
        colored!("1", $s)
    };
}

#[derive(Parser)]
#[command(name = "defaulthound", version, about = "批量检测服务默认密码")]
struct Cli {
    /// 目标 IP（默认 localhost，使用 --file 时忽略此参数）
    ip: Option<String>,

    /// 从文件读取目标列表，每行一个 IP 或 IP:端口
    #[arg(short)]
    file: Option<PathBuf>,

    /// 从 stdin 读取目标列表（优先级低于 --file）
    #[arg(long)]
    stdin: bool,

    /// 输出 JSON 到文件
    #[arg(short)]
    json: Option<PathBuf>,

    /// 输出 CSV 到文件
    #[arg(long)]
    csv: Option<PathBuf>,

    /// 并发数，调高可加快扫描
    #[arg(short, long, default_value_t = MAX_CONCURRENT)]
    rate: usize,

    /// 列出所有可检测的服务
    #[arg(short, long)]
    list: bool,

    /// 仅显示高危结果
    #[arg(short = 'v', long = "vuln")]
    vuln_only: bool,
}

#[derive(Debug, Clone)]
struct Target {
    ip: String,
    ports: Vec<u16>,
    /// 如果指定，只扫描该服务（小写）
    service_filter: Option<String>,
}

#[derive(Debug, Serialize)]
struct ScanEntry {
    service: String,
    ip: String,
    port: u16,
    status: String,
    detail: String,
    vulnerable: bool,
}

/// 解析目标行，支持格式：
/// - `ip`                         所有服务使用默认端口
/// - `ip:port`                    所有服务使用指定端口
/// - `ip:port1,port2`             所有服务使用多个端口
/// - `redis^ip`                   Redis 使用默认端口
/// - `redis^ip:port`              Redis 使用指定端口
/// - `redis^ip:port1,port2`       Redis 使用多个端口
fn parse_targets(content: &str) -> Vec<Target> {
    let mut targets = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // 检查 service^target 格式
        let (service_filter, rest) = if let Some(pos) = line.find('^') {
            let svc = line[..pos].trim().to_lowercase();
            let rest = line[pos + 1..].trim();
            (Some(svc), rest)
        } else {
            (None, line)
        };

        if let Some((ip, port_part)) = rest.split_once(':') {
            let ports: Vec<u16> = port_part
                .split(',')
                .filter_map(|p| p.trim().parse().ok())
                .collect();
            targets.push(Target {
                ip: ip.to_string(),
                ports,
                service_filter,
            });
        } else {
            targets.push(Target {
                ip: rest.to_string(),
                ports: vec![],
                service_filter,
            });
        }
    }
    targets
}

fn export_csv(entries: &[ScanEntry], path: &PathBuf) -> anyhow::Result<()> {
    let mut wtr = csv::Writer::from_path(path)?;
    wtr.write_record(["service", "ip", "port", "status", "detail", "vulnerable"])?;
    for e in entries {
        wtr.write_record([
            &e.service,
            &e.ip,
            &e.port.to_string(),
            &e.status,
            &e.detail,
            &e.vulnerable.to_string(),
        ])?;
    }
    wtr.flush()?;
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let content = if let Some(path) = &cli.file {
        std::fs::read_to_string(path)?
    } else if cli.stdin || !std::io::stdin().is_terminal() {
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        buf
    } else {
        String::new()
    };

    let targets = if !content.is_empty() {
        parse_targets(&content)
    } else {
        let ip = cli.ip.unwrap_or_else(|| "127.0.0.1".into());
        vec![Target {
            ip,
            ports: vec![],
            service_filter: None,
        }]
    };

    let checkers = checkers::all_checkers();

    if cli.list {
        let mut services: Vec<_> = checkers
            .iter()
            .map(|c| (c.service_name(), c.default_port()))
            .collect();
        services.sort_by(|a, b| a.0.cmp(b.0));
        for (name, port) in services {
            println!("{:<20} {}", name, port);
        }
        return Ok(());
    }

    if targets.is_empty() {
        anyhow::bail!("没有有效的目标");
    }
    let mut results: Vec<ScanEntry> = Vec::new();
    let mut vuln_targets: HashSet<usize> = HashSet::new();

    let tasks = checkers.iter().flat_map(|checker| {
        let svc_name = checker.service_name().to_lowercase();
        targets
            .iter()
            .enumerate()
            .filter_map(move |(target_idx, target)| {
                // 如果指定了服务过滤，只运行匹配的服务
                if let Some(ref filter) = target.service_filter {
                    if *filter != svc_name {
                        return None;
                    }
                }
                let ports = if target.ports.is_empty() {
                    vec![checker.default_port()]
                } else {
                    target.ports.clone()
                };
                Some(ports.into_iter().map(move |port| {
                    let ip = target.ip.clone();
                    async move {
                        let result = checker.check(&ip, Some(port)).await;
                        (target_idx, checker.service_name(), ip, port, result)
                    }
                }))
            })
            .flatten()
    });

    let mut stream = futures::stream::iter(tasks).buffer_unordered(cli.rate);

    while let Some((target_idx, name, ip, port, result)) = stream.next().await {
        match result {
            CheckResult::Secure(reason) => {
                if !cli.vuln_only {
                    let tag = cyan!(&format!("[{name}]"));
                    let addr = bold!(&ip);
                    let port_str = cyan!(&port.to_string());
                    let status = green!("✓ 安全");
                    let detail = cyan!(&reason);
                    println!("{tag} {addr}:{port_str}  {status}  {detail}");
                }
                results.push(ScanEntry {
                    service: name.to_string(),
                    ip,
                    port,
                    status: "安全".into(),
                    detail: reason,
                    vulnerable: false,
                });
            }
            CheckResult::Vulnerable {
                credentials,
                details,
            } => {
                vuln_targets.insert(target_idx);
                let tag = red!(&format!("[VULN][{name}]({credentials})"));
                let addr = bold!(&ip);
                let port_str = red!(&port.to_string());
                let status = red!("⚠ 高危");
                let detail = cyan!(&details);
                println!("{tag} {addr}:{port_str}  {status}  {detail}");
                results.push(ScanEntry {
                    service: name.to_string(),
                    ip,
                    port,
                    status: "高危".into(),
                    detail: format!("凭据「{credentials}」: {details}"),
                    vulnerable: true,
                });
            }
            CheckResult::Error(e) => {
                if !cli.vuln_only {
                    let tag = yellow!(&format!("[ERR][{name}]"));
                    let addr = bold!(&ip);
                    let port_str = yellow!(&port.to_string());
                    let msg = yellow!(&format!("⚠ {e}"));
                    println!("{tag} {addr}:{port_str}  {msg}");
                }
                results.push(ScanEntry {
                    service: name.to_string(),
                    ip,
                    port,
                    status: "错误".into(),
                    detail: e,
                    vulnerable: false,
                });
            }
        }
    }

    let target_count = targets.len();
    let vuln_count = vuln_targets.len();
    let secure_count = target_count - vuln_count;
    println!("{}", cyan!("─").repeat(40));
    println!(
        "{}   {}   {}   {}",
        bold!(&format!("目标数 {}", target_count)),
        green!(&format!("✓ 安全 {}", secure_count)),
        red!(&format!("⚠ 高危 {}", vuln_count)),
        bold!("DefaultHound"),
    );

    if let Some(path) = &cli.json {
        let json = serde_json::to_string_pretty(&results)?;
        std::fs::write(path, json)?;
    }
    if let Some(path) = &cli.csv {
        export_csv(&results, path)?;
    }

    Ok(())
}
