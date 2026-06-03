use std::io::{IsTerminal, Read};
use std::path::PathBuf;

use clap::Parser;
use futures::StreamExt;
use serde::Serialize;

use defaulthound::CheckResult;
use defaulthound::checkers;

const MAX_CONCURRENT: usize = 30;

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
}

#[derive(Debug, Clone)]
struct Target {
    ip: String,
    ports: Vec<u16>,
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

fn parse_targets(content: &str) -> Vec<Target> {
    let mut targets = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((ip, port_part)) = line.split_once(':') {
            let ports: Vec<u16> = port_part
                .split(',')
                .filter_map(|p| p.trim().parse().ok())
                .collect();
            targets.push(Target {
                ip: ip.to_string(),
                ports,
            });
        } else {
            targets.push(Target {
                ip: line.to_string(),
                ports: vec![],
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
        vec![Target { ip, ports: vec![] }]
    };

    let checkers = checkers::all_checkers();

    if cli.list {
        let mut services: Vec<_> = checkers.iter().map(|c| (c.service_name(), c.default_port())).collect();
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

    let tasks = targets.iter().flat_map(|target| {
        checkers.iter().flat_map(move |checker| {
            let ports = if target.ports.is_empty() {
                vec![checker.default_port()]
            } else {
                target.ports.clone()
            };
            ports.into_iter().map(move |port| {
                let ip = target.ip.clone();
                async move {
                    let result = checker.check(&ip, Some(port)).await;
                    (checker.service_name(), ip, port, result)
                }
            })
        })
    });

    let mut stream = futures::stream::iter(tasks).buffer_unordered(cli.rate);

    while let Some((name, ip, port, result)) = stream.next().await {
        match result {
            CheckResult::Secure(reason) => {
                println!("[{name}] {ip}:{port}  安全  {reason}");
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
                println!("[VULN][{}]({}) {}:{}", name, credentials, ip, port);
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
                println!("[ERR][{name}] {ip}:{port}  {e}");
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

    let secure = results.iter().filter(|r| !r.vulnerable).count();
    let vuln = results.iter().filter(|r| r.vulnerable).count();
    println!("---");
    println!("总计 {}  安全 {}  高危 {}", results.len(), secure, vuln);

    if let Some(path) = &cli.json {
        let json = serde_json::to_string_pretty(&results)?;
        std::fs::write(path, json)?;
    }
    if let Some(path) = &cli.csv {
        export_csv(&results, path)?;
    }

    Ok(())
}
