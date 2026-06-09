use std::collections::{HashMap, HashSet};
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
#[command(name = "defaulthound", version, about = "批量检测服务默认密码 | <fb0sh@outlook.com> https://github.com/fb0sh/DefaultHound")]
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

    /// 代理地址 (socks5://... 或 http://...)
    #[arg(short = 'p', long = "proxy")]
    proxy: Option<String>,

    /// 显示默认凭据表，可选搜索关键词
    #[arg(long, num_args = 0..=1, default_missing_value = "")]
    show: Option<String>,
}

#[derive(Debug, Clone)]
struct Target {
    ip: String,
    /// 纯端口列表（无 `^` 时匹配服务默认端口）
    ports: Vec<u16>,
    /// 服务级覆盖：service → port，有值时仅运行这些服务
    overrides: HashMap<String, Option<u16>>,
    /// URL scheme: None=全部, Some("http")=仅HTTP, Some("https")=仅HTTPS
    scheme: Option<String>,
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
/// - `ip`                         扫描所有服务（各自默认端口）
/// - `ip:port`                    只扫描匹配该端口的服务
/// - `ip:port1,port2`             只扫描匹配这些端口的服务
/// - `ip:redis^port`              Redis 使用指定端口
/// - `ip:redis^port1,redis2^port2` 多个服务各自指定端口
/// - `ip:redis^`                  Redis 使用默认端口
fn parse_targets(content: &str) -> Vec<Target> {
    let mut targets = Vec::new();
    for line in content.lines() {
        let mut line = line.trim().to_string();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // 检测 http:// 或 https:// 前缀
        let scheme = if line.to_lowercase().starts_with("https://") {
            line = line[8..].to_string();
            Some("https".to_string())
        } else if line.to_lowercase().starts_with("http://") {
            line = line[7..].to_string();
            Some("http".to_string())
        } else {
            None
        };

        // 格式: ip, ip:port, ip:port1,port2, ip:service^port, ip:service^
        if let Some((ip, port_part)) = line.split_once(':') {
            let parts: Vec<&str> = port_part.split(',').map(|p| p.trim()).collect();
            let has_caret = parts.iter().any(|p| p.contains('^'));

            if has_caret {
                let mut overrides = HashMap::new();
                for part in parts {
                    if let Some(pos) = part.find('^') {
                        let svc = part[..pos].trim().to_lowercase();
                        let port_str = part[pos + 1..].trim();
                        let port = if port_str.is_empty() {
                            None
                        } else {
                            port_str.parse::<u16>().ok()
                        };
                        overrides.insert(svc, port);
                    }
                }
                targets.push(Target {
                    ip: ip.to_string(),
                    ports: vec![],
                    overrides,
                    scheme: scheme.clone(),
                });
            } else {
                let ports: Vec<u16> = parts.iter().filter_map(|p| p.parse().ok()).collect();
                targets.push(Target {
                    ip: ip.to_string(),
                    ports,
                    overrides: HashMap::new(),
                    scheme: scheme.clone(),
                });
            }
        } else {
            targets.push(Target {
                ip: line.to_string(),
                ports: vec![],
                overrides: HashMap::new(),
                scheme: scheme.clone(),
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
            overrides: HashMap::new(),
            scheme: None,
        }]
    };

    let checkers = checkers::all_checkers();

    if cli.list {
        let mut services: Vec<_> = checkers
            .iter()
            .map(|c| (c.service_name(), c.default_port(), c.proto()))
            .collect();
        services.sort_by(|a, b| a.1.cmp(&b.1).then(a.0.cmp(b.0)));
        println!("{:<20} {:<6} {}", "Service", "Port", "Type");
        println!("{}", "-".repeat(32));
        for (name, port, proto) in services {
            println!("{:<20} {:<6} {}", name, port, proto);
        }
        return Ok(());
    }

    // ── 显示默认凭据表 ──
    if let Some(query) = cli.show {
        let all = defaulthound::default_creds::get_all();
        let matched: Vec<_> = if query.is_empty() {
            all.iter().collect()
        } else {
            let q = query.to_lowercase();
            all.iter().filter(|e| {
                e.vendor.to_lowercase().contains(&q)
                    || e.version.to_lowercase().contains(&q)
                    || e.username.to_lowercase().contains(&q)
                    || e.password.to_lowercase().contains(&q)
            }).collect()
        };

        println!("Default Credentials ({} matched)", matched.len());
        println!("{}", "─".repeat(100));
        println!("{:<30} {:<18} {:<22} {:<22}", "Vendor / Product", "Version", "Username", "Password");
        println!("{}", "─".repeat(100));
        for entry in matched {
            let vers = if entry.version.is_empty() { "-" } else { entry.version };
            let user = if entry.username.is_empty() { "<blank>" } else { entry.username };
            let pass = if entry.password.is_empty() { "<blank>" } else { entry.password };
            // Truncate long fields
            let v = if entry.vendor.len() > 28 { format!("{}..", &entry.vendor[..28]) } else { entry.vendor.to_string() };
            let s = if vers.len() > 16 { format!("{}..", &vers[..16]) } else { vers.to_string() };
            let u = if user.len() > 20 { format!("{}..", &user[..20]) } else { user.to_string() };
            let p = if pass.len() > 20 { format!("{}..", &pass[..20]) } else { pass.to_string() };
            println!("{:<30} {:<18} {:<22} {:<22}", v, s, u, p);
        }
        return Ok(());
    }

    // 设置代理
    if let Some(ref proxy_url) = cli.proxy {
        defaulthound::set_global_proxy(proxy_url);
    }

    if targets.is_empty() {
        anyhow::bail!("没有有效的目标");
    }
    let mut results: Vec<ScanEntry> = Vec::new();
    let mut vuln_targets: HashSet<usize> = HashSet::new();

    // HTTP 检测器列表（用于 scheme 过滤）
    let http_checkers: [&str; 28] = [
        "Docker","DockerRegistry","Elasticsearch","Jenkins","Kibana","Kubernetes",
        "Jupyter","Nacos","NacosWeakpass","Ollama","Spark","Weblogic","Hadoop",
        "JBoss","ActiveMQ","Zabbix","RabbitMQ","Solr","Harbor","WordPress",
        "Crowd","Kong","ThinkAdmin","Swagger","SpringBoot","Druid","RuoYi",
        "uWSGI",
    ];

    let tasks = checkers.iter().flat_map(|checker| {
        let svc_name = checker.service_name().to_lowercase();
        let is_http = http_checkers.contains(&checker.service_name());
        targets
            .iter()
            .enumerate()
            .filter_map(move |(target_idx, target)| {
                // scheme 过滤
                if let Some(ref scheme) = target.scheme {
                    let http_match = (scheme == "http" || scheme == "https") && is_http;
                    let tcp_match = scheme == "tcp" && !is_http;
                    if !http_match && !tcp_match {
                        return None;
                    }
                }
                // 有 overrides 时只运行匹配的服务
                if !target.overrides.is_empty() {
                    let port = match target.overrides.get(&svc_name) {
                        Some(Some(p)) => *p,
                        Some(None) => checker.default_port(),
                        None => return None,
                    };
                    return Some((target_idx, port, target.ip.clone()));
                }
                // 无 overrides：用端口列表匹配默认端口，或全部运行
                let port = if target.ports.is_empty() {
                    checker.default_port()
                } else if target.ports.contains(&checker.default_port()) {
                    checker.default_port()
                } else {
                    return None;
                };
                Some((target_idx, port, target.ip.clone()))
            })
            .map(move |(target_idx, port, ip)| async move {
                let result = checker.check(&ip, Some(port)).await;
                (target_idx, checker.service_name(), ip, port, result)
            })
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
        bold!("DefaultHound | <fb0sh@outlook.com> https://github.com/fb0sh/DefaultHound"),
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
