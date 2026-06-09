pub mod checkers;
pub mod default_creds;
pub mod prelude;

use async_trait::async_trait;
use std::borrow::Cow;
use std::sync::Mutex;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::time::{Duration, timeout};

/// 全局代理配置
static GLOBAL_PROXY: Mutex<Option<String>> = Mutex::new(None);

/// 设置全局代理 URL
///
/// 支持格式:
/// - `socks5://127.0.0.1:1080`  — SOCKS5 代理（TCP + HTTP）
/// - `socks5h://127.0.0.1:1080` — SOCKS5 with remote DNS
/// - `http://127.0.0.1:8080`     — HTTP 代理（仅 HTTP 检查器）
pub fn set_global_proxy(url: &str) {
    if let Ok(mut p) = GLOBAL_PROXY.lock() {
        *p = Some(url.to_string());
    }
}

/// 获取全局代理 URL
pub fn get_global_proxy() -> Option<String> {
    GLOBAL_PROXY.lock().ok().and_then(|p| p.clone())
}

/// 清除全局代理
pub fn clear_global_proxy() {
    if let Ok(mut p) = GLOBAL_PROXY.lock() {
        *p = None;
    }
}

/// 组合流 trait：代理感知的 TCP 流
pub trait ProxyAwareStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> ProxyAwareStream for T {}

/// 一组登录凭据
#[derive(Debug, Clone)]
pub struct Credential {
    pub username: Cow<'static, str>,
    pub password: Cow<'static, str>,
}

impl Credential {
    pub fn new(
        username: impl Into<Cow<'static, str>>,
        password: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
        }
    }

    /// 格式化显示

    pub fn display(&self) -> String {
        format!("{}:{}", self.username, self.password)
    }
}

/// 安全检查结果
#[derive(Debug)]
pub enum CheckResult {
    /// 安全 —— 无法连接或默认凭据无效
    Secure(String),
    /// 高危 —— 发现有效的默认/空密码凭据
    Vulnerable {
        credentials: String,
        details: String,
    },
    /// 错误 —— 网络不可达、协议错误、超时等
    Error(String),
}

impl CheckResult {
    pub fn is_vulnerable(&self) -> bool {
        matches!(self, CheckResult::Vulnerable { .. })
    }
}

/// 近似 `?` 的宏，用在 check() 内部简化 try_tcp_connect 调用
#[macro_export]
macro_rules! try_connect {
    ($self:expr, $ip:expr, $port:expr) => {
        match $self.try_tcp_connect($ip, $port).await {
            Ok(s) => s,
            Err(r) => return r,
        }
    };
}

/// 服务检查器 trait。
///
/// 每个 checker 只需:
///   1. 提供该服务的默认凭据列表
///   2. 实现 check() 逐个尝试，返回最严重的发现
#[async_trait]
pub trait ServiceChecker: Send + Sync {
    fn service_name(&self) -> &'static str;
    fn default_port(&self) -> u16;

    /// 协议类型: "tcp", "http", "udp", "smtp" 等
    fn proto(&self) -> &'static str {
        "tcp"
    }

    /// 该服务常见的默认/空密码凭据列表
    fn default_credentials(&self) -> Vec<Credential> {
        Vec::new()
    }

    /// 尝试 TCP 连接目标。
    ///
    /// 如果设置了全局代理（SOCKS5），自动通过代理连接。
    /// Err 中直接包装 CheckResult，调用方无需手动转换。
    async fn try_tcp_connect(
        &self,
        ip: &str,
        port: u16,
    ) -> Result<Box<dyn ProxyAwareStream>, CheckResult> {
        let target = format!("{}:{}", ip, port);

        // 如果设置了 SOCKS5 代理，通过代理连接
        if let Some(proxy_url) = get_global_proxy() {
            if proxy_url.starts_with("socks5") {
                return match timeout(
                    Duration::from_secs(5),
                    tokio_socks::tcp::socks5::Socks5Stream::connect(
                        proxy_url.as_str(),
                        target.clone(),
                    ),
                )
                .await
                {
                    Ok(Ok(stream)) => Ok(Box::new(stream)),
                    Ok(Err(e)) => Err(CheckResult::Error(format!("代理连接失败: {}", e))),
                    Err(_) => Err(CheckResult::Error("代理连接超时".to_string())),
                };
            }
            // 非 socks 代理（如 http proxy）则直连 TCP，HTTP 检查器会处理代理
        }

        // 默认：直连
        timeout(Duration::from_secs(3), TcpStream::connect(&target))
            .await
            .map_err(|_| CheckResult::Secure("连接超时".to_string()))?
            .map_err(|e| CheckResult::Secure(format!("端口未开放: {}", e)))
            .map(|s| Box::new(s) as Box<dyn ProxyAwareStream>)
    }

    /// 执行安全检查。
    ///
    /// - `ip`: 目标 IP 地址
    /// - `port`: 目标端口，传 `None` 时使用 `default_port()`
    async fn check(&self, ip: &str, port: Option<u16>) -> CheckResult;
}
