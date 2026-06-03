pub mod checkers;
pub mod prelude;

use async_trait::async_trait;
use std::borrow::Cow;
use tokio::net::TcpStream;
use tokio::time::{Duration, timeout};

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

    /// 该服务常见的默认/空密码凭据列表
    fn default_credentials(&self) -> Vec<Credential> {
        Vec::new()
    }

    /// 尝试 TCP 连接目标 (默认实现，checker 可直接调用)
    /// Err 中直接包装 CheckResult，调用方无需手动转换
    async fn try_tcp_connect(&self, ip: &str, port: u16) -> Result<TcpStream, CheckResult> {
        let target = format!("{}:{}", ip, port);
        timeout(Duration::from_secs(3), TcpStream::connect(&target))
            .await
            .map_err(|_| CheckResult::Secure("连接超时".to_string()))?
            .map_err(|e| CheckResult::Secure(format!("端口未开放: {}", e)))
    }

    /// 执行安全检查。
    ///
    /// - `ip`: 目标 IP 地址
    /// - `port`: 目标端口，传 `None` 时使用 `default_port()`
    async fn check(&self, ip: &str, port: Option<u16>) -> CheckResult;
}
