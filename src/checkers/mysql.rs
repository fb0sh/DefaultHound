use crate::prelude::*;
use tokio::io::AsyncReadExt;
use tokio::time::{Duration, timeout};

pub struct MysqlChecker;

#[async_trait]
impl ServiceChecker for MysqlChecker {
    fn service_name(&self) -> &'static str {
        "MySQL"
    }

    fn default_port(&self) -> u16 {
        3306
    }

    fn default_credentials(&self) -> Vec<Credential> {
        vec![
            Credential::new("root", ""),
            Credential::new("root", "root"),
            Credential::new("root", "123456"),
            Credential::new("admin", ""),
            Credential::new("admin", "admin"),
            Credential::new("test", ""),
            Credential::new("mysql", ""),
        ]
    }

    async fn check(&self, ip: &str, port: Option<u16>) -> CheckResult {
        let port = port.unwrap_or(self.default_port());
        let mut stream = try_connect!(self, ip, port);
        let mut handshake = vec![0u8; 1024];

        let n = match timeout(Duration::from_secs(5), stream.read(&mut handshake)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return CheckResult::Error(format!("读取握手包失败: {}", e)),
            Err(_) => return CheckResult::Error("读取握手包超时".to_string()),
        };
        handshake.truncate(n);

        if n < 4 || handshake[4] != 10 {
            return CheckResult::Secure("响应不是 MySQL 协议".to_string());
        }

        let version_end = handshake[5..].iter().position(|&b| b == 0).unwrap_or(0);
        let version = String::from_utf8_lossy(&handshake[5..5 + version_end]);

        let creds: Vec<_> = self
            .default_credentials()
            .iter()
            .map(|c| c.display())
            .collect();

        CheckResult::Vulnerable {
            credentials: "服务开放".to_string(),
            details: format!(
                "MySQL {version} 端口开放，建议检查默认凭据: {}",
                creds.join(", ")
            ),
        }
    }
}
