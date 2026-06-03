use crate::prelude::*;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::time::{Duration, timeout};

pub struct RedisChecker;

#[async_trait]
impl ServiceChecker for RedisChecker {
    fn service_name(&self) -> &'static str {
        "Redis"
    }

    fn default_port(&self) -> u16 {
        6379
    }

    fn default_credentials(&self) -> Vec<Credential> {
        vec![
            Credential::new("default", ""),
            Credential::new("redis", ""),
            Credential::new("admin", ""),
        ]
    }

    async fn check(&self, ip: &str, port: Option<u16>) -> CheckResult {
        let port = port.unwrap_or(self.default_port());
        let mut stream = try_connect!(self, ip, port);

        let ping_cmd = b"*1\r\n$4\r\nPING\r\n";
        if let Err(e) = stream.write_all(ping_cmd).await {
            return CheckResult::Error(format!("发送 PING 失败: {}", e));
        }

        let mut reader = BufReader::new(&mut stream);
        let mut response = String::new();
        match timeout(Duration::from_secs(5), reader.read_line(&mut response)).await {
            Ok(Ok(_)) => {
                let resp = response.trim();
                if resp == "+PONG" {
                    CheckResult::Vulnerable {
                        credentials: "无需认证".to_string(),
                        details: "Redis 服务未配置密码认证，可任意访问".to_string(),
                    }
                } else if resp.starts_with("-ERR") {
                    CheckResult::Secure("Redis 已启用密码认证，但未验证默认密码强度".to_string())
                } else {
                    CheckResult::Error(format!("未知响应: {}", response))
                }
            }
            Ok(Err(e)) => CheckResult::Error(format!("读取响应失败: {}", e)),
            Err(_) => CheckResult::Error("读取响应超时".to_string()),
        }
    }
}
