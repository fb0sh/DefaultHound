use crate::prelude::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{timeout, Duration};

pub struct MongodbChecker;
#[async_trait]
impl ServiceChecker for MongodbChecker {
    fn service_name(&self) -> &'static str { "MongoDB" }
    fn default_port(&self) -> u16 { 27017 }
    async fn check(&self, ip: &str, port: Option<u16>) -> CheckResult {
        let port = port.unwrap_or(self.default_port());
        let mut stream = match self.try_tcp_connect(ip, port).await { Ok(s) => s, Err(r) => return r };
        stream.write_all(b"db.adminCommand('ping')\r\n").await.ok();
        let mut buf = vec![0u8; 8192];
        let n = timeout(Duration::from_secs(3), stream.read(&mut buf)).await.ok().and_then(|r| r.ok()).unwrap_or(0);
        if String::from_utf8_lossy(&buf[..n]).contains("ok") {
            CheckResult::Vulnerable { credentials: "无需认证".into(), details: "MongoDB 未授权访问".into() }
        } else {
            CheckResult::Secure("MongoDB 未发现未授权访问".into())
        }
    }
}
