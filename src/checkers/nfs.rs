use crate::prelude::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{timeout, Duration};

pub struct NfsChecker;
#[async_trait]
impl ServiceChecker for NfsChecker {
    fn service_name(&self) -> &'static str { "NFS" }
    fn default_port(&self) -> u16 { 2049 }
    async fn check(&self, ip: &str, port: Option<u16>) -> CheckResult {
        let port = port.unwrap_or(self.default_port());
        let mut stream = match self.try_tcp_connect(ip, port).await { Ok(s) => s, Err(r) => return r };
        stream.write_all(b"\x80\x00\x00\x00").await.ok();
        let mut buf = vec![0u8; 1024];
        let n = timeout(Duration::from_secs(3), stream.read(&mut buf)).await.ok().and_then(|r| r.ok()).unwrap_or(0);
        if n > 0 {
            CheckResult::Vulnerable { credentials: "无需认证".into(), details: "NFS 服务暴露，可能未授权访问".into() }
        } else {
            CheckResult::Secure("NFS 未发现未授权访问".into())
        }
    }
}
