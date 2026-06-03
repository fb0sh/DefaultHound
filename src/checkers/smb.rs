use crate::prelude::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{timeout, Duration};

pub struct SmbChecker;
#[async_trait]
impl ServiceChecker for SmbChecker {
    fn service_name(&self) -> &'static str { "SMB" }
    fn default_port(&self) -> u16 { 445 }
    async fn check(&self, ip: &str, port: Option<u16>) -> CheckResult {
        let port = port.unwrap_or(self.default_port());
        let mut stream = match self.try_tcp_connect(ip, port).await { Ok(s) => s, Err(r) => return r };
        let payload: [u8; 16] = [0x00, 0x00, 0x00, 0x85, 0xff, 0x53, 0x4d, 0x42, 0x72, 0x00, 0x00, 0x00, 0x00, 0x18, 0x53, 0xc8];
        stream.write_all(&payload).await.ok();
        let mut buf = vec![0u8; 1024];
        let n = timeout(Duration::from_secs(3), stream.read(&mut buf)).await.ok().and_then(|r| r.ok()).unwrap_or(0);
        if n > 0 {
            CheckResult::Vulnerable { credentials: "无需认证".into(), details: "SMB 服务暴露，可能未授权访问".into() }
        } else {
            CheckResult::Secure("SMB 未发现未授权访问".into())
        }
    }
}
