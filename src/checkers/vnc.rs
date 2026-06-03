use crate::prelude::*;
use tokio::io::AsyncReadExt;
use tokio::time::{timeout, Duration};

pub struct VncChecker;
#[async_trait]
impl ServiceChecker for VncChecker {
    fn service_name(&self) -> &'static str { "VNC" }
    fn default_port(&self) -> u16 { 5900 }
    async fn check(&self, ip: &str, port: Option<u16>) -> CheckResult {
        let port = port.unwrap_or(self.default_port());
        let mut stream = match self.try_tcp_connect(ip, port).await { Ok(s) => s, Err(r) => return r };
        let mut buf = vec![0u8; 1024];
        let n = timeout(Duration::from_secs(3), stream.read(&mut buf)).await.ok().and_then(|r| r.ok()).unwrap_or(0);
        if n > 0 && buf[..n].windows(3).any(|w| w == b"RFB") {
            CheckResult::Vulnerable { credentials: "无需认证".into(), details: "VNC 服务暴露，可能未授权访问".into() }
        } else {
            CheckResult::Secure("VNC 未发现未授权访问".into())
        }
    }
}
