use crate::prelude::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{timeout, Duration};

pub struct LdapChecker;
#[async_trait]
impl ServiceChecker for LdapChecker {
    fn service_name(&self) -> &'static str { "LDAP" }
    fn default_port(&self) -> u16 { 389 }
    async fn check(&self, ip: &str, port: Option<u16>) -> CheckResult {
        let port = port.unwrap_or(self.default_port());
        let mut stream = match self.try_tcp_connect(ip, port).await { Ok(s) => s, Err(r) => return r };
        let req: [u8; 14] = [0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00];
        stream.write_all(&req).await.ok();
        let mut buf = vec![0u8; 1024];
        let n = timeout(Duration::from_secs(3), stream.read(&mut buf)).await.ok().and_then(|r| r.ok()).unwrap_or(0);
        if n > 0 {
            CheckResult::Vulnerable { credentials: "匿名绑定".into(), details: "LDAP 匿名绑定成功，存在未授权访问".into() }
        } else {
            CheckResult::Secure("LDAP 未发现未授权访问".into())
        }
    }
}
