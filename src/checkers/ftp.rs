use crate::prelude::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{timeout, Duration};

pub struct FtpChecker;
#[async_trait]
impl ServiceChecker for FtpChecker {
    fn service_name(&self) -> &'static str { "FTP" }
    fn default_port(&self) -> u16 { 21 }
    fn default_credentials(&self) -> Vec<Credential> {
        vec![Credential::new("anonymous", "anonymous@example.com")]
    }
    async fn check(&self, ip: &str, port: Option<u16>) -> CheckResult {
        let port = port.unwrap_or(self.default_port());
        let mut stream = match self.try_tcp_connect(ip, port).await { Ok(s) => s, Err(r) => return r };
        let mut buf = vec![0u8; 1024];
        let _ = timeout(Duration::from_secs(3), stream.read(&mut buf)).await;
        if !String::from_utf8_lossy(&buf).contains("220") {
            return CheckResult::Secure("FTP 未发现匿名登录".into());
        }
        drop(stream);
        let mut s2 = match self.try_tcp_connect(ip, port).await { Ok(s) => s, Err(r) => return r };
        let _ = timeout(Duration::from_secs(3), s2.read(&mut buf)).await;
        s2.write_all(b"USER anonymous\r\n").await.ok();
        let _ = timeout(Duration::from_secs(3), s2.read(&mut buf)).await;
        if String::from_utf8_lossy(&buf).contains("331") {
            s2.write_all(b"PASS anonymous@example.com\r\n").await.ok();
            let _ = timeout(Duration::from_secs(3), s2.read(&mut buf)).await;
            if String::from_utf8_lossy(&buf).contains("230") {
                return CheckResult::Vulnerable { credentials: "anonymous:anonymous@example.com".into(), details: "FTP 匿名登录成功".into() };
            }
        }
        CheckResult::Secure("FTP 未发现匿名登录".into())
    }
}
