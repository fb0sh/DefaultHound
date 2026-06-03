use crate::prelude::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{timeout, Duration};

pub struct CouchdbChecker;
#[async_trait]
impl ServiceChecker for CouchdbChecker {
    fn service_name(&self) -> &'static str { "CouchDB" }
    fn default_port(&self) -> u16 { 5984 }
    async fn check(&self, ip: &str, port: Option<u16>) -> CheckResult {
        let port = port.unwrap_or(self.default_port());
        let mut stream = match self.try_tcp_connect(ip, port).await { Ok(s) => s, Err(r) => return r };
        let req = b"GET /_all_dbs HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
        stream.write_all(req).await.ok();
        let mut buf = vec![0u8; 8192];
        let n = timeout(Duration::from_secs(3), stream.read(&mut buf)).await.ok().and_then(|r| r.ok()).unwrap_or(0);
        let resp = String::from_utf8_lossy(&buf[..n]);
        if resp.contains("200") || resp.starts_with('[') {
            CheckResult::Vulnerable { credentials: "无需认证".into(), details: "CouchDB 未授权访问".into() }
        } else {
            CheckResult::Secure("CouchDB 未发现未授权访问".into())
        }
    }
}
