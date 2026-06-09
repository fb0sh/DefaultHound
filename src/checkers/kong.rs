use crate::prelude::*;
use crate::checkers::http_helpers::http_get_check;

pub struct KongChecker;
#[async_trait]
impl ServiceChecker for KongChecker {
    fn service_name(&self) -> &'static str { "Kong" }
    fn default_port(&self) -> u16 { 8001 }

    fn proto(&self) -> &'static str {
        "http"
    }
    async fn check(&self, ip: &str, port: Option<u16>) -> CheckResult {
        let port = port.unwrap_or(self.default_port());
        http_get_check(ip, port, "/", &["kong"], "Kong 管理 API 暴露", "Kong").await
    }
}
