use crate::prelude::*;
use crate::checkers::http_helpers::http_get_check;

pub struct CrowdChecker;
#[async_trait]
impl ServiceChecker for CrowdChecker {
    fn service_name(&self) -> &'static str { "Crowd" }
    fn default_port(&self) -> u16 { 8095 }
    async fn check(&self, ip: &str, port: Option<u16>) -> CheckResult {
        let port = port.unwrap_or(self.default_port());
        http_get_check(ip, port, "/crowd/admin/", &["Crowd"], "Crowd 管理后台暴露", "Crowd").await
    }
}
