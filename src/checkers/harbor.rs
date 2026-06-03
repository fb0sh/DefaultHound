use crate::prelude::*;
use crate::checkers::http_helpers::http_get_check;

pub struct HarborChecker;
#[async_trait]
impl ServiceChecker for HarborChecker {
    fn service_name(&self) -> &'static str { "Harbor" }
    fn default_port(&self) -> u16 { 80 }
    async fn check(&self, ip: &str, port: Option<u16>) -> CheckResult {
        let port = port.unwrap_or(self.default_port());
        http_get_check(ip, port, "/api/v2.0/users", &["username"], "Harbor 用户 API 暴露", "Harbor").await
    }
}
