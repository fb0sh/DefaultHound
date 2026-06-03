use crate::prelude::*;
use crate::checkers::http_helpers::http_get_check;

pub struct ActivemqChecker;
#[async_trait]
impl ServiceChecker for ActivemqChecker {
    fn service_name(&self) -> &'static str { "ActiveMQ" }
    fn default_port(&self) -> u16 { 8161 }
    async fn check(&self, ip: &str, port: Option<u16>) -> CheckResult {
        let port = port.unwrap_or(self.default_port());
        http_get_check(ip, port, "/admin/", &["ActiveMQ"], "ActiveMQ 管理后台暴露", "ActiveMQ").await
    }
}
