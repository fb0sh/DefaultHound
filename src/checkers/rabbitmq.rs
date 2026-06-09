use crate::prelude::*;
use crate::checkers::http_helpers::http_get_check;

pub struct RabbitmqChecker;
#[async_trait]
impl ServiceChecker for RabbitmqChecker {
    fn service_name(&self) -> &'static str { "RabbitMQ" }
    fn default_port(&self) -> u16 { 15672 }

    fn proto(&self) -> &'static str {
        "http"
    }
    async fn check(&self, ip: &str, port: Option<u16>) -> CheckResult {
        let port = port.unwrap_or(self.default_port());
        http_get_check(ip, port, "/api/overview", &["management_version"], "RabbitMQ 管理 API 未授权", "RabbitMQ").await
    }
}
