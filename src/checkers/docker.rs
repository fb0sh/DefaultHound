use crate::prelude::*;
use crate::checkers::http_helpers::http_get_check;

pub struct DockerChecker;
#[async_trait]
impl ServiceChecker for DockerChecker {
    fn service_name(&self) -> &'static str { "Docker" }
    fn default_port(&self) -> u16 { 2375 }

    fn proto(&self) -> &'static str {
        "http"
    }
    async fn check(&self, ip: &str, port: Option<u16>) -> CheckResult {
        let port = port.unwrap_or(self.default_port());
        http_get_check(ip, port, "/version", &["ApiVersion"], "Docker 未授权访问", "Docker").await
    }
}
