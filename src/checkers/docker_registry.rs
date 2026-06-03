use crate::prelude::*;
use crate::checkers::http_helpers::http_get_check;

pub struct DockerRegistryChecker;
#[async_trait]
impl ServiceChecker for DockerRegistryChecker {
    fn service_name(&self) -> &'static str { "DockerRegistry" }
    fn default_port(&self) -> u16 { 5000 }
    async fn check(&self, ip: &str, port: Option<u16>) -> CheckResult {
        let port = port.unwrap_or(self.default_port());
        http_get_check(ip, port, "/v2/_catalog", &["repositories"], "Docker Registry 未授权访问", "DockerRegistry").await
    }
}
