use crate::prelude::*;
use crate::checkers::http_helpers::http_get_check;

pub struct NacosChecker;
#[async_trait]
impl ServiceChecker for NacosChecker {
    fn service_name(&self) -> &'static str { "Nacos" }
    fn default_port(&self) -> u16 { 8848 }

    fn proto(&self) -> &'static str {
        "http"
    }
    async fn check(&self, ip: &str, port: Option<u16>) -> CheckResult {
        let port = port.unwrap_or(self.default_port());
        http_get_check(ip, port, "/nacos/v1/auth/users?pageNo=1&pageSize=10", &["username"], "Nacos 未授权访问", "Nacos").await
    }
}
