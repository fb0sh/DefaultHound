use crate::prelude::*;
use crate::checkers::http_helpers::http_get_check;

pub struct JenkinsChecker;
#[async_trait]
impl ServiceChecker for JenkinsChecker {
    fn service_name(&self) -> &'static str { "Jenkins" }
    fn default_port(&self) -> u16 { 8080 }

    fn proto(&self) -> &'static str {
        "http"
    }
    async fn check(&self, ip: &str, port: Option<u16>) -> CheckResult {
        let port = port.unwrap_or(self.default_port());
        http_get_check(ip, port, "/api/json", &["jobs"], "Jenkins 未授权访问", "Jenkins").await
    }
}
