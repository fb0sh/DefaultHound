use crate::prelude::*;
use crate::checkers::http_helpers::http_get_check;

pub struct KibanaChecker;
#[async_trait]
impl ServiceChecker for KibanaChecker {
    fn service_name(&self) -> &'static str { "Kibana" }
    fn default_port(&self) -> u16 { 5601 }

    fn proto(&self) -> &'static str {
        "http"
    }
    async fn check(&self, ip: &str, port: Option<u16>) -> CheckResult {
        let port = port.unwrap_or(self.default_port());
        http_get_check(ip, port, "/api/status", &["status"], "Kibana 未授权访问", "Kibana").await
    }
}
