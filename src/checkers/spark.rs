use crate::prelude::*;
use crate::checkers::http_helpers::http_get_check;

pub struct SparkChecker;
#[async_trait]
impl ServiceChecker for SparkChecker {
    fn service_name(&self) -> &'static str { "Spark" }
    fn default_port(&self) -> u16 { 6066 }

    fn proto(&self) -> &'static str {
        "http"
    }
    async fn check(&self, ip: &str, port: Option<u16>) -> CheckResult {
        let port = port.unwrap_or(self.default_port());
        http_get_check(ip, port, "/", &["Spark"], "Apache Spark 未授权访问", "Spark").await
    }
}
