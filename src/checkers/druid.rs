use crate::prelude::*;
use crate::checkers::http_helpers::http_get_check_multi;

pub struct DruidChecker;
#[async_trait]
impl ServiceChecker for DruidChecker {
    fn service_name(&self) -> &'static str { "Druid" }
    fn default_port(&self) -> u16 { 80 }

    fn proto(&self) -> &'static str {
        "http"
    }
    async fn check(&self, ip: &str, port: Option<u16>) -> CheckResult {
        let port = port.unwrap_or(self.default_port());
        http_get_check_multi(ip, port, &["/druid/index.html","/druid/login.html","/druid/weburi.html","/druid/sql.html"], &["Druid","druid"], "Druid 未授权访问", "Druid").await
    }
}
