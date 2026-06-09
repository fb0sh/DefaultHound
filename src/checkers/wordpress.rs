use crate::prelude::*;
use crate::checkers::http_helpers::http_get_check;

pub struct WordpressChecker;
#[async_trait]
impl ServiceChecker for WordpressChecker {
    fn service_name(&self) -> &'static str { "WordPress" }
    fn default_port(&self) -> u16 { 80 }

    fn proto(&self) -> &'static str {
        "http"
    }
    async fn check(&self, ip: &str, port: Option<u16>) -> CheckResult {
        let port = port.unwrap_or(self.default_port());
        http_get_check(ip, port, "/wp-admin/", &["WordPress"], "WordPress 管理后台暴露", "WordPress").await
    }
}
