use crate::prelude::*;
use crate::checkers::http_helpers::http_get_check;

pub struct ThinkadminChecker;
#[async_trait]
impl ServiceChecker for ThinkadminChecker {
    fn service_name(&self) -> &'static str { "ThinkAdmin" }
    fn default_port(&self) -> u16 { 80 }
    async fn check(&self, ip: &str, port: Option<u16>) -> CheckResult {
        let port = port.unwrap_or(self.default_port());
        http_get_check(ip, port, "/admin.html", &["ThinkAdmin","admin"], "ThinkAdmin 管理后台暴露", "ThinkAdmin").await
    }
}
