use crate::prelude::*;
use crate::checkers::http_helpers::http_get_check_multi;

pub struct RuoyiChecker;
#[async_trait]
impl ServiceChecker for RuoyiChecker {
    fn service_name(&self) -> &'static str { "RuoYi" }
    fn default_port(&self) -> u16 { 80 }

    fn proto(&self) -> &'static str {
        "http"
    }
    async fn check(&self, ip: &str, port: Option<u16>) -> CheckResult {
        let port = port.unwrap_or(self.default_port());
        http_get_check_multi(ip, port, &["/","/login","/admin/dist/index.html"], &["RuoYi","ruoyi","若依"], "RuoYi 后台暴露", "RuoYi").await
    }
}
