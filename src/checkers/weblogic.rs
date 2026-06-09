use crate::prelude::*;
use crate::checkers::http_helpers::http_get_check;

pub struct WeblogicChecker;
#[async_trait]
impl ServiceChecker for WeblogicChecker {
    fn service_name(&self) -> &'static str { "WebLogic" }
    fn default_port(&self) -> u16 { 7001 }

    fn proto(&self) -> &'static str {
        "http"
    }
    async fn check(&self, ip: &str, port: Option<u16>) -> CheckResult {
        let port = port.unwrap_or(self.default_port());
        http_get_check(ip, port, "/console/login/LoginForm.jsp", &["WebLogic Server","WebLogic"], "WebLogic 控制台暴露", "WebLogic").await
    }
}
