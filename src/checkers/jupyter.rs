use crate::prelude::*;
use crate::checkers::http_helpers::http_get_check;

pub struct JupyterChecker;
#[async_trait]
impl ServiceChecker for JupyterChecker {
    fn service_name(&self) -> &'static str { "Jupyter" }
    fn default_port(&self) -> u16 { 8888 }

    fn proto(&self) -> &'static str {
        "http"
    }
    async fn check(&self, ip: &str, port: Option<u16>) -> CheckResult {
        let port = port.unwrap_or(self.default_port());
        http_get_check(ip, port, "/api/kernels", &["kernels"], "Jupyter 未授权访问", "Jupyter").await
    }
}
