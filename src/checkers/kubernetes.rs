use crate::prelude::*;
use crate::checkers::http_helpers::http_get_check;

pub struct KubernetesChecker;
#[async_trait]
impl ServiceChecker for KubernetesChecker {
    fn service_name(&self) -> &'static str { "Kubernetes" }
    fn default_port(&self) -> u16 { 8080 }

    fn proto(&self) -> &'static str {
        "http"
    }
    async fn check(&self, ip: &str, port: Option<u16>) -> CheckResult {
        let port = port.unwrap_or(self.default_port());
        http_get_check(ip, port, "/api/v1/namespaces/default/pods", &["items"], "Kubernetes 未授权访问", "Kubernetes").await
    }
}
