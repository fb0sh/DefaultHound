use crate::prelude::*;
use crate::checkers::http_helpers::http_get_check;

pub struct OllamaChecker;
#[async_trait]
impl ServiceChecker for OllamaChecker {
    fn service_name(&self) -> &'static str { "Ollama" }
    fn default_port(&self) -> u16 { 11434 }

    fn proto(&self) -> &'static str {
        "http"
    }
    async fn check(&self, ip: &str, port: Option<u16>) -> CheckResult {
        let port = port.unwrap_or(self.default_port());
        http_get_check(ip, port, "/api/tags", &["models"], "Ollama 未授权访问", "Ollama").await
    }
}
