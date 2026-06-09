use crate::prelude::*;
use crate::checkers::http_helpers::http_get_check_multi;

pub struct SwaggerChecker;
#[async_trait]
impl ServiceChecker for SwaggerChecker {
    fn service_name(&self) -> &'static str { "Swagger" }
    fn default_port(&self) -> u16 { 80 }

    fn proto(&self) -> &'static str {
        "http"
    }
    async fn check(&self, ip: &str, port: Option<u16>) -> CheckResult {
        let port = port.unwrap_or(self.default_port());
        http_get_check_multi(ip, port, &["/swagger-ui.html","/swagger/index.html","/v2/api-docs","/swagger-resources","/api-docs","/docs"], &["Swagger UI","swagger-ui","swagger.json"], "Swagger UI 未授权访问", "Swagger").await
    }
}
