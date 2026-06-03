use crate::prelude::*;
use crate::checkers::http_helpers::http_get_check_multi;

pub struct SpringbootChecker;
#[async_trait]
impl ServiceChecker for SpringbootChecker {
    fn service_name(&self) -> &'static str { "SpringBoot" }
    fn default_port(&self) -> u16 { 8080 }
    async fn check(&self, ip: &str, port: Option<u16>) -> CheckResult {
        let port = port.unwrap_or(self.default_port());
        http_get_check_multi(ip, port, &["/actuator","/actuator/health","/actuator/env","/actuator/beans","/actuator/metrics"], &["actuator","health","env","beans"], "SpringBoot Actuator 未授权访问", "SpringBoot").await
    }
}
