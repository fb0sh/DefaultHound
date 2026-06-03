use crate::prelude::*;
use crate::checkers::http_helpers::http_get_check;

pub struct HadoopChecker;
#[async_trait]
impl ServiceChecker for HadoopChecker {
    fn service_name(&self) -> &'static str { "Hadoop" }
    fn default_port(&self) -> u16 { 8088 }
    async fn check(&self, ip: &str, port: Option<u16>) -> CheckResult {
        let port = port.unwrap_or(self.default_port());
        http_get_check(ip, port, "/ws/v1/cluster/apps", &["apps"], "Hadoop YARN 未授权访问", "Hadoop").await
    }
}
