use crate::prelude::*;
use crate::checkers::http_helpers::http_get_check;

pub struct ZabbixChecker;
#[async_trait]
impl ServiceChecker for ZabbixChecker {
    fn service_name(&self) -> &'static str { "Zabbix" }
    fn default_port(&self) -> u16 { 10051 }

    fn proto(&self) -> &'static str {
        "http"
    }
    async fn check(&self, ip: &str, port: Option<u16>) -> CheckResult {
        let port = port.unwrap_or(self.default_port());
        http_get_check(ip, port, "/", &["Zabbix"], "Zabbix 服务暴露", "Zabbix").await
    }
}
