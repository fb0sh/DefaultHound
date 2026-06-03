use crate::prelude::*;
use crate::checkers::http_helpers::http_get_check;

pub struct SolrChecker;
#[async_trait]
impl ServiceChecker for SolrChecker {
    fn service_name(&self) -> &'static str { "Solr" }
    fn default_port(&self) -> u16 { 8983 }
    async fn check(&self, ip: &str, port: Option<u16>) -> CheckResult {
        let port = port.unwrap_or(self.default_port());
        http_get_check(ip, port, "/solr/admin/cores", &["responseHeader"], "Solr 未授权访问", "Solr").await
    }
}
