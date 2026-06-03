use crate::prelude::*;
use crate::checkers::http_helpers::http_get_check;

pub struct ElasticsearchChecker;
#[async_trait]
impl ServiceChecker for ElasticsearchChecker {
    fn service_name(&self) -> &'static str { "Elasticsearch" }
    fn default_port(&self) -> u16 { 9200 }
    async fn check(&self, ip: &str, port: Option<u16>) -> CheckResult {
        let port = port.unwrap_or(self.default_port());
        http_get_check(ip, port, "/_cat/indices", &["green","yellow"], "Elasticsearch 未授权访问", "Elasticsearch").await
    }
}
