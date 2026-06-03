mod mysql;
mod redis;

// TCP Socket 类
mod couchdb;
mod dubbo;
mod ftp;
mod ldap;
mod memcached;
mod mongodb;
mod nfs;
mod rsync;
mod smb;
mod uwsgi;
mod vnc;
mod zookeeper;

// HTTP/Web 类
mod activemq;
mod crowd;
mod docker;
mod docker_registry;
mod druid;
mod elasticsearch;
mod hadoop;
mod harbor;
mod jboss;
mod jenkins;
mod jupyter;
mod kibana;
mod kong;
mod kubernetes;
mod nacos;
mod nacos_weakpass;
mod ollama;
mod rabbitmq;
mod ruoyi;
mod solr;
mod spark;
mod springboot;
mod swagger;
mod thinkadmin;
mod weblogic;
mod wordpress;
mod zabbix;

pub(crate) mod http_helpers;

use crate::ServiceChecker;

pub fn all_checkers() -> Vec<Box<dyn ServiceChecker>> {
    vec![
        Box::new(mysql::MysqlChecker),
        Box::new(redis::RedisChecker),
        // ── TCP Socket ──
        Box::new(ftp::FtpChecker),
        Box::new(zookeeper::ZookeeperChecker),
        Box::new(mongodb::MongodbChecker),
        Box::new(ldap::LdapChecker),
        Box::new(vnc::VncChecker),
        Box::new(memcached::MemcachedChecker),
        Box::new(nfs::NfsChecker),
        Box::new(dubbo::DubboChecker),
        Box::new(rsync::RsyncChecker),
        Box::new(smb::SmbChecker),
        Box::new(uwsgi::UwsgiChecker),
        Box::new(couchdb::CouchdbChecker),
        // ── HTTP/Web ──
        Box::new(docker::DockerChecker),
        Box::new(docker_registry::DockerRegistryChecker),
        Box::new(elasticsearch::ElasticsearchChecker),
        Box::new(jenkins::JenkinsChecker),
        Box::new(kibana::KibanaChecker),
        Box::new(kubernetes::KubernetesChecker),
        Box::new(jupyter::JupyterChecker),
        Box::new(nacos::NacosChecker),
        Box::new(nacos_weakpass::NacosWeakpassChecker),
        Box::new(ollama::OllamaChecker),
        Box::new(spark::SparkChecker),
        Box::new(weblogic::WeblogicChecker),
        Box::new(hadoop::HadoopChecker),
        Box::new(jboss::JbossChecker),
        Box::new(activemq::ActivemqChecker),
        Box::new(zabbix::ZabbixChecker),
        Box::new(rabbitmq::RabbitmqChecker),
        Box::new(solr::SolrChecker),
        Box::new(harbor::HarborChecker),
        Box::new(wordpress::WordpressChecker),
        Box::new(crowd::CrowdChecker),
        Box::new(kong::KongChecker),
        Box::new(thinkadmin::ThinkadminChecker),
        Box::new(swagger::SwaggerChecker),
        Box::new(springboot::SpringbootChecker),
        Box::new(druid::DruidChecker),
        Box::new(ruoyi::RuoyiChecker),
    ]
}
