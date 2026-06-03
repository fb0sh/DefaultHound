mod http;
mod mysql;
mod redis;

use crate::ServiceChecker;

pub fn all_checkers() -> Vec<Box<dyn ServiceChecker>> {
    vec![
        Box::new(http::HttpChecker),
        Box::new(mysql::MysqlChecker),
        Box::new(redis::RedisChecker),
    ]
}
