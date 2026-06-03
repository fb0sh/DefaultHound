# DefaultHound

批量检测服务默认密码/空密码的安全扫描工具，Rust 实现。内置 40 个服务检测器，基于 Tokio 异步并发，支持批量扫描、JSON/CSV 导出。

## 安装

```bash
cargo install defaulthound
```

或从源码构建：

```bash
git clone <repo-url>
cd default_hound
cargo install --path .
```

## 使用

```bash
# 扫描 localhost
defaulthound

# 扫描指定 IP
defaulthound 192.168.1.1

# 从文件批量扫描
defaulthound -f targets.txt

# 从 stdin 输入
cat targets.txt | defaulthound

# 列出所有可检测的服务
defaulthound -l

# 导出结果
defaulthound -f targets.txt -j result.json --csv result.csv

# 调高速率
defaulthound -f targets.txt -r 100
```

### 输出格式

```
[MySQL] 127.0.0.1:3306  安全  端口未开放
[VULN][Redis](无需认证) 192.168.1.5:6379
[ERR][Docker] 10.0.0.1:2375  连接超时
---
总计 40  安全 38  高危 2
```

`[VULN]` 行可直接被 grep 提取。

## 内置服务 (40 个)

| TCP Socket (12) | HTTP/Web (26) | 已有 (2) |
|----------------|---------------|----------|
| FTP, ZooKeeper, MongoDB, LDAP, VNC, Memcached, NFS, Dubbo, Rsync, SMB, uWSGI, CouchDB | Docker, DockerRegistry, Elasticsearch, Jenkins, Kibana, Kubernetes, Jupyter, Nacos, Ollama, Spark, WebLogic, Hadoop, JBoss, ActiveMQ, Zabbix, RabbitMQ, Solr, Harbor, WordPress, Crowd, Kong, ThinkAdmin, Swagger, SpringBoot, Druid, RuoYi | MySQL, Redis |

## 架构

```text
src/
├── lib.rs              # ServiceChecker trait + CheckResult + Credential
├── prelude.rs           # 公共导入
├── bin/
│   ├── defaulthound.rs  # CLI 批量扫描
│   └── defaulthound-gui.rs  # GUI 占位
└── checkers/
    ├── mod.rs           # 注册中心
    ├── http_helpers.rs  # HTTP 检测辅助函数
    ├── mysql.rs         # MySQL
    ├── redis.rs         # Redis
    ├── ftp.rs           # ...
    └── ...              # 每个服务独立文件
```

## 添加一个新的 Service Checker

```rust
use crate::prelude::*;

pub struct MyService;

#[async_trait]
impl ServiceChecker for MyService {
    fn service_name(&self) -> &'static str { "MyService" }
    fn default_port(&self) -> u16 { 1234 }
    fn default_credentials(&self) -> Vec<Credential> { vec![
        Credential::new("admin", "admin"),
    ]}
    async fn check(&self, ip: &str, port: Option<u16>) -> CheckResult {
        let port = port.unwrap_or(self.default_port());
        let mut stream = try_connect!(self, ip, port);
        // 检测逻辑...
        CheckResult::Vulnerable {
            credentials: "admin:admin".into(),
            details: "默认凭据有效".into(),
        }
    }
}
```

在 `mod.rs` 加两行：

```diff
+ mod my_service;
  fn all_checkers() -> Vec<Box<dyn ServiceChecker>> {
      vec![
+         Box::new(my_service::MyService),
      ]
  }
```

## 参考项目

灵感来源于：

- **[Unauthorized_VUl](https://github.com/hackerchuan1/Unauthorized_VUl)** — Python 实现，40+ 未授权漏洞检测
- **[Unauthorized_VUL_GUI](https://github.com/phoenix118go/Unauthorized_VUL_GUI)** — PyQt6 GUI 版本
- **[Unauth-Vuln-Scanner](https://github.com/willsafe/Unauth-Vuln-Scanner)** — Java Swing GUI
- **[unauthorized](https://github.com/xk11z/unauthorized)** — Python 命令行版

## License

MIT
