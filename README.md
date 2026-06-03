# DefaultHound

批量检测服务默认密码/空密码的安全扫描工具，Rust 实现。

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

> 即将发布到 [crates.io](https://crates.io)。

## 使用

```bash
# 扫描 localhost
defaulthound

# 扫描指定 IP
defaulthound 192.168.1.1

# 从文件批量扫描（每行一个 IP 或 IP:端口）
defaulthound -f targets.txt

# 从 stdin 输入
cat targets.txt | defaulthound

# 导出结果
defaulthound -f targets.txt -j result.json --csv result.csv

# 调高速率
defaulthound -f targets.txt -r 100
```

### 输出格式

```
[HTTP] 127.0.0.1:80  安全  端口 80 未开放
[VULN][MySQL](root:) 192.168.1.5:3306
[ERR][Redis] 10.0.0.1:6379  连接超时
---
总计 5  安全 3  高危 2
```

`[VULN]` 行可直接被 grep 等工具提取。

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
    ├── http.rs          # HTTP Basic Auth 爆破
    ├── mysql.rs         # MySQL 握手版本泄露
    └── redis.rs         # Redis 无认证 PING
```

## 开发：添加一个新的 Checker

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
        let mut stream = match self.try_tcp_connect(ip, port).await {
            Ok(s) => s,
            Err(r) => return r,
        };
        // 检测逻辑...
    }
}
```

然后在 `src/checkers/mod.rs` 加两行：

```diff
+ mod my_service;
  fn all_checkers() -> Vec<Box<dyn ServiceChecker>> {
      vec![
+         Box::new(my_service::MyService),
      ]
  }
```

## 参考项目

DefaultHound 的灵感来源于以下未授权访问检测工具：

- **[Unauthorized_VUl](https://github.com/hackerchuan1/Unauthorized_VUl)** — Python 实现，40+ 常见未授权漏洞检测，CLI 批量扫描
- **[Unauthorized_VUL_GUI](https://github.com/phoenix118go/Unauthorized_VUL_GUI)** — 基于 PyQt6 的 GUI 版本，支持自定义端口和 Excel 导出
- **[Unauth-Vuln-Scanner](https://github.com/willsafe/Unauth-Vuln-Scanner)** — Java Swing GUI，39+ 服务探测，SOCKS5 代理支持
- **[unauthorized](https://github.com/xk11z/unauthorized)** — Python 命令行版，支持多线程批量扫描

DefaultHound 采用 Rust 重写，将检测重心从"未授权访问"转向"默认密码/空密码"，以插件化架构提升协作效率。

## License

MIT
