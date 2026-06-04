# DefaultHound

批量检测服务默认密码/空密码的安全扫描工具，Rust 实现。内置 40 个服务检测器，基于 Tokio 异步并发，支持批量扫描、JSON/CSV 导出。

提供 **GUI（egui 原生桌面）** 和 **CLI（命令行）** 两种使用方式。

## 🚀 特色亮点

### 革命性的 `ip:service^port` 语法

```
192.169.33.12:redis^7789
```

**以前的做法：** Redis 跑在 7789 端口上？你得找到 checker 源码，把 `default_port` 从 6379 改成 7789，重新编译，扫完再改回来。换个端口改一次代码。

**DefaultHound 的革命性方案：** 直接写 `192.169.33.12:redis^7789`——`redis` 是指定**使用 Redis 检测器**，`7789` 是传进去的**端口参数**。

- ✅ **不改一行代码**——端口是运行时参数，不是编译时常量
- ✅ **按需指定检测器**——`service^` 前缀精确选择 checker，不匹配的服务根本不跑
- ✅ **一个目标多个 checker**——`192.168.1.1:redis^6379,mysql^3306` 一行搞定，各自用自己的检测器
- ✅ **非标准端口零成本**——Redis 改端口了？直接`redis^7780`，无需改代码、无需重编译

> 传统工具只能扫**固定端口的固定服务**；DefaultHound 让你**任意端口 + 任意检测器自由组合**。

---

## 🖥️ GUI 使用

DefaultHound 提供基于 **egui** 的原生桌面 GUI，无需任何系统依赖（不依赖 WebView、Java、Python）。

### 启动

```bash
defaulthound-gui
```

### 界面布局
<img width="1570" height="943" alt="image" src="https://github.com/user-attachments/assets/da661478-6e8b-4f62-a986-40f5fbe589ff" />

<img width="1570" height="943" alt="image" src="https://github.com/user-attachments/assets/bd8c4baf-7500-4148-b453-6ad6fe2437b6" />


<img width="1570" height="943" alt="image" src="https://github.com/user-attachments/assets/e53afdf0-96ba-439c-a1c1-17266b3fbba1" />

<img width="731" height="377" alt="image" src="https://github.com/user-attachments/assets/a68ba5db-a944-4f23-a2c7-21499c174488" />


<img width="1570" height="943" alt="image" src="https://github.com/user-attachments/assets/b8f6f2fa-dd4c-48d6-91ae-052768fc18c2" />



### 功能特性

| 功能 | 说明 |
|------|------|
| **三栏布局** | 左侧目标管理、中间扫描结果、右侧统计面板 |
| **目标管理** | 支持 IP、`ip:service^port` 格式输入，复选框启用/禁用，右键复制目标 |
| **双视图结果** | **日志视图**（实时彩色流水）和 **漏洞表格**（仅高危，可排序/搜索） |
| **右键菜单** | 复制 IP:Port、复制凭据、复制详细信息、复制服务标识 |
| **统计面板** | 高危/安全/错误计数，实时更新 |
| **进度条** | 底部状态栏显示进度百分比、已扫描数、高危计数 |
| **并发控制** | 可拖拽调整并发速率（1~1000） |
| **搜索过滤** | 按服务名、IP、端口搜索；"Vulns only" 仅显示漏洞 |
| **导出 CSV** | 一键导出扫描结果到 CSV 文件 |
| **亮色/暗色** | 顶部控制栏一键切换 Light / Night 主题 |
| **代理设置** | 内置弹窗设置 SOCKS5/HTTP 代理，支持保存/清除 |
| **扫描控制** | 开始扫描 / 停止扫描 |
| **清除结果** | 一键清空扫描结果 |

### GUI 快捷键

| 快捷键 | 功能 |
|--------|------|
| `Cmd + W` | 关闭窗口 |
| `Cmd + M` | 最小化窗口 |

---

## 💻 CLI 使用

### 安装

```bash
cargo install defaulthound
```

或从源码构建：

```bash
git clone <repo-url>
cd default_hound
cargo install --path .
```

### 命令

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

# 仅显示高危结果
defaulthound -f targets.txt -v

# 通过代理扫描
defaulthound -f targets.txt -p socks5://127.0.0.1:1080

# HTTP 代理
defaulthound 192.168.1.1 --proxy http://proxy:8080
```

### 目标格式

目标文件每行支持以下格式：

| 格式 | 说明 | 示例 |
|------|------|------|
| `ip` | 扫描所有服务（各自默认端口） | `192.168.1.1` |
| `ip:port` | 只扫描匹配该端口的服务 | `192.168.1.1:3306` → 仅 MySQL |
| `ip:port1,port2` | 只扫描匹配这些端口的服务 | `192.168.1.1:3306,6379` → MySQL + Redis |
| `ip:service^port` | 指定服务 + 非标端口 | `192.168.1.1:redis^6379` |
| `ip:service^port1,service2^port2` | 多个服务各自指定端口 | `192.168.1.1:redis^6379,mysql^6380` |
| `ip:service^` | 指定服务 + 默认端口 | `192.168.1.1:redis^` |

#### ⭐ 核心创新：`service^` 前缀

`192.169.33.12:redis^7789` 这一行体现了 DefaultHound 最核心的设计思想：

- **`redis`** = 指名道姓用 Redis checker
- **`7789`** = 告诉 checker 连这个端口

| 对比项 | 传统工具 | **DefaultHound** |
|--------|---------|------------------|
| 非标端口 | ❌ 改源码改 `default_port` 再编译 | ✅ `ip:redis^7789` 一行搞定 |
| 检测器选择 | ❌ 只能扫默认端口绑定的服务 | ✅ `service^` 前缀精确指定 checker |
| 混扫多种服务 | ❌ 改完 Redis 再改 MySQL，反复改代码 | ✅ 同一文件写 `ip:redis^6379` 和 `ip:mysql^3306` |
| 端口与服务解耦 | ❌ 端口硬编码在 checker 里 | ✅ 端口是运行时参数，checker 和端口自由组合 |

服务名不区分大小写（`Redis`、`redis`、`REDIS` 均可）。带 `service^` 前缀时**只运行该服务的检测器**，不会浪费时间去扫其他服务。

**实战场景：** 内网 Redis 集群端口各不相同（6379、7789、9001），只需一行一个 `ip:redis^port`，全部用 Redis checker 精准扫描——不用改一行 Rust 代码。

### 输出格式

```
[MySQL] 127.0.0.1:3306  安全  端口未开放
[VULN][Redis](无需认证) 192.168.1.5:6379
[ERR][Docker] 10.0.0.1:2375  连接超时
────────────────────────────────────────
目标数 3  ✓ 安全 2  ⚠ 高危 1  DefaultHound
```

`[VULN]` 行可直接被 grep 提取。

统计按目标行数计算：一个目标只要有一个服务存在漏洞即计为高危。

使用 `-v`（`--vuln`）时只输出高危行：

```
defaulthound -f targets.txt -v
```

---

## 内置服务 (40 个)

| TCP Socket (12) | HTTP/Web (26) | 已有 (2) |
|----------------|---------------|----------|
| FTP, ZooKeeper, MongoDB, LDAP, VNC, Memcached, NFS, Dubbo, Rsync, SMB, uWSGI, CouchDB | Docker, DockerRegistry, Elasticsearch, Jenkins, Kibana, Kubernetes, Jupyter, Nacos, Ollama, Spark, WebLogic, Hadoop, JBoss, ActiveMQ, Zabbix, RabbitMQ, Solr, Harbor, WordPress, Crowd, Kong, ThinkAdmin, Swagger, SpringBoot, Druid, RuoYi | MySQL, Redis |

---

## 架构设计：checker 与端口解耦

DefaultHound 的核心架构创新是 **Service Checker 与目标端口解耦**。

```rust
// 每个 checker 只关心「怎么检测这个服务」，不关心「端口是什么」
#[async_trait]
pub trait ServiceChecker: Send + Sync {
    fn service_name(&self) -> &'static str;
    fn default_port(&self) -> u16;  // 只是默认值，随时可覆盖
    async fn check(&self, ip: &str, port: Option<u16>) -> CheckResult;
    //                            ^^^^^^^^^^ 端口由调用方传入
}
```

当用户写 `192.169.33.12:redis^7789` 时：

1. 解析器提取 `service = "redis"`、`ip = "192.169.33.12"`、`port = 7789`
2. 调度器只选中 `RedisChecker`（其他 39 个 checker 跳过）
3. `RedisChecker::check("192.169.33.12", Some(7789))` 被调用
4. 返回结果

> **不需要改 checker 源码、不需要重编译、不需要改默认端口。**
>
> 传统工具要扫非标端口只能改代码；DefaultHound 让你在**目标列表里**完成一切。

## 架构

```text
src/
├── lib.rs                  # ServiceChecker trait + CheckResult + Credential
├── prelude.rs              # 公共导入
├── bin/
│   ├── defaulthound.rs     # CLI 入口
│   └── defaulthound-gui.rs # GUI 入口（egui 原生桌面）
├── gui/                    # GUI 模块（计划中，当前在 bin 文件内）
├── checkers/
│   ├── mod.rs              # 注册中心
│   ├── http_helpers.rs     # HTTP 检测辅助函数
│   ├── mysql.rs            # MySQL
│   ├── redis.rs            # Redis
│   ├── ftp.rs              # ...
│   └── ...                 # 每个服务独立文件
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
