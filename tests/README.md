# DefaultHound 测试环境

用 Docker Compose 拉起一组内置服务（均无认证/默认凭据），全部暴露在**同一个 Docker 内部 IP** 上，模拟扫描一个多端口开放的外网 IP。

---

## 架构

```
┌── Docker Network: 172.20.0.0/24 ──────────────────────┐
│                                                         │
│  172.20.0.2  ─── Gateway (socat) ─── 端口聚合器         │
│     │          │          │          │          │       │
│     │          │          │          │          │       │
│  172.20.0.10  .11       .12       .13       .14     .15│
│  redis   memcached  mongodb  couchdb  es        ftp    │
│  :6379    :11211    :27017   :5984    :9200    :21     │
│                                                         │
│  Scanner (alpine) ──── defaulthound 172.20.0.2          │
└─────────────────────────────────────────────────────────┘
```

关键点：

- 每个后端服务有独立的 **Docker 静态 IP**（`172.20.0.10` ~ `.15`）
- **Gateway** 容器用 `socat` 把 6 个端口全部转发到 **同一个 IP `172.20.0.2`**
- 扫描时只需要指向 **`172.20.0.2`**，所有 Checker 都会命中对应的服务端口
- **不需要 `sudo`**，不需要配 loopback alias，纯 Docker 网络

---

## 包含的服务

| 服务 | 端口 | 内部 IP | 类型 | 镜像 | Checker 检测方式 | 预期结果 |
|------|------|---------|------|------|------------------|----------|
| Redis | 6379 | 172.20.0.10 | TCP | `redis:alpine` | 发送 `PING`，期待 `+PONG` | **VULN** — 无需认证 |
| Memcached | 11211 | 172.20.0.11 | TCP | `memcached:alpine` | 发送 `stats`，期待 `STAT` | **VULN** — 无需认证 |
| MongoDB | 27017 | 172.20.0.12 | TCP | `mongo:7` | 发送 `ping`，期待 `ok` | **VULN** — 无需认证 |
| CouchDB | 5984 | 172.20.0.13 | TCP (HTTP) | `couchdb:2.3.1` | `GET /_all_dbs`，期待 `200` / `[` | **VULN** — Admin Party |
| Elasticsearch | 9200 | 172.20.0.14 | HTTP | `elasticsearch:7.17.25` | `GET /_cat/indices`，期待 `green`/`yellow` | **VULN** — 未授权访问 |
| FTP | 21 | 172.20.0.15 | TCP | `fauria/vsftpd` | USER anonymous + PASS anonymous@example.com | **VULN** — 匿名登录 |

> 注：以上均为**无认证 / 默认凭据**配置，`defaulthound` 应检出 `[VULN]` 结果。
> 如果某个服务显示 `安全` 或 `错误`，说明 Checker 实现或环境配置有问题。

---

## 快速开始

### 1. 启动服务

```bash
docker compose -f tests/docker-compose.yml up -d
```

首次启动会自动拉取 6 个镜像。Elasticsearch 需约 20-30 秒完成初始化。

### 2. 扫描（两种方式）

#### 方式 A：从宿主机扫描（通过端口映射）

所有端口已 publish 到宿主机，可直接扫描 localhost：

```bash
cargo run --release
```

等价于：

```bash
cargo run --release -- 127.0.0.1
```

#### 方式 B：从 Docker 内部扫描（⭐ 推荐 — 模拟"非本机"）

将编译好的二进制挂载到 Alpine 容器中，在 Docker 网络内扫描 `172.20.0.2`：

```bash
bash tests/setup.sh scan:docker
```

或手动：

```bash
# 编译
cargo build --release

# 在 Docker 内部运行
docker run --rm \
  --network defaulthound_defaulthound-net \
  -v "$(pwd)/target/release/defaulthound:/defaulthound:ro" \
  alpine:latest \
  sh -c "apk add --no-cache libgcc && /defaulthound 172.20.0.2"
```

### 预期输出

```
[Redis] 172.20.0.2:6379          ⚠ 高危  无需认证 Redis 服务未配置密码认证，可任意访问
[Memcached] 172.20.0.2:11211     ⚠ 高危  无需认证 Memcached 未授权访问
[MongoDB] 172.20.0.2:27017       ⚠ 高危  无需认证 MongoDB 未授权访问
[CouchDB] 172.20.0.2:5984        ⚠ 高危  无需认证 CouchDB 未授权访问
[Elasticsearch] 172.20.0.2:9200  ⚠ 高危  无需认证 Elasticsearch 未授权访问
[FTP] 172.20.0.2:21              ⚠ 高危  anonymous:anonymous@example.com FTP 匿名登录成功
...
---
总计 40  ✓ 安全 34  ⚠ 高危 6
```

> `总计 40` 是因为所有 40 个 Checker 都会运行，其中 34 个针对未开放服务返回 `安全`，6 个靶向服务返回 `VULN`。

### 3. 清理

```bash
docker compose -f tests/docker-compose.yml down -v
```

---

## 一键管理脚本

```bash
# 启动
bash tests/setup.sh start

# 检查服务状态
bash tests/setup.sh status

# 从宿主机扫描
bash tests/setup.sh scan

# 从 Docker 内部扫描（推荐）
bash tests/setup.sh scan:docker

# 查看网络 IP
bash tests/setup.sh list

# 清理
bash tests/setup.sh stop
```

---

## Gateway 工作原理

Gateway 容器使用 `socat` 创建 6 个 TCP 端口转发：

```bash
socat TCP-LISTEN:6379,fork,reuseaddr TCP:redis:6379 &
socat TCP-LISTEN:11211,fork,reuseaddr TCP:memcached:11211 &
# ... 以此类推
wait
```

- 每个 `socat` 进程监听 Gateway 的一个端口
- 收到连接后 fork 并转发到后端服务的内网 IP
- Gateway 通过 `depends_on` 确保后端先启动
- `reuseaddr` 允许快速重启

---

## 自定义扫描

### 仅测试开放端口

```bash
echo "172.20.0.2:6379,11211,27017" | cargo run --release -- --stdin
```

或通过文件：

```bash
echo "172.20.0.2:9200" > /tmp/targets.txt
cargo run --release -- -f /tmp/targets.txt
```

### 调整并发

```bash
cargo run --release -- -r 50 172.20.0.2
```

### 导出结果

```bash
cargo run --release -- 172.20.0.2 -j result.json --csv result.csv
```

---

## 扩展：添加更多服务

在 `docker-compose.yml` 中新增 service，然后在 Gateway 中追加 socat 转发：

```yaml
# 示例：添加 Jenkins (8080)
jenkins:
  image: jenkins/jenkins:lts-jdk11
  container_name: dh-jenkins
  networks:
    defaulthound-net:
      ipv4_address: 172.20.0.20
```

在 Gateway 的 `command` 中追加一行：

```yaml
socat TCP-LISTEN:8080,fork,reuseaddr TCP:jenkins:8080 &
```

确保端口不冲突，且 Checker 的 `default_port()` 与暴露端口一致。

---

## 常见问题

### Q: 为什么用 172.20.0.x 而不是 127.0.0.2？

`127.0.0.2` 需要 `sudo` 添加 loopback alias（`sudo ifconfig lo0 alias 127.0.0.2`），跨平台不一致。`172.20.0.2` 是纯 Docker 虚拟 IP，无需任何系统权限。

### Q: Elasticsearch 无法启动

确保 Docker Engine 分配了至少 2GB 内存（Docker Desktop → Settings → Resources → Memory）。ES 默认需要 1GB+ JVM heap。

### Q: CouchDB 返回 401

`couchdb:3+` 默认关闭了 Admin Party 模式。本环境使用 `couchdb:2.3.1` 锁定 v2 以确保无认证访问。

### Q: FTP 连接失败

FTP passive mode 需要额外端口，已在 compose 中映射 `21100:21100`。但 Checker **只测试控制连接**（USER/PASS），不会实际传输文件，所以 passive 配置不影响检测结果。

### Q: 端口冲突

如果宿主机已有服务占用 6379 等端口，修改 `ports` 左侧的 host 端口（如 `"6380:6379"`）。从 Docker 内部扫描不受影响（直接走内部 IP）。

### Q: 从宿主机怎么扫描非 localhost IP？

- **macOS Docker Desktop**：published ports 绑定在 `0.0.0.0`，局域网其他机器可通过你的 LAN IP（如 `192.168.1.x`）访问
- **Linux**：可直接扫描 `172.20.0.2`，Docker bridge 默认可从宿主机路由

---

## 文件结构

```
tests/
├── README.md          # 本文件
├── docker-compose.yml # 服务编排（Gateway + 6 个后端）
├── setup.sh           # 一键管理脚本
└── scan.sh            # Docker 内部扫描脚本
```
