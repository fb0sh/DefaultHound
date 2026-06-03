#!/usr/bin/env bash
# =============================================================
# DefaultHound — 一键测试脚本
# =============================================================
# 1) docker compose up -d           ← 启动全部 6 个容器
# 2) wait_for_services              ← 等待端口就绪
# 3) cargo build --release          ← 编译 defaulthound
# 4) docker run ... defaulthound 172.20.0.2   ← 在 Docker 网络内扫描
# =============================================================
set -euo pipefail
cd "$(dirname "$0")/.."

COMPOSE_FILE="tests/docker-compose.yml"
NET_NAME="defaulthound_defaulthound-net"
GATEWAY_IP="172.20.0.2"

# ── 辅助：等待 TCP 端口可连接 ──
wait_port() {
  local ip=$1 port=$2 timeout=${3:-60}
  echo -n "  Waiting $ip:$port "
  for i in $(seq 1 "$timeout"); do
    if docker run --rm --network "$NET_NAME" alpine:latest \
         sh -c "nc -z -w 2 $ip $port" 2>/dev/null; then
      echo "  ✓"
      return 0
    fi
    echo -n "."
    sleep 2
  done
  echo "  ✗ timeout"
  return 1
}

# ── 1. 启动容器 ──
echo "━━━ 1. Starting containers ━━━━━━━━━━━━━━━━━━━━━━━━"
docker compose -f "$COMPOSE_FILE" up -d
echo ""

# ── 2. 等待服务就绪 ──
echo "━━━ 2. Waiting for services ─━━━━━━━━━━━━━━━━━━━━━━━"
wait_port "$GATEWAY_IP" 6379      # Redis
wait_port "$GATEWAY_IP" 11211     # Memcached
wait_port "$GATEWAY_IP" 27017     # MongoDB
wait_port "$GATEWAY_IP" 5984 90   # CouchDB (2.x, ~30s)
wait_port "$GATEWAY_IP" 9200 120  # Elasticsearch (~40s)
wait_port "$GATEWAY_IP" 21        # FTP
echo ""
