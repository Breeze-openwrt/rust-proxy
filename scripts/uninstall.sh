#!/bin/bash

# =============================================================================
# 🧨 Rust-Proxy: 一键卸载脚本 (Systemd 集成)
# =============================================================================

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${RED}====================================================${NC}"
echo -e "${RED}   🧹  Rust-Proxy 卸载程序 (Graceful Clean)         ${NC}"
echo -e "${RED}====================================================${NC}"

# 1. 权限检查
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}❌ 请以 root 权限运行此脚本 (或使用 sudo)${NC}"
  exit 1
fi

# 2. 停止服务
echo -e "${YELLOW}🛑 停止并禁用 Rust-Proxy 服务...${NC}"
systemctl stop rust-proxy || true
systemctl disable rust-proxy || true

# 3. 删除服务文件
echo -e "${YELLOW}🗑️  移除 Systemd 配置文件...${NC}"
rm -f /etc/systemd/system/rust-proxy.service
systemctl daemon-reload

# 4. 删除二进制文件
echo -e "${YELLOW}🗑️  移除主程序 (/usr/local/bin)...${NC}"
rm -f /usr/local/bin/rust-proxy

# 5. 删除配置目录 (询问用户)
echo -e "${YELLOW}❓ 是否删除配置目录 /etc/rust-proxy? (y/N)${NC}"
read -r response
if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
    rm -rf /etc/rust-proxy
    echo -e "${GREEN}✅ 配置目录已移除。${NC}"
else
    echo -e "${BLUE}ℹ️  保留配置目录以备不时之需。${NC}"
fi

# 6. 删除 PID 文件
rm -f /var/run/rust-proxy.pid
rm -f /tmp/rust-proxy.pid

echo -e "${GREEN}====================================================${NC}"
echo -e "${GREEN}✨ Rust-Proxy 已从系统中彻底清除。${NC}"
echo -e "${GREEN}====================================================${NC}"
