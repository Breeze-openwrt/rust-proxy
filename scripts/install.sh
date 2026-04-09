#!/bin/bash

# =============================================================================
# 🚀 Rust-Proxy: 一键部署脚本 (Systemd 集成)
# =============================================================================

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}====================================================${NC}"
echo -e "${BLUE}   🛡️  Rust-Proxy 自动化安装程序 (Industrial Grade)  ${NC}"
echo -e "${BLUE}====================================================${NC}"

# 1. 权限检查
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}❌ 请以 root 权限运行此脚本 (或使用 sudo)${NC}"
  exit 1
fi

# 2. 检查编译环境
echo -e "${YELLOW}🛠️  检测编译环境...${NC}"
if ! command -v cargo &> /dev/null; then
    echo -e "${RED}❌ 错误: 未检测到 Rust 环境 (cargo). 请先安装 Rust.${NC}"
    exit 1
fi

# 3. 编译主程序 (核心逻辑)
echo -e "${YELLOW}🍳 开始编译 Rust-Proxy (Release 模式)...${NC}"
# 注意：我们假设 ebpf.o 已经在 resources/ 目录下准备就绪
# 如果没有，尝试从 target 寻找
if [ ! -f "src/resources/ebpf.o" ]; then
    echo -e "${BLUE}🔍 探测内核字节码...${NC}"
    EBPF_PATH=$(find target/bpfel-unknown-none/release -type f -name "rust_proxy_ebpf_kernel" | head -n 1)
    if [ -n "$EBPF_PATH" ]; then
        mkdir -p src/resources
        cp "$EBPF_PATH" src/resources/ebpf.o
    else
        echo -e "${YELLOW}⚠️  警告: 未在运行目录发现内核字节码，编译可能使用“内置占位符”。${NC}"
    fi
fi

cargo build --release --package rust-proxy

BINARY_PATH="target/release/rust-proxy"
if [ ! -f "$BINARY_PATH" ]; then
    echo -e "${RED}❌ 错误: 编译失败，未找到二进制文件。${NC}"
    exit 1
fi

# 4. 安装文件分发
echo -e "${YELLOW}🚚 正在分发程序文件...${NC}"
# 拷贝二进制
cp "$BINARY_PATH" /usr/local/bin/rust-proxy
chmod +x /usr/local/bin/rust-proxy

# 创建配置目录
mkdir -p /etc/rust-proxy
if [ ! -f "/etc/rust-proxy/config.jsonc" ]; then
    echo -e "${BLUE}📝 初始化默认配置文件...${NC}"
    cp config.jsonc /etc/rust-proxy/config.jsonc
fi

# 5. 系统服务安装
echo -e "${YELLOW}⚙️  安装 Systemd 服务...${NC}"
if [ -f "scripts/rust-proxy.service" ]; then
    cp scripts/rust-proxy.service /etc/systemd/system/rust-proxy.service
else
    # ... (原有 fallback 逻辑保持不变)
    cat <<EOF > /etc/systemd/system/rust-proxy.service
[Unit]
Description=Rust-Proxy Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/rust-proxy -c /etc/rust-proxy/config.jsonc
WorkingDirectory=/etc/rust-proxy
Restart=always
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_ADMIN
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_ADMIN
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
EOF
fi

# 确保卸载脚本可执行
if [ -f "scripts/uninstall.sh" ]; then
    chmod +x scripts/uninstall.sh
fi

# 6. 激活服务
echo -e "${YELLOW}🚀 正在启用并启动服务...${NC}"
systemctl daemon-reload
systemctl enable rust-proxy
systemctl restart rust-proxy

echo -e "${GREEN}====================================================${NC}"
echo -e "${GREEN}✅ Rust-Proxy 安装圆满完成！${NC}"
echo -e "${BLUE}📊 运行状态: systemctl status rust-proxy${NC}"
echo -e "${BLUE}📜 实时日志: journalctl -u rust-proxy -f${NC}"
echo -e "${BLUE}🧨 卸载方式: sudo ./scripts/uninstall.sh${NC}"
echo -e "${GREEN}====================================================${NC}"
