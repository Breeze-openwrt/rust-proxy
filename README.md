# 🚀 Rust-Proxy: 基于 io_uring & eBPF 的暴力分流加速引擎

[![CI](https://github.com/Breeze-openwrt/rust-proxy/actions/workflows/bin-release.yml/badge.svg)](https://github.com/Breeze-openwrt/rust-proxy/actions/workflows/bin-release.yml)
[![Version](https://img.shields.io/badge/version-v0.1.0-blue.svg)](https://github.com/Breeze-openwrt/rust-proxy/releases/latest)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**Rust-Proxy** 是专为高性能场景打造的、基于内核特性的 SNI 自适应代理服务器。它不满足于仅仅能跑，它追求的是**榨干每一丝频率，瞬移每一份报文**。

---

## ✨ 核心黑科技 (Killer Features)

- **⚡ io_uring 运行时**: 基于 `monoio` 实现 Thread-per-core 架构，彻底消除异步 I/O 的上下文切换。
- **🛡️ eBPF SockMap**: 将转发逻辑下沉至 Linux 内核，实现数据包在 Socket 间的“原地瞬移”，中继阶段 0 内存拷贝。
- **🧠 零拷贝 SNI 嗅探**: 使用 `tls-parser` 工业级解析器，无需解密加密流量即可实现智能分流。
- **🔥 物理级调优**: 自动应用 `TCP_QUICKACK`、`SO_REUSEPORT` 及 4MB 巨型内核缓冲区。
- **💎 指令集提速**: 自动为现代 CPU (AVX2/FMA) 进行分层优化编译。

---

## 📂 项目知识库 (Documentation)

为了方便 AI 开发者和人类协作，我们建立了详尽的文档体系：

| 文档名称 | 描述 | 点击进入 |
| :--- | :--- | :--- |
| **需求定义** | 业务愿景与核心诉求 | [📖 PRD.md](./docs/PRD.md) |
| **架构原理** | 系统分层、io_uring 与 eBPF 细节 | [🏗️ ARCHITECTURE.md](./docs/ARCHITECTURE.md) |
| **开发标准** | 内核调优红线与代码规范 | [📏 STANDARDS.md](./docs/STANDARDS.md) |
| **发布指南** | CPU 分层编译与 CI 逻辑 | [🚀 CI_CD.md](./docs/CI_CD.md) |
| **演进路线** | 我们的过去、现在与未来 | [🗺️ ROADMAP.md](./docs/ROADMAP.md) |

---

## 🛠️ 快速开始

### 本地构建 (需 Linux 内核 5.10+)
```bash
# 构建用户态程序
cargo build --release --package rust-proxy

# 构建内核态 eBPF 模块 (需 nightly)
cd rust-proxy-ebpf && cargo build --release --target bpfel-unknown-none -Z build-std=core
```

### 生产部署 (推荐)
直接在 [Releases](https://github.com/Breeze-openwrt/rust-proxy/releases) 页面下载针对您架构优化的二进制包：
- `rust-proxy-linux-amd64-v3`: 开启 AVX2 指令集，速度最快。
- `rust-proxy-linux-amd64-std`: 传统架构，兼容性最强。

---

## 🤝 贡献与参与

本项目坚持 **First Principles Thinking (第一性原理)** 驱动。所有的改动应优先考虑其在 Linux 内核层面的性能开销。

维护者: **[Breeze-openwrt](https://github.com/Breeze-openwrt)** & **Antigravity (AI)**

---

> [!IMPORTANT]
> **AI 开发指南**: 请务必在开始任何功能扩展前，先阅读 [开发标准](./docs/STANDARDS.md)，保持项目的暴力提速基因。
