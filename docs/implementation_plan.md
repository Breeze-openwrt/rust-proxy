# Rust-Proxy 高性能 SNI 分流代理开发计划

本项目旨在利用 Rust 的内存安全和零开销抽象，结合 Linux 最新的 `io_uring` 异步 I/O 接口和 `eBPF` 内核加速技术，打造一个超越传统代理的高性能转发服务器。

## 核心设计理念

1.  **First Principles Thinking（第一性原理思维）**: 减少不必要的上下文切换，利用 `io_uring` 实现零拷贝（Zero-copy）和批处理 I/O。
2.  **KISS (Keep It Simple, Stupid)**: 简单的架构往往更稳定、更高能。
3.  **性能狂魔**: 每一微秒的延迟都在优化范围内。
4.  **易懂性**: 为每一行代码提供详尽的中文注释，解释底层原理和设计意图。

## 用户评审要求

> [!IMPORTANT]
> - 本项目将深度依赖 Linux `io_uring` 这一特性，因此在非 Linux 环境（如 Windows）下编译可能需要特定处理（虽然开发在 Windows 上进行，但最终运行目标是 Linux 6.0+ 服务器）。
> - eBPF 的引入需要内核支持。我们将优先保证基于用户态 `io_uring` 的极致性能，再通过 eBPF 进一步下压延迟。

## 拟选技术栈

- **运行时**: `monoio` (基于 io_uring 的异步运行时)。
- **eBPF 框架**: `aya-rs` (纯 Rust 实现的 eBPF 编程框架)。
- **网络流解析**: 手撸极致性能的 TLS Client Hello 解析器（仅提取 SNI）。
- **并发管理**: `tokio` (工具类) + `crossbeam` (无锁数据结构)。
- **日志**: `tracing` + `tracing-subscriber` (高性能异步日志)。

## 拟议的变更计划

### 第一阶段：项目骨架与基础设施 [NEW]

- 初始化 `Cargo.toml`，配置 `nightly` 或稳定版 Rust。
- 搭建 `TDD` 环境。
- 引入 `docs` 体系，为后续“源码阅读导航”打好基础。

### 第二阶段：SNI 协议解析模块 (Domain Layer) [NEW]

- 实现 TLS Client Hello 的极致解析。
- 无需依赖大型 SSL 库，仅通过二进制协议头提取 SNI 字段。
- **验证**: 编写大量测试用例。

### 第三阶段：连接管理与转发核心 (Application Layer) [NEW]

- 使用 `monoio` 实现异步 TCP 服务器。
- 实现 `ConnectionPool`（连接池）与 `JumpStart` 机制。

### 第四阶段：eBPF 内核加速 (Infra Layer) [NEW]

- 编写 eBPF 程序进行转发加速。

## 开放性问题

> [!CAUTION]
> 1. **Windows 兼容性**: 在 Windows 上开发时，我们将使用 `monoio` 的 epoll/select 后端模拟，或直接在 WSL2 中进行测试。

## 验证计划

### 自动化测试
- 运行 `cargo test`。
- 使用 `wrk` 或 `h2load` 进行性能测试。
