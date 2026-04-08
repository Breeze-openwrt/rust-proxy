//! # 源码阅读导航 (Navigation)
//! 
//! 本项目采用 DDD (领域驱动设计) 分层架构，方便维护和扩展。

## 目录结构说明

- [ ] [src/main.rs](file:///d:/prj/mihhawork/rust-proxy/src/main.rs): **系统入口**。负责初始化日志、异步运行时环境。
- [ ] [src/domain/](file:///d:/prj/mihhawork/rust-proxy/src/domain/): **领域层**。包含业务核心逻辑，如 SNI 协议解析。
    - [src/domain/protocol/sni.rs](file:///d:/prj/mihhawork/rust-proxy/src/domain/protocol/sni.rs): 实现 TLS 握手解析。
- [ ] [src/application/](file:///d:/prj/mihhawork/rust-proxy/src/application/): **应用层**。协调领域层和基础设施层，实现业务流程。
    - [src/application/proxy/](file:///d:/prj/mihhawork/rust-proxy/src/application/proxy/): 核心代理转发流程。
- [ ] [src/infra/](file:///d:/prj/mihhawork/rust-proxy/src/infra/): **基础设施层**。实现外部依赖，如 io_uring 网络底层、eBPF 加速。
    - [src/infra/network/pool.rs](file:///d:/prj/mihhawork/rust-proxy/src/infra/network/pool.rs): 高性能连接池。
- [ ] [docs/](file:///d:/prj/mihhawork/rust-proxy/docs/): **文档中心**。存放设计方案和导航。

## 核心技术栈
- **Runtime**: monoio (io_uring)
- **Log**: tracing
- **Build**: Rust 2024 edition
