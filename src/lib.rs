//! # Rust-Proxy 核心库
//! 
//! 本库包含了高性能 SNI 分流代理的所有核心逻辑。
//! 
//! 分层结构：
//! - `domain`: 业务领域模型和解析逻辑。
//! - `application`: 业务编排和转发控制。
//! - `infra`: 底层网络和硬件加速抽象。
//! - `config`: 系统配置。

pub mod domain;
pub mod application;
pub mod infra;
pub mod config;

// --- 符号聚合 (Global Symbol Aggregation) ---
// 为了让深层模块能直接使用这些核心库，我们在入口文件进行统一声明。
pub use ::anyhow; // 让 Result 处理变得像呼吸一样自然
pub use ::libc;   // 搭建起通往 Linux 内核原生接口的桥梁
