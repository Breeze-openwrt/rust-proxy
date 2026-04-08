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
