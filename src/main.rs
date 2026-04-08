//! # Rust-Proxy 入口程序
//! 
//! 本模块是高性能 SNI 分流代理服务器的启动点。
//! 它负责初始化异步运行时、配置日志系统，并启动核心转发任务。
//! 
//! 设计原则：
//! 1. 极致性能：基于 monoio (io_uring)。
//! 2. 结构化日志：便于生产环境监控。

use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;
use rust_proxy::config::Config; // 引入配置模块。
use rust_proxy::application::proxy::server::ProxyServer; // 引入应用层的代理服务器实现。

/// 程序主入口
#[monoio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // --- 步骤 1: 初始化日志系统 ---
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("无法设置全局日志订阅者");

    info!("🚀 Rust-Proxy 高性能分流服务器启动中...");

    // --- 步骤 2: 加载配置文件 ---
    // 在实际运行中，我们可以从命令行参数获取路径，现在先默认加载当前目录。
    let config_path = "config.jsonc";
    let config = match Config::load(config_path) {
        Ok(c) => {
            info!("📖 配置文件加载成功: {}", config_path);
            c
        },
        Err(e) => {
            info!("⚠️ 无法读取 config.jsonc，正在使用默认配置示例。错误: {}", e);
            // 这里可以提供一个备用的硬编码默认配置以便快速启动
            return Err(e.into());
        }
    };

    // --- 步骤 3: 初始化并启动代理服务 ---
    // 我们的架构是分布式+分层的，ProxyServer 负责编排业务流程。
    let server = ProxyServer::new(config.listen_addr);
    
    // 启动主循环，由 monoio 接管异步调度。
    server.run().await?;

    Ok(())
}
