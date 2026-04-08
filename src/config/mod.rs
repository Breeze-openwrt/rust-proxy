//! # 配置管理模块 (Configuration Management)
//! 
//! 本模块负责项目的配置解析。
//! 我们支持带注释的 JSON 格式 (JSONC)，这与 gnet-proxy 保持一致，提升了配置文件的可读性。

use serde::{Deserialize, Serialize}; // 引入序列化和反序列化宏。
use std::collections::HashMap; // 存储路由表的哈希映射。
use std::fs; // 文件操作。

/// 全局配置结构体
#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    /// 监听地址，例如 "[::]:443"
    pub listen_addr: String,
    /// 路由表：域名 -> 目标配置
    pub routes: HashMap<String, RouteConfig>,
}

/// 路由目标配置
#[derive(Debug, Serialize, Deserialize)]
pub struct RouteConfig {
    /// 目标后端 TCP 地址，例如 "tcp://127.0.0.1:10443"
    pub addr: String,
    /// 连接预热数量 (JumpStart)
    pub jump_start: usize,
    /// 空闲连接超时时间（秒）
    pub idle_timeout: u64,
}

impl Config {
    /// 从文件中加载配置
    /// 
    /// 支持跳过 JS 风格的注释 (//)，使得配置文件更易维护。
    pub fn load(path: &str) -> anyhow::Result<Self> {
        // 读取文件原始内容
        let content = fs::read_to_string(path)?;
        
        // 使用 json_comments 剥离注释
        let stripped = json_comments::StripComments::new(content.as_bytes());
        
        // 反序列化为 Rust 结构体
        let config: Config = serde_json::from_reader(stripped)?;
        
        Ok(config)
    }
}
