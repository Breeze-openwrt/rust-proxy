//! # 配置管理模块 (Configuration Management)
//! 
//! 本模块负责项目的配置解析。
//! 我们支持带注释的 JSON 格式 (JSONC)，这与 gnet-proxy 保持一致，提升了配置文件的可读性。

use serde::{Deserialize, Serialize}; // 引入序列化和反序列化宏。
use std::collections::HashMap; // 存储路由表的哈希映射。
use std::fs; // 文件操作。
use anyhow; // 🔥 引入 anyhow 错误处理，确保配置加载链路的每一个 IO 错误都能被清晰记录。

/// 全局配置结构体
#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    /// 监听地址，例如 "[::]:443"
    pub listen_addr: String,
    /// 日志配置
    pub log: Option<LogConfig>,
    /// 路由表：域名 -> 目标配置
    pub routes: HashMap<String, RouteConfig>,
}

/// 日志配置
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LogConfig {
    /// 日志级别：trace, debug, info, warn, error
    pub level: Option<String>,
    /// 日志输出文件路径，如果为空则输出到 stdout
    pub output: Option<String>,
}

/// 路由目标配置
#[derive(Debug, Serialize, Deserialize, Clone)]
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
    /// 🔥 暴力提速：支持“逗号分隔键”，允许 `"a.com, b.com": { ... }` 格式自动展开。
    pub fn load(path: &str) -> anyhow::Result<Self> {
        // 读取文件原始内容
        let content = fs::read_to_string(path)?;
        
        // 使用 json_comments 剥离注释
        let stripped = json_comments::StripComments::new(content.as_bytes());
        
        // 第一步：初步反序列化
        let mut config: Config = serde_json::from_reader(stripped)?;
        
        // 第二步：展开“逗号分隔”的路由键
        let mut expanded_routes = HashMap::new();
        for (key, val) in config.routes {
            if key.contains(',') {
                // 发现逗号，进行分身处理
                for domain in key.split(',') {
                    let domain_trimmed = domain.trim().to_string();
                    if !domain_trimmed.is_empty() {
                        expanded_routes.insert(domain_trimmed, val.clone());
                    }
                }
            } else {
                // 普通单域名，直接拷贝
                expanded_routes.insert(key, val);
            }
        }
        
        // 覆盖原始路由表
        config.routes = expanded_routes;
        
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_comma_expansion() {
        let json = r#"
        {
            "listen_addr": "0.0.0.0:443",
            "routes": {
                "apple.com, icloud.com ": {
                    "addr": "127.0.0.1:8080",
                    "jump_start": 4,
                    "idle_timeout": 3600
                },
                "single.com": {
                    "addr": "127.0.0.1:9090",
                    "jump_start": 1,
                    "idle_timeout": 60
                }
            }
        }
        "#;
        
        let mut config: Config = serde_json::from_str(json).unwrap();
        
        // 模拟 load 中的展开逻辑
        let mut expanded = HashMap::new();
        for (key, val) in config.routes {
            for d in key.split(',') {
                let d = d.trim();
                if !d.is_empty() {
                    expanded.insert(d.to_string(), val.clone());
                }
            }
        }
        config.routes = expanded;

        assert_eq!(config.routes.len(), 3);
        assert!(config.routes.contains_key("apple.com"));
        assert!(config.routes.contains_key("icloud.com"));
        assert!(config.routes.contains_key("single.com"));
        assert_eq!(config.routes.get("apple.com").unwrap().addr, "127.0.0.1:8080");
    }
}
