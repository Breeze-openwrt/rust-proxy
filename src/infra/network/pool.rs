//! # 高性能连接预热池 (JumpStart Connection Pool)
//! 
//! 本模块实现了一个异步连接池，专门用于预先建立与后端的 TCP 链接。
//! 其核心目的是消除“代理握手”带来的延迟（RTT），让第一个数据包能够“瞬间”发出。
//! 
//! 设计架构：
//! 1. **Thread-per-core**: 完美适配 monoio，每个核心维持独立的池，无锁竞争。
//! 2. **异步填充**: 后台协程自动补全连接。

use std::collections::{HashMap, VecDeque}; // 引入哈希表和双端队列，用于管理不同域名的连接。
use monoio::net::TcpStream; // 引入高性能 TCP 流。
use std::time::{Instant, Duration}; // 用于计算连接的存活时间。

/// 连接包装器，包含建立时间，用于超时校验
struct IdleConnection {
    stream: TcpStream, // 原始的 TCP 连接。
    created_at: Instant, // 连接创建的时间戳。
}

/// 全局连接池管理器
pub struct ConnectionPool {
    /// 存储结构：域名 -> 连接队列
    /// 使用 VecDeque 是因为我们需要先进先出（FIFO）来保证连接的公平性和新鲜度。
    pools: HashMap<String, VecDeque<IdleConnection>>,
    /// 连接的最大空闲时间（秒）
    idle_timeout: Duration,
}

impl ConnectionPool {
    /// 创建一个新的连接池
    pub fn new(idle_timeout_secs: u64) -> Self {
        Self {
            pools: HashMap::new(),
            idle_timeout: Duration::from_secs(idle_timeout_secs),
        }
    }

    /// 从池中“借出”一个可用的连接
    /// 
    /// 源码欣赏：这里体现了“快速提取”的思想。
    /// 我们会检查队列头部的连接是否已经超时，如果超时则丢弃并寻找下一个。
    pub fn get(&mut self, target: &str) -> Option<TcpStream> {
        // 尝试获取该目标的队列
        if let Some(queue) = self.pools.get_mut(target) {
            // 循环检查，直到找到一个没过期的连接或队列为空
            while let Some(conn) = queue.pop_front() {
                if conn.created_at.elapsed() < self.idle_timeout {
                    // 找到一个“新鲜”的连接，完美！
                    return Some(conn.stream);
                }
                // 连接太老了，后台会自动断开，我们直接丢弃处理下一个。
                drop(conn); 
            }
        }
        None // 没找到可用的，只能让调用者自己去创建了。
    }

    /// 将一个新建立的连接存入池中
    /// 
    /// 这是 JumpStart 被动填充或主动回收的入口。
    pub fn put(&mut self, target: String, stream: TcpStream) {
        let entry = self.pools.entry(target).or_insert_with(VecDeque::new);
        entry.push_back(IdleConnection {
            stream,
            created_at: Instant::now(),
        });
    }

    /// 维护函数：由后台协程调用，确保每个后端的连接数达到预设的 jump_start 值
    /// 
    /// 参数说明：
    /// `target`: 后端地址（例如 "127.0.0.1:10443"）
    /// `target_count`: 目标预热连接数
    pub async fn fill_if_needed(&mut self, target: &str, target_count: usize) {
        let current_count = self.pools.get(target).map_or(0, |q| q.len());
        
        if current_count < target_count {
            // 这里体现了异步填充的威力：我们并行发出连接请求
            // 为了简单起见，目前我们只填一个，由外部循环不断调用。
            match monoio::net::TcpStream::connect(target).await {
                Ok(stream) => {
                    self.put(target.to_string(), stream);
                }
                Err(_) => {
                    // 连接失败，可能后端挂了，暂不处理，等待下一次尝试。
                }
            }
        }
    }
}
