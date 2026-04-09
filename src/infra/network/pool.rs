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
use tracing::{debug, info}; // 引入日志宏。

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
    /// 优化 1：LIFO (后进先出) - 最鲜活的连接放在队列尾部。
    /// 优化 2：健康探测 - 确保借出的连接不是“僵尸连接”。
    pub fn get(&mut self, target: &str) -> Option<TcpStream> {
        if let Some(queue) = self.pools.get_mut(target) {
            // LIFO: 改用 pop_back 获取最新鲜的连接
            while let Some(conn) = queue.pop_back() {
                // 首先检查时间戳超时
                if conn.created_at.elapsed() >= self.idle_timeout {
                    drop(conn);
                    continue;
                }

                // 核心优化：主动探测连接是否依然健康 (Active Health Probing)
                if !Self::is_connection_alive(&conn.stream) {
                    debug!("🗑️ 发现失效连接: {}, 已丢弃", target);
                    drop(conn);
                    continue;
                }

                return Some(conn.stream);
            }
        }
        None
    }

    /// 探测连接是否依然存活 (不读取数据的 Peek 探测)
    fn is_connection_alive(stream: &TcpStream) -> bool {
        use std::os::unix::io::AsRawFd;
        let fd = stream.as_raw_fd();
        let mut buf = [0u8; 1];
        // 使用 MSG_PEEK | MSG_DONTWAIT 探测协议栈状态
        // 如果返回 0，表示对端已关闭连接（EOF）
        // 如果返回错误且错误不是 EWOULDBLOCK，表示连接已异常
        let res = unsafe {
            libc::recv(fd, buf.as_mut_ptr() as *mut _, 1, libc::MSG_PEEK | libc::MSG_DONTWAIT)
        };
        
        if res == 0 { return false; } // 对端已正常关闭
        if res < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                return true; // 没有数据可读，但连接依然活跃
            }
            return false; // 发生套接字错误
        }
        true // 有数据等待读取（对于预热连接这很少见，但也表示连接是活的）
    }

    /// 将一个新建立的连接存入池中
    pub fn put(&mut self, target: String, stream: TcpStream) {
        let entry = self.pools.entry(target).or_insert_with(VecDeque::new);
        entry.push_back(IdleConnection {
            stream,
            created_at: Instant::now(),
        });
    }

    /// 获取指定目标还缺少的连接数
    pub fn get_needed_count(&self, target: &str, target_count: usize) -> usize {
        let current_count = self.pools.get(target).map_or(0, |q| q.len());
        if current_count < target_count {
            target_count - current_count
        } else {
            0
        }
    }

    /// 暴力优化：并发批量填充 (Batch JumpStart)
    /// 
    /// 不再在持有锁的情况下进行异步连接。
    pub async fn fill_batch(target: String, count: usize) -> Vec<TcpStream> {
        info!("🔥 正在为 {} 并发建立 {} 个连接...", target, count);
        
        let mut futures = Vec::new();
        for _ in 0..count {
            futures.push(monoio::net::TcpStream::connect(target.clone()));
        }

        let results = futures::future::join_all(futures).await;
        let mut streams = Vec::new();
        for res in results {
            if let Ok(stream) = res {
                // 暴力优化：预热连接在入池前必须完成极致性能调优
                let _ = crate::infra::network::socket_opt::SocketOptimizer::tune_stream(&stream);
                streams.push(stream);
            }
        }
        streams
    }
}
