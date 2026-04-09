//! # 底层 Socket 调优专家 (由 socket2 强力驱动)
//! 
//! 本模块专门负责对 Linux 内核的网络参数进行“暴力”微调。
//! 我们使用流行的 `socket2` 库，因为它提供了对系统调用最完整的封装。
//! 
//! 调优目标：
//! 1. **SO_REUSEPORT**: 允许更多核心同时监听端口，消除单核 Accept 瓶颈。
//! 2. **Buffer 扩容**: 将内核接收/发送缓冲区扩大到 1MB 以上，防止瞬时峰值导致丢包。
//! 3. **TCP_NODELAY**: 禁用 Nagle 算法，首包立即发送，追求毫秒级延迟。

use socket2::{Socket, Domain, Type, Protocol}; // 引入流行的底层控制原语。
use std::net::SocketAddr; // 标准地址库。
use anyhow; // 🔥 引入高级错误处理框架，让“暴力提速”过程中的每一个环节都处于监控下。
use libc;   // 🔥 引入底层 C 库绑定，它是我们通过 setsockopt 操纵内核协议栈的魔法钥匙。

/// Socket 调优工具
pub struct SocketOptimizer;

impl SocketOptimizer {
    /// 创建并调优一个极致性能的消息监听器
    /// 
    /// 这里的逻辑是先构建一个原始 Socket，进行深度配置后，再将其转换为 TcpListener。
    pub fn create_tuned_listener(addr: SocketAddr) -> anyhow::Result<std::net::TcpListener> {
        // --- 1. 创建原始 Socket ---
        // 根据地址族（IPv4/IPv6）自动选择 Domain。
        let domain = if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
        let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;

        // --- 2. 设置极致性能参数 ---
        
        // 允许端口复用（这对暴力提速和水平扩展至关重要！）
        socket.set_reuse_address(true)?;
        #[cfg(not(windows))] // Linux 特有的杀手锏：真正的核心级分流
        socket.set_reuse_port(true)?;

        // --- 暴力提速：4MB 巨型缓冲区 ---
        // 默认缓冲区太小，容易导致接收窗口快速填满。
        // 我们将其提升到 4MB，让发送端可以“撒开了跑”，不被 TCP 流量控制限制。
        let buf_size = 4 * 1024 * 1024; // 4MiB
        if let Err(e) = socket.set_recv_buffer_size(buf_size) {
            tracing::warn!("⚠️ 无法设置接收缓冲区大小: {}", e);
        }
        if let Err(e) = socket.set_send_buffer_size(buf_size) {
            tracing::warn!("⚠️ 无法设置发送缓冲区大小: {}", e);
        }

        // 绑定地址
        socket.bind(&addr.into())?;

        // 开始监听（设置最大挂起连接数）
        socket.listen(1024)?;

        // 执行“封印解除”：将底层 Socket 转换为标准 Rust TcpListener
        // 后续我们将进一步将其包装给 monoio 使用。
        Ok(socket.into())
    }

    /// 对已建立的连接进行调优
    pub fn tune_stream(stream: &std::net::TcpStream) -> anyhow::Result<()> {
        let socket = Socket::from(stream.try_clone()?); // 暂时包装
        
        // 禁用 Nagle 算法：
        // 对于代理服务器，首包的速度就是生命，绝不能让内核由于等待合并而产生延迟。
        socket.set_nodelay(true)?;

        // 源码级调优：TCP_QUICKACK
        // 通过设置快速确认，让对端尽早感知到数据已接收，从而加快滑动窗口滑动。
        #[cfg(target_os = "linux")]
        {
            // 使用底层系统调用设置 TCP 快速确认
            use std::os::unix::io::AsRawFd;
            let fd = stream.as_raw_fd();
            unsafe {
                let opt: i32 = 1;
                libc::setsockopt(fd, libc::IPPROTO_TCP, libc::TCP_QUICKACK, &opt as *const i32 as *const libc::c_void, std::mem::size_of::<i32>() as libc::socklen_t);
            }
        }

        // 开启 TCP Keepalive，防止连接由于链路空闲被静默断开
        let ka = socket2::TcpKeepalive::new()
            .with_time(std::time::Duration::from_secs(60));
        socket.set_tcp_keepalive(&ka)?;

        Ok(())
    }
}
