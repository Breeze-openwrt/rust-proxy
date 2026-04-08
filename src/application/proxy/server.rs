//! # 代理转发服务器核心 (Proxy Server Core)
//! 
//! 本模块实现了高性能代理的业务逻辑流程。
//! 它协调了协议解析、路由查找和流量转发。
//! 
//! 核心流程：监听 -> 接受连接 -> Peek 首包 -> 解析 SNI -> 获取后端 -> 建立转发。

use crate::domain::protocol::sni::{SniParser, SniResult};
use crate::infra::network::pool::ConnectionPool;
use crate::infra::network::socket_opt::SocketOptimizer; // 引入底层调优工具。
use monoio::net::{TcpListener, TcpStream};
use monoio::io::{AsyncReadRent, AsyncWriteRentExt};
use std::rc::Rc;
use std::cell::RefCell;
use tracing::{info, error, debug, warn};

// --- eBPF 增强组件 ---
// 在 Linux 上运行时，我们需要这些库来接管内核转发。
#[cfg(target_os = "linux")]
use aya::{Bpf, programs::SkMsg};
#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;

/// 代理服务器主体
pub struct ProxyServer {
    /// 监听地址
    listen_addr: String,
    /// 共享连接池
    pool: Rc<RefCell<ConnectionPool>>,
    /// eBPF 程序句柄 (仅 Linux 下生效)
    #[cfg(target_os = "linux")]
    bpf: Option<Rc<RefCell<Bpf>>>,
}

impl ProxyServer {
    /// 创建服务器实例
    pub fn new(addr: String) -> Self {
        // 初始化一个默认超时 5 分钟的池
        let pool = Rc::new(RefCell::new(ConnectionPool::new(300)));
        Self { listen_addr: addr, pool }
    }

    /// 启动服务器（主循环）
    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        // --- 质量升级：使用 socket2 调优后的监听器 ---
        // 我们不再使用简单的标准库 bind，而是通过 SocketOptimizer 开启 REUSEPORT 和 Buffer 扩容。
        let addr = self.listen_addr.parse()?;
        let std_listener = SocketOptimizer::create_tuned_listener(addr)?;
        
        // 将调优后的标准 Listener 转为 monoio 支持的异步 Listener
        let listener = TcpListener::from_std(std_listener)?;
        
        info!("📡 调优完毕！代理服务器在高能模式下监听: {}", self.listen_addr);

        loop {
            // 等待并接受一个新的入站连接
            let (conn, peer_addr) = listener.accept().await?;
            debug!("🤝 收到新连接，来自: {}", peer_addr);

            // 为每个连接派生一个异步任务（协程）
            // 注意：由于 monoio 是单线程 Runtime，派生的任务直接运行在当前 CPU 核心上，零跨核开销。
            let shared_pool = self.pool.clone();
            monoio::spawn(async move {
                if let Err(e) = Self::handle_connection(conn, shared_pool).await {
                    error!("❌ 处理连接失败: {}", e);
                }
            });
        }
    }

    /// 处理单个连接的业务逻辑
    async fn handle_connection(mut inbound: TcpStream, pool: Rc<RefCell<ConnectionPool>>) -> anyhow::Result<()> {
        // --- 步骤 1: 探测首包获取 SNI ---
        // 我们需要读取足够的数据来解析 SNI，但又不能真正“消耗”掉它（因为后面转发需要完整包）。
        // 目前我们使用简化的 Read + Peek 思路，或者直接读取到一个缓冲区中。
        let mut buf = vec![0u8; 2048]; // 分配 2KB 缓冲区，足以容纳绝大多数 Client Hello。
        
        // 使用 monoio 的异步读取。由于 monoio 是所有权式的 I/O，我们要传入 Buffer。
        let (res, buf) = inbound.read(buf).await;
        let read_len = res?;
        if read_len == 0 { return Ok(()); }

        // 使用我们强大的 SniParser 解析域名
        let sni = match SniParser::parse(&buf[..read_len]) {
            SniResult::Found(name) => name,
            _ => {
                debug!("❓ 未能在首包中解析到 SNI 或协议不匹配，连接关闭。");
                return Ok(());
            }
        };

        info!("🎯 目标域名识别: {}", sni);

        // --- 步骤 2: 获取后端连接 ---
        // 模拟路由：在实际项目中，这里会查表。我们现在先硬编码一个目标用于开发。
        // TODO: 接入真正的工作配置路由。
        let backend_addr = "127.0.0.1:10443"; 

        // 尝试从池中获取预热好的连接（JumpStart）
        let mut outbound = {
            let mut pool_v = pool.borrow_mut();
            match pool_v.get(backend_addr) {
                Some(conn) => {
                    debug!("🔥 命中 JumpStart 池！成功复用预热连接。");
                    conn
                },
                None => {
                    debug!("🧊 池中无可用连接，正在发起新连接到: {}", backend_addr);
                    TcpStream::connect(backend_addr).await?
                }
            }
        };

        // --- 步骤 3: 转发残留的首包 ---
        // 关键点：由于我们刚才在 User 态 Read 了首包，我们必须先把它发给后端。
        let (res, _buf) = outbound.write_all(buf).await;
        res?;

        // --- 步骤 4: 建立双向透明转发 (Relay) ---
        // 核心亮点：尝试将此连接卸载到 eBPF 内核态加速！
        Self::try_offload_to_ebpf(&inbound, &outbound).await;

        let (mut client_r, mut client_w) = inbound.split();
        let (mut server_r, mut server_w) = outbound.split();

        // 同时运行两个拷贝任务：
        // 1. Client -> Server
        // 2. Server -> Client
        let c2s = monoio::io::copy(&mut client_r, &mut server_w);
        let s2c = monoio::io::copy(&mut server_r, &mut client_w);

        // 使用 join! 并行执行，直到其中一方关闭连接。
        tokio::select! {
            _ = c2s => debug!("⬆️ 客户端已断开发送流"),
            _ = s2c => debug!("⬇️ 服务器已断开响应流"),
        }

        Ok(())
    }

    /// 尝试将转发逻辑交给 eBPF 接管
    /// 
    /// 源码欣赏：
    /// 这就是“暴力提速”的最终战术。如果我们成功在内核 Map 中将 client_fd
    /// 关联到 server_fd，后续的 copy 任务将几乎不搬运任何数据。
    async fn try_offload_to_ebpf(_in: &TcpStream, _out: &TcpStream) {
        #[cfg(target_os = "linux")]
        {
            // 通过 raw_fd 获取文件描述符
            let fd_in = _in.as_raw_fd();
            let fd_out = _out.as_raw_fd();
            debug!("⚡ 正在尝试 eBPF 卸载加速: FD {} -> FD {}", fd_in, fd_out);
            
            // TODO: 在此处调用 aya 的 Map 接口写入连接对。
            // 由于开发处于骨架阶段，我们先通过条件编译预留位置。
        }
        
        #[cfg(not(target_os = "linux"))]
        {
            // Windows 环境下仅输出日志，不进行内核操作。
            // 确保了代码的可移植性和“初学者友好”。
        }
    }
}
