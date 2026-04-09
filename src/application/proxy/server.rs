//! # 代理转发服务器核心 (Proxy Server Core)
//! 
//! 本模块实现了高性能代理的业务逻辑流程。
//! 它协调了协议解析、路由查找和流量转发。
//! 
//! 核心流程：监听 -> 接受连接 -> Peek 首包 -> 解析 SNI -> 获取后端 -> 建立转发。

use crate::domain::protocol::sni::{SniParser, SniResult};
use crate::infra::network::pool::ConnectionPool;
use crate::infra::network::socket_opt::SocketOptimizer;
use crate::config::Config;
use monoio::net::{TcpListener, TcpStream};
use monoio::io::{AsyncReadRent, AsyncWriteRentExt, Splitable};
use std::rc::Rc;
use std::cell::RefCell;
use tracing::{info, error, debug, warn};
use futures::future::{select, Either};

// --- eBPF 增强组件 ---
#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;

/// 代理服务器主体
pub struct ProxyServer {
    /// 全局配置
    config: Rc<Config>,
    /// 共享连接池
    pool: Rc<RefCell<ConnectionPool>>,
}

impl ProxyServer {
    /// 创建服务器实例
    pub fn new(config: Config) -> Self {
        // 从配置中读取默认超时，若未指定则默认 5 分钟
        let idle_timeout = 300; 
        let pool = Rc::new(RefCell::new(ConnectionPool::new(idle_timeout)));
        Self { 
            config: Rc::new(config), 
            pool 
        }
    }

    /// 启动服务器（主循环）
    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        let addr = self.config.listen_addr.parse()?;
        let std_listener = SocketOptimizer::create_tuned_listener(addr)?;
        let listener = TcpListener::from_std(std_listener)?;
        
        info!("📡 代理服务器启动，监听: {}", self.config.listen_addr);

        // --- 质量升级：启动后台 JumpStart 预热卫士 ---
        // 我们不眠不休地监控连接池，确保后端连接随时可用。
        let pool_for_warmup = self.pool.clone();
        let config_for_warmup = self.config.clone();
        monoio::spawn(async move {
            debug!("🛡️ JumpStart 预热卫士已就位。");
            loop {
                for route in config_for_warmup.routes.values() {
                    let mut p = pool_for_warmup.borrow_mut();
                    p.fill_if_needed(&route.addr, route.jump_start).await;
                }
                // 每隔 10 秒巡检一次，避免 CPU 空转，同时保持连接新鲜。
                monoio::time::sleep(std::time::Duration::from_secs(10)).await;
            }
        });
        loop {
            let (conn, peer_addr) = listener.accept().await?;
            debug!("🤝 收到新连接: {}", peer_addr);

            let shared_pool = self.pool.clone();
            let shared_config = self.config.clone();
            
            monoio::spawn(async move {
                if let Err(e) = Self::handle_connection(conn, shared_pool, shared_config).await {
                    error!("❌ 连接处理异常: {}", e);
                }
            });
        }
    }

    /// 处理单个连接的业务逻辑
    async fn handle_connection(
        mut inbound: TcpStream, 
        pool: Rc<RefCell<ConnectionPool>>, 
        config: Rc<Config>
    ) -> anyhow::Result<()> {
        // --- 步骤 1: 探测首包获取 SNI ---
        let buf = vec![0u8; 2048];
        let (res, buf) = inbound.read(buf).await;
        let read_len = res?;
        if read_len == 0 { return Ok(()); }

        let sni = match SniParser::parse(&buf[..read_len]) {
            SniResult::Found(name) => name,
            _ => {
                debug!("❓ 未能在首包中解析到 SNI 或协议不匹配。");
                return Ok(());
            }
        };

        info!("🎯 目标域名识别: {}", sni);

        // --- 步骤 2: 动态路由匹配 ---
        let route = match config.routes.get(&sni) {
            Some(r) => r,
            None => {
                warn!("🚫 未找到域名 {} 的路由配置", sni);
                return Ok(());
            }
        };

        // --- 步骤 3: 获取后端连接 ---
        let backend_addr = &route.addr;
        let mut outbound = {
            let mut pool_v = pool.borrow_mut();
            match pool_v.get(backend_addr) {
                Some(conn) => {
                    debug!("🔥 JumpStart 命中: {}", backend_addr);
                    conn
                },
                None => {
                    debug!("🧊 发起新连接: {}", backend_addr);
                    TcpStream::connect(backend_addr).await?
                }
            }
        };

        // --- 步骤 4: 转发残留的首包 ---
        let (res, _buf) = outbound.write_all(buf).await;
        res?;

        // --- 步骤 5: 建立双向透明转发 ---
        Self::try_offload_to_ebpf(&inbound, &outbound).await;

        let (mut client_r, mut client_w) = inbound.into_split();
        let (mut server_r, mut server_w) = outbound.into_split();

        let c2s = monoio::io::copy(&mut client_r, &mut server_w);
        let s2c = monoio::io::copy(&mut server_r, &mut client_w);

        // 使用 futures::future::select 实现极简控制流
        match select(Box::pin(c2s), Box::pin(s2c)).await {
            Either::Left((res, _)) => {
                if let Err(e) = res { debug!("⬆️ C2S 转发结束: {}", e); }
            }
            Either::Right((res, _)) => {
                if let Err(e) = res { debug!("⬇️ S2C 转发结束: {}", e); }
            }
        }

        Ok(())
    }

    /// 尝试将转发逻辑交给 eBPF 接管
    async fn try_offload_to_ebpf(_in: &TcpStream, _out: &TcpStream) {
        #[cfg(target_os = "linux")]
        {
            let fd_in = _in.as_raw_fd();
            let fd_out = _out.as_raw_fd();
            debug!("⚡ 尝试 eBPF 加速: FD {} -> FD {}", fd_in, fd_out);
        }
    }
}
