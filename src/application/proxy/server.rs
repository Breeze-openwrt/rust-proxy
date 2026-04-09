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
#[cfg(target_os = "linux")]
use aya::{Ebpf, programs::SkSkb};
#[cfg(target_os = "linux")]
use aya::maps::{SockMap, HashMap};
#[cfg(target_os = "linux")]
use aya::programs::{SchedClassifier, TcAttachType};
#[cfg(target_os = "linux")]
use aya::programs::tc;
use rust_proxy_common::DomainKey;
use tracing::{info, error, debug, warn};
use futures::future::{select, Either};

#[cfg(target_os = "linux")]
/// 静态嵌入 eBPF 内核字节码 (Static Embed Bytecode)
const BPF_BYTECODE: &[u8] = include_bytes!("../../resources/ebpf.o");

use std::sync::atomic::{AtomicUsize, Ordering};

/// 代理服务器主体
#[derive(Clone)]
pub struct ProxyServer {
    /// 全局配置
    config: Rc<Config>,
    /// 共享连接池
    pool: Rc<RefCell<ConnectionPool>>,
    #[cfg(target_os = "linux")]
    bpf: Option<Rc<RefCell<Ebpf>>>,
    #[cfg(target_os = "linux")]
    next_index: Rc<RefCell<u32>>,
    /// 活跃连接计数器 (平滑下线的核心)
    active_connections: Rc<AtomicUsize>,
}

impl ProxyServer {
    /// 创建服务器实例
    pub fn new(config: Config) -> Self {
        let shared_config = Rc::new(config);
        let idle_timeout = 300; 
        let pool = Rc::new(RefCell::new(ConnectionPool::new(idle_timeout)));

        #[cfg(target_os = "linux")]
        let mut bpf_instance = None;
        #[cfg(target_os = "linux")]
        {
            // 🚀 动态优先：先尝试加载同级目录下的 ebpf.o
            let (bytecode_data, source) = if let Ok(data) = std::fs::read("ebpf.o") {
                (data, "外部文件 (ebpf.o)")
            } else if let Ok(data) = std::fs::read("target/release/ebpf.o") {
                (data, "发布目录 (target/release/ebpf.o)")
            } else {
                (BPF_BYTECODE.to_vec(), "内置嵌入 (Static)")
            };

            info!("🧬 eBPF 来源: {}", source);
            info!("🧪 内存字节码指纹: {:02x?}", &bytecode_data[0..4]);

            match Ebpf::load(&bytecode_data) {
                Ok(mut bpf) => {
                    info!("🚀 eBPF 字节码加载成功，准备挂载...");
                    
                    // --- 步骤 1: 挂载 TC 过滤器 (针对域名侦听和防御) ---
                    let _ = tc::qdisc_add_clsact("eth0");
                    if let Some(prog) = bpf.program_mut("filter_sni") {
                        if let Ok(tc_prog) = prog.try_into() {
                            let tc_prog: &mut SchedClassifier = tc_prog;
                            if let Ok(_) = tc_prog.load() {
                                if let Err(e) = tc_prog.attach("eth0", TcAttachType::Ingress) {
                                    warn!("❌ TC 挂载失败 (eth0): {:?}", e);
                                } else {
                                    info!("✅ TC 域名过滤器已挂载到 eth0 (Ingress)");
                                }
                            }
                        }
                    }

                    // --- 步骤 2: 同步域名白名单到内核 ---
                    if let Some(map) = bpf.map_mut("ALLOWED_DOMAINS") {
                        if let Ok(mut domains_map) = HashMap::<&mut aya::maps::MapData, DomainKey, u32>::try_from(map) {
                            for domain in shared_config.routes.keys() {
                                let mut key = DomainKey { name: [0u8; 64] };
                                let bytes = domain.as_bytes();
                                let len = std::cmp::min(bytes.len(), 64);
                                key.name[..len].copy_from_slice(&bytes[..len]);
                                let _ = domains_map.insert(key, 1, 0);
                                info!("🛡️ 内核白名单已同步: {}", domain);
                            }
                        }
                    }

                    // 改进后的带有详细错误日志的挂载流程
                    let mut success = false;
                    unsafe {
                        let bpf_ptr = &mut bpf as *mut Ebpf;
                        match (*bpf_ptr).map("REDIRECT_MAP") {
                            Some(map) => match SockMap::<&aya::maps::MapData>::try_from(map) {
                                Ok(sm) => match (*bpf_ptr).program_mut("fast_forward") {
                                    Some(program) => match program.try_into() {
                                        Ok(sk_msg) => {
                                            let sk_msg: &mut SkSkb = sk_msg;
                                            match sk_msg.load() {
                                                Ok(_) => match sk_msg.attach(sm.fd()) {
                                                    Ok(_) => {
                                                        info!("✅ eBPF 程序已成功挂载到 REDIRECT_MAP (StreamVerdict)");
                                                        success = true;
                                                    }
                                                    Err(e) => warn!("❌ eBPF 挂载错误 (attach failed): {:?}", e),
                                                },
                                                Err(e) => warn!("❌ eBPF 挂载错误 (load failed): {:?}", e),
                                            }
                                        }
                                        Err(e) => warn!("❌ eBPF 挂载错误 (program_mut type mismatch): {:?}", e),
                                    },
                                    None => warn!("❌ eBPF 挂载错误 (找不到 program 'fast_forward')"),
                                },
                                Err(e) => warn!("❌ eBPF 挂载错误 (SockMap try_from failed): {:?}", e),
                            },
                            None => warn!("❌ eBPF 挂载错误 (找不到 map 'REDIRECT_MAP')"),
                        }
                    }
                    if success {
                        bpf_instance = Some(Rc::new(RefCell::new(bpf)));
                    } else {
                        warn!("⚠️ eBPF 挂载失败，将降级到纯用户态模式");
                    }
                }
                Err(e) => {
                    warn!("⚠️ eBPF 加速模块未就绪 (或非 Linux 环境): {}", e);
                }
            }
        }

        ProxyServer {
            config: shared_config,
            pool,
            #[cfg(target_os = "linux")]
            bpf: bpf_instance,
            #[cfg(target_os = "linux")]
            next_index: Rc::new(RefCell::new(0)),
            active_connections: Rc::new(AtomicUsize::new(0)),
        }
    }

    /// 启动服务器（主循环，支持平滑下线）
    pub async fn run(&self, mut shutdown_rx: futures::channel::oneshot::Receiver<()>) -> Result<(), Box<dyn std::error::Error>> {
        let addr = self.config.listen_addr.parse()?;
        let std_listener = SocketOptimizer::create_tuned_listener(addr)?;
        let listener = TcpListener::from_std(std_listener)?;
        
        info!("📡 代理服务器启动，监听: {}", self.config.listen_addr);

        // --- 启动后台 JumpStart 预热卫士 ---
        let pool_for_warmup = self.pool.clone();
        let config_for_warmup = self.config.clone();
        monoio::spawn(async move {
            loop {
                for route in config_for_warmup.routes.values() {
                    // 1. 先探测缺口（短时间借用池子，不带 Await）
                    let needed = {
                        let p = pool_for_warmup.borrow();
                        p.get_needed_count(&route.addr, route.jump_start)
                    };

                    // 2. 如果有缺口，并发连接（不持有池子的锁）
                    if needed > 0 {
                        let connections = ConnectionPool::fill_batch(route.addr.clone(), needed).await;
                        
                        // 3. 把连好的塞回去（短时间借用池子，不带 Await）
                        let mut p = pool_for_warmup.borrow_mut();
                        for conn in connections {
                            p.put(route.addr.clone(), conn);
                        }
                    }
                }
                monoio::time::sleep(std::time::Duration::from_secs(10)).await;
            }
        });

        loop {
            // 使用 select 同时监听新连接和关闭信号
            let accept_fut = listener.accept();
            
            match select(Box::pin(accept_fut), Box::pin(&mut shutdown_rx)).await {
                Either::Left((accept_res, _)) => {
                    let (conn, peer_addr) = accept_res?;
                    debug!("🤝 收到新连接: {}", peer_addr);

                    // 增加连接计数
                    self.active_connections.fetch_add(1, Ordering::SeqCst);
                    
                    let this = self.clone();
                    monoio::spawn(async move {
                        if let Err(e) = this.handle_connection(conn).await {
                            error!("❌ 连接处理异常: {}", e);
                        }
                        // 连接处理结束，减少计数
                        this.active_connections.fetch_sub(1, Ordering::SeqCst);
                    });
                }
                Either::Right(_) => {
                    info!("🛑 收到终止信号，正在平滑下线...");
                    break;
                }
            }
        }

        // --- 进入平滑下线等待期 ---
        let start_wait = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(30);
        
        while self.active_connections.load(Ordering::SeqCst) > 0 {
            let count = self.active_connections.load(Ordering::SeqCst);
            info!("⏳ 正在等待 {} 个活跃连接关闭...", count);
            
            if start_wait.elapsed() >= timeout {
                warn!("⏰ 平滑下线超时，强制退出。仍有 {} 个连接。", count);
                break;
            }
            monoio::time::sleep(std::time::Duration::from_millis(500)).await;
        }

        info!("👋 平滑下线完成，服务正式退出。");
        Ok(())
    }

    /// 处理单个连接的业务逻辑
    async fn handle_connection(
        &self,
        mut inbound: TcpStream, 
    ) -> anyhow::Result<()> {
        let pool = self.pool.clone();
        let config = self.config.clone();
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
                    // 核心修复：优先尝试解析为 SocketAddr，防止 IP 字符串触发不可靠的 DNS 解析
                    if let Ok(addr) = backend_addr.parse::<std::net::SocketAddr>() {
                        TcpStream::connect(addr).await?
                    } else {
                        TcpStream::connect(backend_addr).await?
                    }
                }
            }
        };

        // --- 步骤 4: 转发残留的首包 ---
        let (res, _buf) = outbound.write_all(buf).await;
        res?;

        // --- 步骤 5: 建立双向透明转发 ---
        #[cfg(target_os = "linux")]
        {
            if let Some(ref bpf) = self.bpf {
                self.try_offload_to_ebpf(bpf, &inbound, &outbound).await;
            }
        }

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

    /// 尝试将转发逻辑交给 eBPF 接管 (Offload Implementation)
    #[cfg(target_os = "linux")]
    async fn try_offload_to_ebpf(&self, bpf_rc: &Rc<RefCell<Ebpf>>, inbound: &TcpStream, outbound: &TcpStream) {
        use std::os::unix::io::AsRawFd;
        
        let fd_in = inbound.as_raw_fd();
        let fd_out = outbound.as_raw_fd();

        // 1. 分配唯一的索引对（Index Pairing）
        // 采用 index <-> index + 1 的奇偶对撞策略
        let (idx_in, idx_out) = {
            let mut next = self.next_index.borrow_mut();
            let start = *next;
            *next += 2;
            (start, start + 1)
        };

        // 获取 Socket Cookie (内核级的唯一标识)
        let mut cookie_in: u64 = 0;
        let mut cookie_out: u64 = 0;
        let mut len = std::mem::size_of::<u64>() as libc::socklen_t;
        unsafe {
            libc::getsockopt(fd_in, libc::SOL_SOCKET, 80 /* SO_COOKIE */, &mut cookie_in as *mut _ as *mut _, &mut len);
            libc::getsockopt(fd_out, libc::SOL_SOCKET, 80 /* SO_COOKIE */, &mut cookie_out as *mut _ as *mut _, &mut len);
        }

        if cookie_in == 0 || cookie_out == 0 { return; }

        // 1. 获取并操作 REDIRECT_MAP
        {
            let mut bpf = bpf_rc.borrow_mut();
            if let Some(map) = bpf.map_mut("REDIRECT_MAP") {
                if let Ok(mut redirect_map) = SockMap::try_from(map) {
                    let _ = redirect_map.set(idx_in, &fd_in, 0);
                    let _ = redirect_map.set(idx_out, &fd_out, 0);
                }
            }
        }

        // 2. 获取并操作 PEER_MAP
        {
            let mut bpf = bpf_rc.borrow_mut();
            if let Some(map) = bpf.map_mut("PEER_MAP") {
                if let Ok(mut peer_map) = HashMap::<_, u64, u32>::try_from(map) {
                    let _ = peer_map.insert(&cookie_in, &idx_out, 0);
                    let _ = peer_map.insert(&cookie_out, &idx_in, 0);
                }
            }
        }

        info!("⚡ eBPF 暴力加速成功: FD {} <-> FD {} (Indices: {} <-> {})", fd_in, fd_out, idx_in, idx_out);
    }
}
