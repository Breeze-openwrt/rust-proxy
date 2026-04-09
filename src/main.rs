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
use rust_proxy::config::Config;
use rust_proxy::application::proxy::server::ProxyServer;
use clap::Parser;
use std::str::FromStr;
use std::fs;
use std::path::Path;
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use daemonize::Daemonize;

/// Rust-Proxy 命令行参数
#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// 配置文件路径
    #[arg(short, long, default_value = "config.jsonc")]
    config: String,

    /// 开启详细日志 (-v: DEBUG, -vv: TRACE)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// 以守护进程模式运行（后台运行）
    #[arg(short, long)]
    daemon: bool,

    /// PID 文件路径
    #[arg(short, long)]
    pid_file: Option<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // --- 步骤 1: 解析命令行参数 ---
    let cli = Cli::parse();

    // --- 步骤 2: 确定 PID 文件位置 ---
    let pid_path = cli.pid_file.clone().unwrap_or_else(|| {
        if nix::unistd::getuid().is_root() {
            "/var/run/rust-proxy.pid".to_string()
        } else {
            "/tmp/rust-proxy.pid".to_string()
        }
    });

    // --- 步骤 3: 尝试杀掉旧进程 (夺舍逻辑) ---
    if let Ok(content) = fs::read_to_string(&pid_path) {
        if let Ok(old_pid) = content.trim().parse::<i32>() {
            let pid = Pid::from_raw(old_pid);
            // 检查进程是否还在
            if signal::kill(pid, None).is_ok() {
                println!("⚠️ 发现正在运行的旧实例 (PID: {}), 正在尝试终止...", old_pid);
                let _ = signal::kill(pid, Signal::SIGTERM);
                // 给一点时间退出
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
        }
    }

    // --- 步骤 4: 背景化 (分身术) ---
    if cli.daemon {
        let stdout = fs::File::create("/dev/null").unwrap();
        let stderr = fs::File::create("/dev/null").unwrap();

        let daemonize = Daemonize::new()
            .pid_file(&pid_path) // 自动处理 PID 文件的写入和清理
            .chown_pid_file(true)
            .working_directory(".")
            .stdout(stdout)
            .stderr(stderr);

        match daemonize.start() {
            Ok(_) => println!("🚀 Rust-Proxy 已切入后台运行。"),
            Err(e) => {
                eprintln!("❌ 无法切入后台运行: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        // 非后台模式也要写 PID 文件以便下次“被夺舍”
        fs::write(&pid_path, std::process::id().to_string())?;
    }

    // --- 步骤 5: 启动异步运行时并执行核心逻辑 ---
    // 通过手动调用被 #[monoio::main] 修饰的异步函数来进入异步世界
    async_main(cli)
}

/// 异步主函数，处理配置文件加载和日志初始化
#[monoio::main(enable_timer = true)]
async fn async_main(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    // 加载配置
    let config = match Config::load(&cli.config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("⚠️ 无法读取配置文件 {}，错误: {}", cli.config, e);
            return Err(e.into());
        }
    };

    // 初始化日志
    let log_level = if cli.verbose > 0 {
        match cli.verbose {
            1 => Level::DEBUG,
            _ => Level::TRACE,
        }
    } else {
        config.log.as_ref()
            .and_then(|l| l.level.as_ref())
            .and_then(|s| Level::from_str(s).ok())
            .unwrap_or(Level::INFO)
    };

    let log_output = config.log.as_ref()
        .and_then(|l| l.output.as_ref())
        .map(|s| s.as_str())
        .unwrap_or("stdout");

    let _guard = if log_output != "stdout" && log_output != "" {
        let path = Path::new(log_output);
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let filename = path.file_name().and_then(|s| s.to_str()).unwrap_or("rust-proxy.log");
        
        let file_appender = tracing_appender::rolling::never(parent, filename);
        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
        
        let subscriber = FmtSubscriber::builder()
            .with_max_level(log_level)
            .with_writer(non_blocking)
            .with_ansi(false)
            .finish();
        tracing::subscriber::set_global_default(subscriber).ok();
        Some(guard)
    } else {
        let subscriber = FmtSubscriber::builder()
            .with_max_level(log_level)
            .finish();
        tracing::subscriber::set_global_default(subscriber).ok();
        None
    };

    info!("🚀 Rust-Proxy 服务逻辑已就绪");
    info!("📊 当前日志级别: {}", log_level);

    // --- 平滑下线：信号捕捉初始化 ---
    let (shutdown_tx, shutdown_rx) = futures::channel::oneshot::channel();
    
    // 我们使用 Unix 套接字对（Socket Pair）来架起信号处理与异步运行时之间的桥梁。
    // 这比原始管道更符合 monoio 的 IO 模型。
    use monoio::net::UnixStream;
    let (mut socket_r, socket_w) = UnixStream::pair()?;
    
    // 信号处理器：收到信号后往套接字里塞一个字节
    use std::os::unix::io::{RawFd, AsRawFd};
    static mut SIGNAL_FD: RawFd = -1;
    unsafe { SIGNAL_FD = socket_w.as_raw_fd(); }

    extern "C" fn handle_sig(_: libc::c_int) {
        unsafe {
            let buf = [1u8];
            libc::write(SIGNAL_FD, buf.as_ptr() as *const _, 1);
        }
    }

    unsafe {
        libc::signal(libc::SIGINT, handle_sig as libc::sighandler_t);
        libc::signal(libc::SIGTERM, handle_sig as libc::sighandler_t);
    }

    // 异步任务：监视套接字读取端
    use monoio::io::AsyncReadRent;
    monoio::spawn(async move {
        let buf = vec![0u8; 1];
        let (res, _): (Result<usize, _>, _) = socket_r.read(buf).await;
        if res.is_ok() {
            let _ = shutdown_tx.send(());
        }
    });

    let server = ProxyServer::new(config);
    server.run(shutdown_rx).await?;

    Ok(())
}
