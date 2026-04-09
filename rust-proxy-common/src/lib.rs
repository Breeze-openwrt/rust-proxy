//! # 共享数据结构 (Shared Common Library)
//! 
//! 本子模块定义了用户态 (User Space) 与内核态 (Kernel Space) 之间沟通的“暗号”。
//! 所有的 BPF Map 结构体定义都应存放在此处，以保证内存对齐一致。

#![no_std] // 核心修正：强制开启 no_std，确保共享库能被内核态 BPF 正常引用。

// 在 common 模块中，我们仅定义结构体，不直接操作 BPF Map。

/// 关键：Socket 重定向映射表
/// 
/// 这个 Map 是实现“暴力提速”的关键：
/// - Key: 一个 4 字节的标识符（通常是连接的 ID）。
/// - Value: 两个通过 Socket 建立关联的 FD (File Descriptor)。
/// 虽然这里仅是一个标识，但在 eBPF 加载器中它将被声明为 BPF_MAP_TYPE_SOCKMAP。
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SocketPair {
    pub client_fd: u32,
    pub server_fd: u32,
}

/// 域名过滤键 (Domain Filter Key)
/// 固定 64 字节长度，溢出部分将被截断。
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DomainKey {
    pub name: [u8; 64],
}

/// 会话缓存键 (Session Cache Key)
/// 用于在内核态快速识别已经过验证的合法连接。
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionKey {
    pub src_ip: u32,  // IPv4 暂仅支持 v4 演示，生产环境可扩展为 v6
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
}

// 为 BPF Map 访问提供必要的 Trait 支撑 (如果需要)
#[cfg(feature = "user")]
unsafe impl aya::Pod for DomainKey {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for SessionKey {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for SocketPair {}
