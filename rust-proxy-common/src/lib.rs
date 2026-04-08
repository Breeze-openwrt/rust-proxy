//! # 共享数据结构 (Shared Common Library)
//! 
//! 本子模块定义了用户态 (User Space) 与内核态 (Kernel Space) 之间沟通的“暗号”。
//! 所有的 BPF Map 结构体定义都应存放在此处，以保证内存对齐一致。

use aya_ebpf::macros::map; // 引入宏（注意：在普通库中我们仅作为定义参考）。

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

// 注意：在实际开发中，这里经常使用 aya::Pod 宏来实现零拷贝序列化，
// 但为了保持小白易懂性，我们目前先定义逻辑结构。
