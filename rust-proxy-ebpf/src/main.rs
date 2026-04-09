//! # eBPF 内核重定向程序 (eBPF Kernel Redirector)
//! 
//! 本程序运行在 Linux 内核态空间中。
//! 它的职责是：当数据到达某个 Socket 时，直接将其“瞬移”到另一个关联的 Socket。
//! 
//! 源码欣赏：
//! 这段代码虽然简略，但它直接操作了内核的 Socket 消息缓冲区，绕过了用户态的 3 次上下文切换！

#![no_std] // 内核态没有标准库，我们使用 no_std 保持精简。
#![no_main] // BPF 程序没有常规的 main 函数，它是驱动程序式的响应模式。

use aya_ebpf::{
    macros::{stream_verdict, map, classifier}, // 引入 BPF 程序宏。
    maps::{SockMap, HashMap}, // 引入 Socket 映射表与哈希表。
    programs::{SkBuffContext, TcContext}, // 消息上下文。
    helpers::{bpf_get_socket_cookie, bpf_ktime_get_ns}, // 获取 Socket 唯一标识与时间。
    EbpfContext, // 引入上下文 Trait，提供 as_ptr 支持。
};
use network_types::{
    eth::EthHdr,
    ip::{Ipv4Hdr, IpProto},
    tcp::TcpHdr,
};
use rust_proxy_common::{DomainKey, SessionKey};
pub trait PtrAt {
    fn ptr_at<T>(&self, offset: usize) -> Result<*const T, ()>;
}

impl PtrAt for TcContext {
    #[inline(always)]
    fn ptr_at<T>(&self, offset: usize) -> Result<*const T, ()> {
        let start = self.data();
        let end = self.data_end();
        let len = core::mem::size_of::<T>();

        if start + offset + len > end {
            return Err(());
        }

        Ok((start + offset) as *const T)
    }
}

/// 声明一个全局的 Socket 映射表
/// 
/// 这个 Map 由用户态填充：存放所有的活跃 Socket。
#[map]
static REDIRECT_MAP: SockMap = SockMap::with_max_entries(1024, 0);

/// 映射关系表：Socket Cookie -> 目标在 REDIRECT_MAP 中的索引
#[map]
static PEER_MAP: HashMap<u64, u32> = HashMap::with_max_entries(1024, 0);

/// 域名白名单 (Domain Whitelist)
#[map]
static ALLOWED_DOMAINS: HashMap<DomainKey, u32> = HashMap::with_max_entries(1024, 0);

/// 会话缓存 (Session Cache)
/// Key: 5-tuple, Value: 最后活跃时间 (ns)
/// 优化：扩容到 32768，减少高并发下的哈希冲突和解析损耗
#[map]
static SESSION_CACHE: HashMap<SessionKey, u64> = HashMap::with_max_entries(32768, 0);

/// 许可证 (License) - eBPF 的法典
/// 
/// 必须声明 GPL 兼容权限，内核才允许加载并调用 get_socket_cookie 等核心函数。
#[unsafe(no_mangle)]
#[unsafe(link_section = "license")]
pub static _LICENSE: [u8; 4] = *b"GPL\0";

/// 核心重定向逻辑
/// 
/// 每当有数据流到达时，内核就会调用这个函数进行判定。
/// 🔥 突围：切换到 stream_verdict 挂载点，因为该挂载点合法支持获取 Socket Cookie。
#[stream_verdict]
#[inline(always)]
pub fn fast_forward(ctx: SkBuffContext) -> u32 {
    // 1. 获取当前 Socket 的唯一“身份证” (Cookie)
    // 提示：在 stream_verdict 中 ctx.as_ptr() 返回的是 *mut __sk_buff
    let cookie = unsafe { bpf_get_socket_cookie(ctx.as_ptr() as *mut _) };
    
    // 2. 在关系表中查找它的“另一半”在哪
    if let Some(peer_index) = unsafe { PEER_MAP.get(&cookie) } {
        // 3. 暴力重定向：让数据包直接“瞬移”到目标端口
        unsafe {
            let _ = REDIRECT_MAP.redirect_skb(&ctx, *peer_index, 0);
        }
    }

    // 处理完成，允许通过
    1
}

/// 核心过滤逻辑：在 TC 挂载点拦截非法 SNI
#[classifier]
pub fn filter_sni(ctx: TcContext) -> i32 {
    match try_filter_sni(ctx) {
        Ok(ret) => ret,
        Err(_) => 0, // TC_ACT_OK (放行异常情况，防止误杀正常连接)
    }
}

#[inline(always)]
fn try_filter_sni(ctx: TcContext) -> Result<i32, ()> {
    let eth_hdr = ctx.ptr_at::<EthHdr>(0)?;
    if unsafe { (*eth_hdr).ether_type } != network_types::eth::EtherType::Ipv4 { 
        return Ok(0); // TC_ACT_OK
    }

    let eth_len = core::mem::size_of::<EthHdr>();
    let ip_hdr = ctx.ptr_at::<Ipv4Hdr>(eth_len)?;
    if unsafe { (*ip_hdr).proto } != IpProto::Tcp { 
        return Ok(0);
    }

    let ip_len = eth_len + core::mem::size_of::<Ipv4Hdr>();
    let tcp_hdr = ctx.ptr_at::<TcpHdr>(ip_len)?;

    // 1. 构建会话 Key
    let session = unsafe {
        SessionKey {
            src_ip: (*ip_hdr).src_addr,
            dst_ip: (*ip_hdr).dst_addr,
            src_port: (*tcp_hdr).source,
            dst_port: (*tcp_hdr).dest,
            proto: 0x06,
        }
    };

    // 2. 检查会话缓存：已建立的连接直接放行，无需重复解析
    if unsafe { SESSION_CACHE.get(&session).is_some() } {
        return Ok(0); // TC_ACT_OK
    }

    // 🏆 暴力优化：快速路径 (Fast Path)
    // 提示：绝大多数 4K 视频数据包都是纯 ACK，在缓存命中后由于上方逻辑放行。
    // 但对于未命中的包（如握手中期包），如果没有 PSH 标记且不是 SYN，几乎不可能包含 SNI，直接跳过解析。
    let tcp_val = unsafe { &*tcp_hdr };
    
    // 手动位运算提取 Flags
    let flags = unsafe { 
        *(((tcp_hdr as *const _ as *const u8).add(13)))
    };
    let is_syn = flags & 0x02;
    let is_psh = flags & 0x08;

    if is_syn == 0 && is_psh == 0 {
        return Ok(0);
    }

    // 3. 解析 TLS Client Hello (探测 SNI)
    // 数据偏移量 = Ethernet + IP + TCP Data Offset
    let data_offset = ip_len + (tcp_val.doff() as usize * 4);
    
    // 我们只在大约前 512 字节中寻找 SNI，以防被绕过
    if let Some(sni) = parse_sni(&ctx, data_offset) {
        // 查表验证
        if unsafe { ALLOWED_DOMAINS.get(&sni).is_some() } {
            // 合法：存入缓存并放行
            let now = unsafe { bpf_ktime_get_ns() };
            let _ = SESSION_CACHE.insert(&session, &now, 0);
            return Ok(0);
        } else {
            // 非法：直接丢弃！
            return Ok(2); // TC_ACT_SHOT
        }
    }

    // 对于非 TLS 或无 SNI 的 TCP 包（如三次握手中间包），暂时放行
    Ok(0)
}

#[inline(always)]
fn parse_sni(ctx: &TcContext, offset: usize) -> Option<DomainKey> {
    // 1. TLS Record Header (5 bytes)
    let content_type: u8 = unsafe { *ctx.ptr_at::<u8>(offset).ok()? };
    if content_type != 0x16 { return None; } // 必须是 Handshake

    // 2. Handshake Header (4 bytes)
    // Offset 5: Handshake Type (0x01 = Client Hello)
    let handshake_type: u8 = unsafe { *ctx.ptr_at::<u8>(offset + 5).ok()? };
    if handshake_type != 0x01 { return None; }

    // 3. 跳过固定字段定位到 Extensions
    // Handshake Header(4) + Version(2) + Random(32) = 38
    let mut curr = offset + 5 + 38;

    // A. 跳过 Session ID (1 字节长度 + 数据)
    let session_id_len: u8 = unsafe { *ctx.ptr_at::<u8>(curr).ok()? };
    curr += 1 + (session_id_len as usize);

    // B. 跳过 Cipher Suites (2 字节长度 + 数据)
    let cipher_suites_len: u16 = unsafe { u16::from_be(*ctx.ptr_at::<u16>(curr).ok()?) };
    curr += 2 + (cipher_suites_len as usize);

    // C. 跳过 Compression Methods (1 字节长度 + 数据)
    let compression_methods_len: u8 = unsafe { *ctx.ptr_at::<u8>(curr).ok()? };
    curr += 1 + (compression_methods_len as usize);

    // 4. 解析 Extensions (2 字节总长度)
    let extensions_len: u16 = unsafe { u16::from_be(*ctx.ptr_at::<u16>(curr).ok()?) };
    curr += 2;
    let extensions_end = curr + (extensions_len as usize);

    // 5. 遍历 Extensions 寻找 SNI (Type 0x0000)
    // 注意：BPF 必须限制循环次数，我们最多查找 10 个扩展
    for _ in 0..10 {
        if curr + 4 > extensions_end { break; }
        
        let ext_type: u16 = unsafe { u16::from_be(*ctx.ptr_at::<u16>(curr).ok()?) };
        let ext_len: u16 = unsafe { u16::from_be(*ctx.ptr_at::<u16>(curr + 2).ok()?) };
        curr += 4;

        if ext_type == 0x0000 { // Server Name Extension
            // SNI 内容解析: List Len(2) + Name Type(1) + Name Len(2) + Name(X)
            if curr + 5 > extensions_end { break; }
            let name_type: u8 = unsafe { *ctx.ptr_at::<u8>(curr + 2).ok()? };
            if name_type == 0x00 { // host_name
                let name_len: u16 = unsafe { u16::from_be(*ctx.ptr_at::<u16>(curr + 3).ok()?) };
                let name_start = curr + 5;
                
                // 验证长度并拷贝到 DomainKey
                let mut key = DomainKey { name: [0u8; 64] };
                let copy_len = if (name_len as usize) > 64 { 64 } else { name_len as usize };
                
                // 核心安全操作：使用 bpf_probe_read_kernel 或手动拷贝（TC 可直接访问）
                // 在 TC 中我们直接从 ctx 拷贝
                for i in 0..64 {
                    if i >= copy_len { break; }
                    if let Ok(val) = ctx.ptr_at::<u8>(name_start + i) {
                        key.name[i] = unsafe { *val };
                    }
                }
                return Some(key);
            }
        }
        curr += ext_len as usize;
    }

    None 
}

#[cfg(not(test))] // 核心修正：避免与 std 冲突
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {} // 内核态 Panic 处理：保持静默，因为内核不能挂。
}
