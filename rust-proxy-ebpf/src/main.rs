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
    macros::{sk_msg, map}, // 引入 BPF 程序宏。
    maps::{SockMap, HashMap}, // 引入 Socket 映射表与哈希表。
    programs::SkMsgContext, // 消息上下文。
    helpers::bpf_get_socket_cookie, // 获取 Socket 唯一标识的黑科技。
};

/// 声明一个全局的 Socket 映射表
/// 
/// 这个 Map 由用户态填充：存放所有的活跃 Socket。
#[map]
static REDIRECT_MAP: SockMap = SockMap::with_max_entries(1024, 0);

/// 映射关系表：Socket Cookie -> 目标在 REDIRECT_MAP 中的索引
#[map]
static PEER_MAP: HashMap<u64, u32> = HashMap::with_max_entries(1024, 0);

/// 核心重定向逻辑
/// 
/// 每当有数据包 (Message) 到达受监控的 Socket 时，内核就会调用这个函数。
#[sk_msg]
pub fn fast_forward(ctx: SkMsgContext) -> u32 {
    // 1. 获取当前 Socket 的唯一“身份证” (Cookie)
    let cookie = unsafe { bpf_get_socket_cookie(ctx.msg as *mut _) };
    
    // 2. 在关系表中查找它的“另一半”在哪
    if let Some(peer_index) = unsafe { PEER_MAP.get(&cookie) } {
        // 3. 暴力重定向：让数据包直接“瞬移”到目标端口
        unsafe {
            let _ = REDIRECT_MAP.redirect_msg(&ctx, *peer_index, 0);
        }
    }

    // 处理完成，允许通过
    1
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {} // 内核态 Panic 处理：保持静默，因为内核不能挂。
}
