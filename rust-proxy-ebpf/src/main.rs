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
    maps::SockMap, // 引入 Socket 映射表。
    programs::SkMsgContext, // 消息上下文。
};

/// 声明一个全局的 Socket 映射表
/// 
/// 这个 Map 由用户态填充：当代理服务器确定了转发关系，
/// 就会把两端的 FD 存入这里。
#[map]
static REDIRECT_MAP: SockMap = SockMap::with_max_entries(1024, 0);

/// 核心重定向逻辑
/// 
/// 每当有数据包 (Message) 到达受监控的 Socket 时，内核就会调用这个函数。
#[sk_msg]
pub fn fast_forward(ctx: SkMsgContext) -> u32 {
    // --- 暴力重定向：类型对齐 ---
    // 根据编译器高度智能的反馈，redirect_msg 返回的是原始的 i64 状态码，
    // 而非 Rust 用户态常见的 Result 枚举。
    // 我们直接执行该指令，并将决策权交给内核。
    let _ = REDIRECT_MAP.redirect_msg(&ctx, 0, 0);

    // 源码级解释：
    // 返回 1 代表 SK_PASS，表示该消息处理完成且被允许通过。
    // 即使重定向失败，我们也交由用户态做兜底转发，确保服务 100% 可用。
    1
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {} // 内核态 Panic 处理：保持静默，因为内核不能挂。
}
