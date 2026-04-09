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
    // --- 暴力提速：核心修正 ---
    // 在 aya-ebpf 中，重定向指令目前是由映射表（REDIRECT_MAP）直接发起的。
    // 我们命令它将当前的上下文（ctx）指引向关联的 Socket。
    match REDIRECT_MAP.redirect(&ctx, 0, 0) {
        Ok(_) => 1, // 成功重定向：这里的 1 对应内核中的 SK_PASS。
        Err(_) => 1, // 兜底策略：失败也让数据流向用户态，保证代理逻辑稳健。
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {} // 内核态 Panic 处理：保持静默，因为内核不能挂。
}
