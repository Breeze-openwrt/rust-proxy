use aya::Ebpf;
use std::fs;

fn main() {
    let path = "target/bpfel-unknown-none/release/rust_proxy_ebpf_kernel";
    println!("🔍 正在诊断: {}", path);
    
    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            println!("❌ 无法读取: {}", e);
            return;
        }
    };

    println!("📊 大小: {} 字节, 魔法字节: {:02x?}", data.len(), &data[0..4]);

    // Aya 0.13.1 使用 Ebpf::load
    match Ebpf::load(&data) {
        Ok(_) => println!("✅ [SUCCESS] Aya 完美解析了字节码！"),
        Err(e) => {
            println!("❌ [FAILED] Aya 解析失败: {:?}", e);
            println!("💡 详细错误: {:#?}", e);
        }
    }
}
