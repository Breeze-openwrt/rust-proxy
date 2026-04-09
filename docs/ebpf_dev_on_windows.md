# 💡 Windows 开发者：如何在提交前“预知” eBPF 编译错误？

由于 eBPF 是 Linux 内核的高级特性，通常情况下只有在 Linux 环境（如 GitHub Actions）下才能发现编译错误。这会导致反馈周期极长。

通过以下技巧，您可以在 **Windows** 本地开发时，通过 VSCode 或命令行秒级发现 99% 的 eBPF API 错误。

---

### 1. 安装跨平台编译目标
在 Windows 终端（PowerShell）执行一次以下命令：
```powershell
rustup target add bpfel-unknown-none
```
这个 target 代表“小端序、无操作系统、BPF 格式”。它不需要 Linux 内核，只需要 Rust 编译器支持。

### 2. 执行静态检查 (Static Check) —— 推荐脚本模式
**暴力提速核心套路**：为了方便您，我已经在项目中集成了 **`scripts/check.ps1`** 脚本。

每当您修改了代码，只需在包含项目的 PowerShell 窗口执行：
```powershell
.\scripts\check.ps1
```

**该脚本会为您自动完成：**
1.  **环境体检**：自动发现并提示您安装缺失的 Target。
2.  **内核态扫描**：自动进入 `rust-proxy-ebpf` 目录执行跨平台 API 校验。
3.  **用户态验证**：自动运行 SNI 解析器的单元测试，确保转发逻辑不出错。

如果您倾向于手动执行，步骤如下：
```powershell
cd rust-proxy-ebpf
cargo check --target bpfel-unknown-none
```

### 3. VSCode 实时报错
如果您想在 VSCode 中也看到红色波浪线报错：
1. 在项目根目录创建或进入 `.vscode/settings.json`。
2. 找到 `rust-analyzer.check.extraArgs` 配置项。
3. 添加或修改为：`["--target", "bpfel-unknown-none"]`。

---

### 🚀 关于 Rust 的性能分层 (v2, v3)
本项目现已通过 `-C target-cpu=x86-64-v3` 实现了与 Go 语言相同的指令集优化：
- **Standard (v1)**: 兼容所有服务器。
- **v3 (Performance Monster)**: 专为近 10 年的现代服务器打造，一键开启 AVX2/BMI2，将网络转发性能推向物理极限。

*如果您在 Linux 环境看到编译错误，请先尝试上述本地 Check 方案！*
