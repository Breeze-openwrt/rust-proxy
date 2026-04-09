# 🚀 Rust-Proxy 高性能流水线指南 (CI/CD)

> **原则**: 自动化、分层化、幂等化。

---

## 1. 编译分层策略 (CPU Tiering)

为了兼顾通用性和极致性能，流水线会自动产出两个版本的 Linux 二进制包：

- **Standard (amd64)**: 兼容所有 64 位 Intel/AMD CPU。
- **v3 (Performance Monster)**: 开启 `x86-64-v3` 优化。
    - **激活指令**: AVX, AVX2, BMI2, FMA。
    - **性能收益**: 对协议解析和 CRC 校验有显著硬件加速效果。

## 2. 内核态自动构建 (eBPF Pipeline)

eBPF 的构建流程具有高度特殊性：
1. **工具链**: 必须使用 Nightly Rust。
2. **重编译**: 必须指定 `-Z build-std=core`，因为 eBPF 环境没有现成的预编译基础库。
3. **目标**: `bpfel-unknown-none`。
4. **验证**: 生成的字节码将被嵌入用户态安装包，或作为独立资产发布。

## 3. 幂等发布逻辑 (Clean Release)

模仿 `gnet-proxy` 的发布风格：
- 每次触发流水线都会 **自动删除旧的同名 Release**。
- 这确保了用户下载的永远是当前主分支的最新成果。
- 使用 `gh` (GitHub CLI) 进行资产的暴力清理与重建。

## 4. 维护说明 (Maintenance)

- **Workflow 文件**: `.github/workflows/bin-release.yml`
- **关键环境变量**: `GITHUB_TOKEN` 用于 Release 权限授权。

---

> [!CAUTION]
> **AI 参考指引**: 当修改流水线时，严禁删除 `-Z build-std` 参数，否则 eBPF 编译将彻底崩溃。
