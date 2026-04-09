# 📏 Rust-Proxy 高性能开发规范

> **口号**: “每一毫秒的等待，都是对 CPU 算力的浪费。”

---

## 1. 内存管理标准 (Memory Standards)

### 1.1 坚持零拷贝 (Zero-copy)
- **要求**: 在处理数据包中转时，禁止使用 `Clone()` 或内存拷贝。
- **工具**: 优先使用 `bytes` 库的引用计数视图。

### 1.2 规避堆分配 (No Heap Allocation in Hotpath)
- **红线**: 在单次请求的处理路径（Hotpath）上，严禁动态分配 `Vec` 或 `String`。
- **对策**: 使用 `ArrayVec` 或预分配好的对象池。

## 2. 内核调优标准 (Kernel Tuning Standards)

所有的网络监听器（Listener）必须调用 `SocketOptimizer` 进行封印解除：

| 变量名 | 标准设值 | 调优意图 |
| :--- | :--- | :--- |
| `SO_REUSEPORT` | `true` | 启用核心级负载均衡，多核并行 Accept。 |
| `TCP_NODELAY` | `true` | 禁用 Nagle，追求极致首包响应速度。 |
| `SO_RCVBUF` | `4MiB` | 巨型接收窗口，应对高频突发流量。 |
| `SO_SNDBUF` | `4MiB` | 巨型发送窗口，消除发送阻塞。 |
| `TCP_QUICKACK` | `1` | 快速确认，加快 TCP 滑动窗口滑动。 |

## 3. 异步并发规范 (Concurrency Standards)

### 3.1 核心绑定与亲和性 (CPU Affinity)
- 在生产环境下，每个工作线程必须锁定（Pin）在一个物理核心上。
- 严禁在 Monoio 线程中调用任何带有阻塞属性的 `std` 系列库函数。

### 3.2 无锁化数据交换
- 内部信令传输应优先使用基于 Atomic 的 SPSC (单生产单消费) 队列，避免 Mutex 造成的上下文切换。

## 4. 注释与文档规范 (Documentation Quality)

> 依照“反重力规则”，代码不仅要快，还要易读。

- **函数级**: 必须描述其对性能的影响（如：是否有内存分配）。
- **语句级**: 对于底层 `unsafe` 或 BPF Helper 指令，必须由通俗的中文解释其内核原理。
- **源码分析级**: 核心逻辑区需包含“代码赏析”注释，解释为什么要这么写。

---

> [!CAUTION]
> **AI 参考指引**: 所有的 AI 生成代码或重构建议，必须经过上述“调优标准”的脱敏与加持。任何降低吞吐量的改动应被标记为 High Risk。
