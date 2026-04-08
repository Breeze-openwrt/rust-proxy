//! # SNI (Server Name Indication) 安全解析器 (由 tls-parser 强力驱动)
//! 
//! 本模块经过精品化重构，移除了手写的二进制解析逻辑，
//! 改为使用社区流行的 `tls-parser` 库。
//! 
//! 为什么要这么做？
//! 1. **工业级鲁棒性**: 能够处理 TLS 1.2/1.3 各种复杂的扩展排列。
//! 2. **防御性编程**: 内置了完善的长度校验，从根本上杜绝了缓冲区溢出风险。
//! 3. **高性能**: 该库基于 Nom 框架，依然保持了零拷贝解析的特性。

use tls_parser::{parse_tls_plaintext, TlsMessage, TlsMessageHandshake, TlsExtension}; // 引入流行的 TLS 解析逻辑。

/// 解析结果枚举 (保持 API 与旧版兼容)
pub enum SniResult {
    /// 成功提取到域名
    Found(String),
    /// 数据不完整，需要更多字节
    Incomplete,
    /// 解析出错或非 TLS 协议
    Error,
}

/// SNI 解析助手
pub struct SniParser;

impl SniParser {
    /// 利用流行的 tls-parser 库提取 SNI
    /// 
    /// 参数 `data` 是从 TCP 连接中读取的原始数据。
    pub fn parse(data: &[u8]) -> SniResult {
        // --- 步骤 1: 使用 tls-parser 进行初次解析 ---
        // parse_tls_plaintext 会解析 TLS Record Header 并提取内部的消息。
        match parse_tls_plaintext(data) {
            Ok((_, record)) => {
                // 遍历 Record 中的每一个消息（TLS 支持在一个包里放多个消息）
                for msg in record.msg {
                    if let TlsMessage::Handshake(TlsMessageHandshake::ClientHello(hello)) = msg {
                        // 源码欣赏：利用模式匹配深度进入 ClientHello 结构
                        // 我们需要寻找 Extensions 列表。
                        if let Some(extensions) = hello.ext {
                            return Self::extract_from_extensions(extensions);
                        }
                    }
                }
                SniResult::Error
            }
            Err(e) => {
                // 判断错误类型：如果是数据不足，则返回 Incomplete。
                if e.is_incomplete() {
                    SniResult::Incomplete
                } else {
                    SniResult::Error
                }
            }
        }
    }

    /// 从扩展列表中精准提取服务器名称
    fn extract_from_extensions(extensions: &[u8]) -> SniResult {
        // 使用 tls-parser 提供的扩展解析器
        use tls_parser::parse_tls_extensions;
        
        match parse_tls_extensions(extensions) {
            Ok((_, ext_list)) => {
                // 遍历所有扩展，寻找 SNI (Type 0)
                for ext in ext_list {
                    if let TlsExtension::SNI(sni_list) = ext {
                        // SNI 列表通常只有一个 HostName (0x00) 类型
                        for (sni_type, sni_name) in sni_list {
                            if sni_type == tls_parser::SNIType::HostName {
                                // 将字节切片转换为 String，实现最终提取
                                return SniResult::Found(String::from_utf8_lossy(sni_name).into_owned());
                            }
                        }
                    }
                }
                SniResult::Error
            }
            Err(_) => SniResult::Error,
        }
    }
}

// 注意：原先的测试用例依旧有效。由于库的接口更健壮，
// 我们不再需要手动编写大量的偏移量计算，代码变得极度清晰！
