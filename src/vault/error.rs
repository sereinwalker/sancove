//! Vault 错误类型

use std::fmt;

/// 保密文件库操作错误
#[derive(Debug)]
pub enum VaultError {
    /// 文件 I/O 错误
    Io(std::io::Error),
    /// 数据库操作错误
    Db(rusqlite::Error),
    /// 密码学操作错误
    Crypto(String),
    /// 完整性校验失败
    Integrity(String),
    /// 数据损坏
    Corrupt(String),
    /// 未找到
    NotFound(String),
    /// 序列化/反序列化错误
    Serialize(bincode::Error),
    /// 无效输入
    InvalidInput(String),
    /// 审计日志错误
    AuditLog(String),
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VaultError::Io(e) => write!(f, "I/O 错误: {}", e),
            VaultError::Db(e) => write!(f, "数据库错误: {}", e),
            VaultError::Crypto(e) => write!(f, "密码学错误: {}", e),
            VaultError::Integrity(e) => write!(f, "完整性校验失败: {}", e),
            VaultError::Corrupt(e) => write!(f, "数据损坏: {}", e),
            VaultError::NotFound(e) => write!(f, "未找到: {}", e),
            VaultError::Serialize(e) => write!(f, "序列化错误: {}", e),
            VaultError::InvalidInput(e) => write!(f, "无效输入: {}", e),
            VaultError::AuditLog(e) => write!(f, "审计日志错误: {}", e),
        }
    }
}

impl std::error::Error for VaultError {}
