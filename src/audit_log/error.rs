//! 审计日志错误类型

/// 审计日志操作错误
#[derive(Debug)]
pub enum AuditLogError {
    /// 数据库操作错误
    Db(rusqlite::Error),
    /// 序列化/反序列化错误
    Serialize(bincode::Error),
    /// 数据损坏（数据库数据格式异常，非恶意篡改）
    Corrupt(String),
    /// 哈希链完整性验证失败（数据被篡改）
    ChainBroken(String),
}

impl std::fmt::Display for AuditLogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditLogError::Db(e) => write!(f, "数据库错误: {}", e),
            AuditLogError::Serialize(e) => write!(f, "序列化错误: {}", e),
            AuditLogError::Corrupt(e) => write!(f, "数据损坏: {}", e),
            AuditLogError::ChainBroken(e) => write!(f, "审计日志完整性验证失败: {}", e),
        }
    }
}

impl std::error::Error for AuditLogError {}
