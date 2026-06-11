//! 防篡改审计日志（哈希链）
//!
//! 基于 SM3 哈希链 + HMAC-SM3 完整性保护，实现不可伪造的审计日志。
//! 日志条目按序号递增链接，每个条目标含前一条目的 SM3 哈希值（prev_hash），
//! 形成哈希链结构。任何对历史条目的篡改均可在遍历全链时被检测。
//!
//! # 安全模型
//!
//! - **防篡改**：每条日志包含前一条的哈希引用，修改任一历史条目将导致后续所有哈希验证失败。
//! - **完整性验证**：每条日志的 HMAC-SM3(KEK, serialized_entry) 确保条目内容未被未授权方修改。
//! - **密钥绑定**：HMAC 密钥为 KEK（由用户密码经 PBKDF2-SM3 派生），只有持有正确密码者才能追加有效日志。
//! - **自校验**：每个条目的 `hash` 字段是其逻辑内容的 SM3 摘要，与 HMAC 形成双重防护。
//!
//! # Schema
//!
//! ```sql
//! CREATE TABLE audit_log (
//!     idx         INTEGER PRIMARY KEY,
//!     entry_blob  BLOB NOT NULL,
//!     hmac_tag    BLOB NOT NULL
//! );
//! ```

mod error;
mod export;

pub use error::AuditLogError;
pub use export::chrono_from_timestamp;

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};

use crate::crypto::secure_eq::constant_time_eq_32;
use crate::crypto::sm3::{Sm3, hmac_sm3};

// ============================================================
// 常量
// ============================================================

/// SM3 哈希输出长度 / HMAC-SM3 标签长度（字节）
const HASH_LEN: usize = 32;

// ============================================================
// 审计日志条目类型
// ============================================================

/// 审计日志条目类型枚举
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditEntryType {
    /// 文件导入保险箱
    FileImport = 0,
    /// 从保险箱导出文件
    FileExport = 1,
    /// 从保险箱移除文件
    FileDelete = 2,
    /// 修改保险箱密码
    PasswordChange = 3,
    /// 创建新保险箱
    VaultCreate = 4,
    /// 备份保险箱
    VaultBackup = 5,
    /// 从备份恢复保险箱
    VaultRestore = 6,
    /// 重命名文件
    FileRename = 7,
    /// 打开保险箱（登录）
    VaultOpen = 8,
    /// 关闭保险箱（登出）
    VaultClose = 9,
    /// GUI 操作（搜索、复制公钥、基准测试等）
    GuiAction = 10,
}

impl AuditEntryType {
    /// 将 u8 转换为枚举值
    pub fn from_u8(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::FileImport),
            1 => Some(Self::FileExport),
            2 => Some(Self::FileDelete),
            3 => Some(Self::PasswordChange),
            4 => Some(Self::VaultCreate),
            5 => Some(Self::VaultBackup),
            6 => Some(Self::VaultRestore),
            7 => Some(Self::FileRename),
            8 => Some(Self::VaultOpen),
            9 => Some(Self::VaultClose),
            10 => Some(Self::GuiAction),
            _ => None,
        }
    }

    /// 返回条目类型的可读名称（中文）
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::FileImport => "文件导入",
            Self::FileExport => "文件导出",
            Self::FileDelete => "文件删除",
            Self::PasswordChange => "密码修改",
            Self::VaultCreate => "创建保险箱",
            Self::VaultBackup => "保险箱备份",
            Self::VaultRestore => "保险箱恢复",
            Self::FileRename => "文件重命名",
            Self::VaultOpen => "打开保险箱",
            Self::VaultClose => "关闭保险箱",
            Self::GuiAction => "GUI 操作",
        }
    }

    /// 返回条目类型的英文标识（用于 JSON 导出）
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::FileImport => "FileImport",
            Self::FileExport => "FileExport",
            Self::FileDelete => "FileDelete",
            Self::PasswordChange => "PasswordChange",
            Self::VaultCreate => "VaultCreate",
            Self::VaultBackup => "VaultBackup",
            Self::VaultRestore => "VaultRestore",
            Self::FileRename => "FileRename",
            Self::VaultOpen => "VaultOpen",
            Self::VaultClose => "VaultClose",
            Self::GuiAction => "GuiAction",
        }
    }
}

// ============================================================
// 审计日志条目结构体
// ============================================================

/// 审计日志中的单一条目
///
/// 每一条目包含序号、时间戳、条目类型、前一条目的哈希、自身哈希和载荷。
/// `hash` 字段通过 SM3(idx || timestamp || entry_type || prev_hash || payload) 计算。
/// 存储时使用 bincode 序列化为 entry_blob，HMAC 基于 entry_blob 计算。
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AuditEntry {
    /// 序号（从 0 开始递增，单调递增）
    pub idx: u64,
    /// Unix 时间戳（秒）
    pub timestamp: i64,
    /// 条目类型码（对应 AuditEntryType 的 u8 值）
    pub entry_type: u8,
    /// 前一条目的 SM3 哈希值（创世条目为全零 [0u8; HASH_LEN]）
    pub prev_hash: [u8; HASH_LEN],
    /// 本条目的 SM3 哈希值：SM3(idx || timestamp || entry_type || prev_hash || payload)
    pub hash: [u8; HASH_LEN],
    /// 条目载荷（UTF-8 文本字节，如文件名、路径等；无额外数据时为空切片）
    pub payload: Vec<u8>,
}

// ============================================================
// 审计日志操作接口
// ============================================================

/// 防篡改审计日志操作接口
///
/// 管理 vault.db 中的 `audit_log` 表，提供哈希链追加、查询、
/// 完整性验证和 JSON 导出功能。
pub struct AuditLog {
    pub(crate) conn: Connection,
}

impl AuditLog {
    /// 打开或创建审计日志数据库
    ///
    /// 打开指定路径的 SQLite 数据库，若 `audit_log` 表不存在则自动创建。
    pub fn open(db_path: &Path) -> rusqlite::Result<Self> {
        let conn = Connection::open(db_path)?;

        crate::db::apply_safe_pragmas(&conn)?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS audit_log (
                idx         INTEGER PRIMARY KEY,
                entry_blob  BLOB NOT NULL,
                hmac_tag    BLOB NOT NULL
            )",
            [],
        )?;

        Ok(Self { conn })
    }

    /// 追加一条新的审计日志条目
    ///
    /// 自动获取当前索引和上一条目的哈希值，计算本条目的哈希，
    /// 序列化后用 KEK 计算 HMAC 标签，在事务中写入数据库。
    pub fn append(
        &self,
        entry_type: AuditEntryType,
        kek: &[u8],
        payload: &[u8],
    ) -> Result<AuditEntry, AuditLogError> {
        self.conn
            .execute_batch("BEGIN")
            .map_err(AuditLogError::Db)?;

        let result = (|| -> Result<AuditEntry, AuditLogError> {
            let (next_idx, prev_hash) = Self::get_latest_hash_impl(&self.conn)?;

            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;

            let type_code = entry_type as u8;
            let hash = compute_entry_hash(next_idx, timestamp, type_code, &prev_hash, payload);

            let entry = AuditEntry {
                idx: next_idx,
                timestamp,
                entry_type: type_code,
                prev_hash,
                hash,
                payload: payload.to_vec(),
            };

            let entry_blob = bincode::serialize(&entry).map_err(AuditLogError::Serialize)?;

            let hmac_tag = hmac_sm3(kek, &entry_blob);

            self.conn
                .execute(
                    "INSERT INTO audit_log (idx, entry_blob, hmac_tag) VALUES (?1, ?2, ?3)",
                    params![entry.idx as i64, entry_blob, hmac_tag.to_vec()],
                )
                .map_err(AuditLogError::Db)?;

            Ok(entry)
        })();

        match result {
            Ok(entry) => {
                self.conn
                    .execute_batch("COMMIT")
                    .map_err(AuditLogError::Db)?;
                Ok(entry)
            }
            Err(e) => {
                // ROLLBACK 失败不应掩盖原错误
                let _ = self.conn.execute_batch("ROLLBACK");
                Err(e)
            }
        }
    }

    /// 获取最近 N 条审计日志条目
    pub fn get_recent(
        &self,
        limit: usize,
    ) -> Result<Vec<(AuditEntry, [u8; HASH_LEN])>, AuditLogError> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT entry_blob, hmac_tag FROM audit_log ORDER BY idx DESC LIMIT ?1")
            .map_err(AuditLogError::Db)?;

        let rows = stmt
            .query_map(params![limit as i64], |row| {
                let entry_blob: Vec<u8> = row.get(0)?;
                let hmac_tag: Vec<u8> = row.get(1)?;
                Ok((entry_blob, hmac_tag))
            })
            .map_err(AuditLogError::Db)?;

        let mut results = Vec::new();
        for row in rows {
            let (entry_blob, hmac_tag_vec) = row.map_err(AuditLogError::Db)?;
            let entry: AuditEntry =
                bincode::deserialize(&entry_blob).map_err(AuditLogError::Serialize)?;

            if hmac_tag_vec.len() != HASH_LEN {
                return Err(AuditLogError::Corrupt("HMAC 标签长度异常".to_string()));
            }
            let mut hmac_arr = [0u8; HASH_LEN];
            hmac_arr.copy_from_slice(&hmac_tag_vec);

            results.push((entry, hmac_arr));
        }

        Ok(results)
    }

    /// 验证整个审计日志哈希链的完整性
    ///
    /// 按序号升序遍历全部条目，执行三重验证：
    /// 1. HMAC 验证
    /// 2. 内容哈希验证
    /// 3. 链式 prev_hash 验证
    pub fn verify_chain(&self, kek: &[u8]) -> Result<bool, AuditLogError> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT idx, entry_blob, hmac_tag FROM audit_log ORDER BY idx ASC")
            .map_err(AuditLogError::Db)?;

        let rows = stmt
            .query_map([], |row| {
                let idx: i64 = row.get(0)?;
                let entry_blob: Vec<u8> = row.get(1)?;
                let hmac_tag: Vec<u8> = row.get(2)?;
                Ok((idx, entry_blob, hmac_tag))
            })
            .map_err(AuditLogError::Db)?;

        let mut expected_prev_hash = [0u8; HASH_LEN];
        let mut entry_count = 0u64;

        for row in rows {
            let (idx, entry_blob, hmac_tag_vec) = row.map_err(AuditLogError::Db)?;

            if hmac_tag_vec.len() != HASH_LEN {
                return Err(AuditLogError::Corrupt(format!(
                    "条目 {} 的 HMAC 标签长度异常",
                    idx
                )));
            }
            let mut stored_hmac = [0u8; HASH_LEN];
            stored_hmac.copy_from_slice(&hmac_tag_vec);

            // 验证 1：HMAC-SM3(KEK, entry_blob) == stored_hmac
            let computed_hmac = hmac_sm3(kek, &entry_blob);
            if !constant_time_eq_32(&computed_hmac, &stored_hmac) {
                return Err(AuditLogError::ChainBroken(format!(
                    "条目 {} 的 HMAC 验证失败，数据可能被篡改",
                    idx
                )));
            }

            let entry: AuditEntry =
                bincode::deserialize(&entry_blob).map_err(AuditLogError::Serialize)?;

            if entry.idx as i64 != idx {
                return Err(AuditLogError::ChainBroken(format!(
                    "条目索引不一致：数据库为 {}，条目内为 {}",
                    idx, entry.idx
                )));
            }

            // 验证 2：重新计算内容哈希
            let expected_hash = compute_entry_hash(
                entry.idx,
                entry.timestamp,
                entry.entry_type,
                &entry.prev_hash,
                &entry.payload,
            );
            if expected_hash != entry.hash {
                return Err(AuditLogError::ChainBroken(format!(
                    "条目 {} 的内容哈希不一致",
                    entry.idx
                )));
            }

            // 验证 3：链式 prev_hash
            if entry.prev_hash != expected_prev_hash {
                return Err(AuditLogError::ChainBroken(format!(
                    "条目 {} 的 prev_hash 与前一条目的 hash 不匹配",
                    entry.idx
                )));
            }

            expected_prev_hash = entry.hash;
            entry_count += 1;
        }

        // 检查索引连续性
        if entry_count > 0 {
            let max_idx: Option<i64> = self
                .conn
                .query_row("SELECT MAX(idx) FROM audit_log", [], |row| row.get(0))
                .map_err(AuditLogError::Db)?;

            let count: i64 = self
                .conn
                .query_row("SELECT COUNT(*) FROM audit_log", [], |row| row.get(0))
                .map_err(AuditLogError::Db)?;

            if let Some(mx) = max_idx
                && mx + 1 != count
            {
                return Err(AuditLogError::ChainBroken(format!(
                    "条目索引不连续：最大索引={}，条目数={}",
                    mx, count
                )));
            }
        }

        Ok(true)
    }

    /// 获取审计日志条目总数
    pub fn count(&self) -> rusqlite::Result<u64> {
        self.conn
            .query_row("SELECT COUNT(*) FROM audit_log", [], |row| row.get(0))
    }

    // ============================================================
    // 内部辅助方法
    // ============================================================

    /// 在指定连接上查询最新索引和哈希（用于追加时计算 prev_hash）
    fn get_latest_hash_impl(conn: &Connection) -> Result<(u64, [u8; HASH_LEN]), AuditLogError> {
        let result: Result<Vec<u8>, _> = conn.query_row(
            "SELECT entry_blob FROM audit_log ORDER BY idx DESC LIMIT 1",
            [],
            |row| row.get(0),
        );

        match result {
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok((0, [0u8; HASH_LEN])),
            Err(e) => Err(AuditLogError::Db(e)),
            Ok(entry_blob) => {
                let latest_entry: AuditEntry =
                    bincode::deserialize(&entry_blob).map_err(AuditLogError::Serialize)?;
                Ok((latest_entry.idx + 1, latest_entry.hash))
            }
        }
    }
}

// ============================================================
// 哈希计算辅助函数
// ============================================================

/// 计算审计日志条目的 SM3 哈希值
fn compute_entry_hash(
    idx: u64,
    timestamp: i64,
    entry_type: u8,
    prev_hash: &[u8; 32],
    payload: &[u8],
) -> [u8; 32] {
    let mut hasher = Sm3::new();
    hasher.update(&idx.to_be_bytes());
    hasher.update(&timestamp.to_be_bytes());
    hasher.update(&[entry_type]);
    hasher.update(prev_hash);
    hasher.update(payload);
    hasher.finalize()
}

// ============================================================
// 测试
// ============================================================

#[cfg(test)]
mod tests;
