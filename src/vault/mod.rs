//! Vault 核心业务层
//!
//! 实现保密文件库的全部操作：
//!
//! - 创建/打开保险箱（KEK 派生 + 初始化数据库）
//! - 导入文件（SM4-CTR 加密 + HMAC-SM3 完整性保护）
//! - 导出文件（Verify-then-Decrypt 先验证后解密）
//! - 列文件（解密元数据展示文件名列表）
//! - 移除文件（删除数据库记录 + 密文文件）
//!
//! # 密钥体系
//!
//! ```text
//! 用户密码 ──PBKDF2-SM3──→ KEK (16B) ──SM4-CBC──→ 加密 DEK 存数据库
//!                                                      │
//! OsRng ───────────────→ DEK (32B) ←───────────────────┘
//!                          ├── DEK_enc[0..16] ──SM4-CTR──→ 文件密文
//!                          └── DEK_mac[16..32] ─HMAC-SM3──→ 完整性标签
//! ```

mod core;
pub(crate) mod error;
mod export;
mod files;
pub(crate) mod helpers;
mod import;
mod interface;
mod internal;
mod manage;
#[cfg(test)]
mod tests;

pub use error::VaultError;

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::audit_log::AuditLog;
use crate::crypto::sm4_ctr::Sm4Key;
use crate::db::FileDb;

// ============================================================
// 常量
// ============================================================

/// PBKDF2-SM3 迭代次数
const KDF_ITERATIONS: u32 = 600_000;

/// 数据加密密钥长度（32 字节：前 16 为 DEK_enc，后 16 为 DEK_mac）
const DEK_SIZE: usize = 32;

/// 加密数据库头大小: salt(16) + verify_tag(32) + db_iv(16) = 64 字节
const DB_ENC_HEADER_SIZE: usize = 64;

/// 配置文件中的 salt key
const CONFIG_KEY_SALT: &str = "vault_salt";

/// 密码验证标签 key
const CONFIG_KEY_VERIFY: &str = "vault_verify";

/// HMAC-SM3 密码验证上下文字符串
const PWD_VERIFY_CONTEXT: &[u8] = b"vault_password_verify_v1";

/// SM2 公钥配置 key
const CONFIG_KEY_SM2_PUB: &str = "sm2_pub_key";
/// SM2 私钥加密 IV 配置 key
const CONFIG_KEY_SM2_IV: &str = "sm2_priv_iv";
/// SM2 加密私钥配置 key
const CONFIG_KEY_SM2_PRIV: &str = "sm2_encrypted_priv";

/// 盲索引派生上下文字符串（HMAC-SM3 上下文分离，防止密钥误用）
const BLIND_INDEX_CONTEXT: &[u8] = b"blind_index_key_v1";

/// 消毒后文件名为空时的回退默认名
pub(crate) const DEFAULT_FILE_NAME: &str = "unnamed_file";

// ============================================================
// 数据结构
// ============================================================

/// 文件元数据（加密后作为 envelope 存储）
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FileMetadata {
    /// 原始文件名
    pub filename: String,
    /// 文件原始大小（字节）
    pub original_size: u64,
    /// 导入时间戳（Unix 纪元秒）
    pub created_at: i64,
}

/// 列表中展示的文件信息
#[derive(Debug, Clone)]
pub struct FileInfo {
    /// 盲索引（用于后续操作定位文件）
    pub blind_index: [u8; 32],
    /// 解密后的文件名
    pub filename: String,
    /// 文件原始大小
    pub original_size: u64,
    /// 导入时间
    pub created_at: i64,
}

// ============================================================
// Vault 主结构体
// ============================================================

/// 保密文件库实例
///
/// 持有期仅存在于用户会话期间，Drop 时自动零化密钥。
pub struct Vault {
    pub(crate) db: FileDb,
    /// 文件库根目录
    pub(crate) vault_dir: PathBuf,
    /// 临时解密数据库路径（会话结束后加密写回 vault.db）
    pub(crate) db_temp_path: PathBuf,
    /// 密钥加密密钥
    pub(crate) kek: Zeroizing<[u8; 16]>,
    /// 预展开的 KEK 轮密钥
    pub(crate) kek_sm4: Sm4Key,
    /// 文件库盐值
    pub(crate) vault_salt: Zeroizing<[u8; 16]>,
    /// 防篡改审计日志
    pub(crate) audit_log: Option<AuditLog>,
    /// SM2 公钥
    pub(crate) sm2_pub_key: Option<[u8; 65]>,
    /// SM2 私钥
    pub(crate) sm2_priv_key: Option<Zeroizing<[u8; 32]>>,
}

impl Drop for Vault {
    fn drop(&mut self) {
        // 记录关闭事件
        self.log_audit_event(crate::audit_log::AuditEntryType::VaultClose, b"");
        // 将临时数据库加密写回 vault.db
        if let Err(e) = self.save_database() {
            eprintln!("保存加密数据库失败: {}", e);
        }
        // 清理临时数据库相关文件
        let temp_path_str = self.db_temp_path.to_string_lossy().to_string();
        let _ = std::fs::remove_file(&self.db_temp_path);
        let _ = std::fs::remove_file(format!("{}-wal", temp_path_str));
        let _ = std::fs::remove_file(format!("{}-shm", temp_path_str));
    }
}
