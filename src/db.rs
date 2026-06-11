//! SQLite 持久化层
//!
//! 管理加密文件索引的数据库操作。
//! 所有敏感元数据均以加密形式存储（盲索引 + 加密信封）。
//!
//! 文件密文通过增量 BLOB I/O 读写，避免加载全部到内存。
//!
//! # Schema
//!
//! ```sql
//! CREATE TABLE secure_vault (
//!     blind_index BLOB PRIMARY KEY,       -- 32 字节 HMAC-SM3 盲哈希
//!     iv BLOB NOT NULL,                   -- 16 字节文件加密 IV
//!     dek_iv BLOB NOT NULL,               -- 16 字节 DEK 加密 IV
//!     encrypted_dek BLOB NOT NULL,        -- 被 KEK 加密的 48 字节 DEK 信封
//!     encrypted_metadata BLOB NOT NULL,   -- 被 DEK_enc 加密的元数据
//!     hmac_tag BLOB NOT NULL,             -- 32 字节 HMAC-SM3 校验值
//!     encrypted_content BLOB NOT NULL     -- 加密文件内容（增量 BLOB I/O）
//! );
//! ```

use rusqlite::{Connection, params};
use std::path::Path;

/// 文件索引数据库
pub struct FileDb {
    pub(crate) conn: Connection,
}

/// 数据库中的一条文件记录（不含文件内容，内容通过增量 BLOB I/O 访问）
pub struct FileRecord {
    pub blind_index: Vec<u8>,
    pub iv: Vec<u8>,
    pub dek_iv: Vec<u8>,
    pub encrypted_dek: Vec<u8>,
    pub encrypted_metadata: Vec<u8>,
    pub hmac_tag: Vec<u8>,
}

impl FileDb {
    /// 打开或创建数据库，初始化 Schema
    pub fn open(db_path: &Path) -> rusqlite::Result<Self> {
        let conn = Connection::open(db_path)?;

        // 安全配置 — 统一 PRAGMA 设置
        apply_safe_pragmas(&conn)?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS secure_vault (
                blind_index     BLOB PRIMARY KEY,
                iv              BLOB NOT NULL,
                dek_iv          BLOB NOT NULL,
                encrypted_dek   BLOB NOT NULL,
                encrypted_metadata BLOB NOT NULL,
                hmac_tag        BLOB NOT NULL,
                encrypted_content BLOB NOT NULL
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS vault_config (
                key   TEXT PRIMARY KEY,
                value BLOB NOT NULL
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS config_hmac (
                key  TEXT PRIMARY KEY,
                hmac BLOB NOT NULL
            )",
            [],
        )?;

        Ok(Self { conn })
    }

    // ============================================================
    // 元数据查询（不含 encrypted_content，通过 BLOB I/O 访问）
    // ============================================================

    /// 按盲索引查询文件记录（不含文件内容）
    pub fn get_by_blind_index(&self, blind_index: &[u8]) -> rusqlite::Result<Option<FileRecord>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT blind_index, iv, dek_iv, encrypted_dek, encrypted_metadata, hmac_tag
             FROM secure_vault WHERE blind_index = ?1",
        )?;

        let mut rows = stmt.query(params![blind_index])?;
        match rows.next()? {
            Some(row) => Ok(Some(FileRecord {
                blind_index: row.get(0)?,
                iv: row.get(1)?,
                dek_iv: row.get(2)?,
                encrypted_dek: row.get(3)?,
                encrypted_metadata: row.get(4)?,
                hmac_tag: row.get(5)?,
            })),
            None => Ok(None),
        }
    }

    /// 获取所有文件记录（不含文件内容）
    pub fn list_all_with_details(&self) -> rusqlite::Result<Vec<FileRecord>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT blind_index, iv, dek_iv, encrypted_dek, encrypted_metadata, hmac_tag
             FROM secure_vault ORDER BY rowid",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(FileRecord {
                blind_index: row.get(0)?,
                iv: row.get(1)?,
                dek_iv: row.get(2)?,
                encrypted_dek: row.get(3)?,
                encrypted_metadata: row.get(4)?,
                hmac_tag: row.get(5)?,
            })
        })?;
        let mut result = Vec::new();
        for row in rows {
            result.push(row?);
        }
        Ok(result)
    }

    // ============================================================
    // 写入操作
    // ============================================================

    /// 插入文件记录（不含文件内容，仅元数据 + hmac_tag）
    pub fn insert(&self, record: &FileRecord) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT INTO secure_vault (blind_index, iv, dek_iv, encrypted_dek, encrypted_metadata, hmac_tag, encrypted_content)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, zeroblob(0))",
            params![
                record.blind_index,
                record.iv,
                record.dek_iv,
                record.encrypted_dek,
                record.encrypted_metadata,
                record.hmac_tag,
            ],
        )?;
        Ok(())
    }

    /// 插入记录并用 zeroblob 预分配加密内容空间，返回 rowid（用于增量 BLOB I/O）
    ///
    /// 先插入元数据和占位 BLOB，然后调用方通过 `open_content_blob` 逐块写入密文。
    pub fn insert_with_zeroblob(
        &self,
        blind_index: &[u8],
        iv: &[u8],
        dek_iv: &[u8],
        encrypted_dek: &[u8],
        encrypted_metadata: &[u8],
        encrypted_size: usize,
    ) -> rusqlite::Result<i64> {
        self.conn.execute(
            "INSERT INTO secure_vault (blind_index, iv, dek_iv, encrypted_dek, encrypted_metadata, hmac_tag, encrypted_content)
             VALUES (?1, ?2, ?3, ?4, ?5, zeroblob(32), zeroblob(?6))",
            params![
                blind_index,
                iv,
                dek_iv,
                encrypted_dek,
                encrypted_metadata,
                encrypted_size as i64,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// 更新 HMAC 标签（流式写入密文后设置）
    pub fn update_hmac_tag(&self, blind_index: &[u8], hmac_tag: &[u8]) -> rusqlite::Result<()> {
        self.conn.execute(
            "UPDATE secure_vault SET hmac_tag = ?1 WHERE blind_index = ?2",
            params![hmac_tag, blind_index],
        )?;
        Ok(())
    }

    /// 更新指定盲索引的 DEK 加密信息（密码修改时使用）
    pub fn update_dek(
        &self,
        blind_index: &[u8],
        dek_iv: &[u8],
        encrypted_dek: &[u8],
    ) -> rusqlite::Result<()> {
        self.conn.execute(
            "UPDATE secure_vault SET dek_iv = ?1, encrypted_dek = ?2 WHERE blind_index = ?3",
            params![dek_iv, encrypted_dek, blind_index],
        )?;
        Ok(())
    }

    /// 按盲索引删除文件记录
    pub fn delete(&self, blind_index: &[u8]) -> rusqlite::Result<bool> {
        let affected = self.conn.execute(
            "DELETE FROM secure_vault WHERE blind_index = ?1",
            params![blind_index],
        )?;
        Ok(affected > 0)
    }

    /// 获取文件总数
    pub fn count(&self) -> rusqlite::Result<u64> {
        self.conn
            .query_row("SELECT COUNT(*) FROM secure_vault", [], |row| row.get(0))
    }

    // ============================================================
    // 增量 BLOB I/O（文件内容读写，不占用 Rust 堆内存）
    // ============================================================

    /// 获取文件记录的 rowid（用于 `open_content_blob`）
    pub fn get_rowid_by_blind_index(&self, blind_index: &[u8]) -> rusqlite::Result<Option<i64>> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT rowid FROM secure_vault WHERE blind_index = ?1")?;
        let mut rows = stmt.query(params![blind_index])?;
        match rows.next()? {
            Some(row) => Ok(Some(row.get(0)?)),
            None => Ok(None),
        }
    }

    /// 打开 `encrypted_content` 列的增量 BLOB 句柄
    ///
    /// `writeable = true` 时以读写模式打开（用于导入），
    /// `writeable = false` 时以只读模式打开（用于导出）。
    pub fn open_content_blob(
        &self,
        rowid: i64,
        writeable: bool,
    ) -> rusqlite::Result<rusqlite::blob::Blob<'_>> {
        self.conn.blob_open(
            rusqlite::DatabaseName::Main,
            "secure_vault",
            "encrypted_content",
            rowid,
            !writeable,
        )
    }

    // -------- SAVEPOINT / checkpoint --------

    /// 创建 SAVEPOINT（支持嵌套）
    pub fn begin_savepoint(&self) -> rusqlite::Result<()> {
        self.conn.execute_batch("SAVEPOINT sp")
    }

    /// 释放最近的 SAVEPOINT
    pub fn release_savepoint(&self) -> rusqlite::Result<()> {
        self.conn.execute_batch("RELEASE sp")
    }

    /// 回滚到最近的 SAVEPOINT
    pub fn rollback_savepoint(&self) -> rusqlite::Result<()> {
        self.conn.execute_batch("ROLLBACK TO sp")
    }

    /// 强制 WAL checkpoint
    pub fn checkpoint(&self) -> rusqlite::Result<()> {
        self.conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
    }

    // -------- vault_config 操作 --------

    /// 写入 vault 配置项（无 HMAC，用于已加密的数据如 SM2 密钥）
    pub fn set_config(&self, key: &str, value: &[u8]) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO vault_config (key, value) VALUES (?1, ?2)",
            params![key, value],
        )?;
        Ok(())
    }

    /// 读取 vault 配置项
    pub fn get_config(&self, key: &str) -> rusqlite::Result<Option<Vec<u8>>> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT value FROM vault_config WHERE key = ?1")?;
        let mut rows = stmt.query(params![key])?;
        match rows.next()? {
            Some(row) => Ok(Some(row.get(0)?)),
            None => Ok(None),
        }
    }

    /// 写入配置项 + HMAC 完整性标签（防篡改）
    pub fn set_config_with_hmac(
        &self,
        key: &str,
        value: &[u8],
        hmac: &[u8],
    ) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO vault_config (key, value) VALUES (?1, ?2)",
            params![key, value],
        )?;
        self.conn.execute(
            "INSERT OR REPLACE INTO config_hmac (key, hmac) VALUES (?1, ?2)",
            params![key, hmac],
        )?;
        Ok(())
    }

    fn get_config_hmac_raw(&self, key: &str) -> rusqlite::Result<Option<Vec<u8>>> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT hmac FROM config_hmac WHERE key = ?1")?;
        let mut rows = stmt.query(params![key])?;
        match rows.next()? {
            Some(row) => {
                let val: Vec<u8> = row.get(0)?;
                Ok(Some(val))
            }
            None => Ok(None),
        }
    }

    pub fn get_config_with_hmac(&self, key: &str) -> rusqlite::Result<Option<(Vec<u8>, Vec<u8>)>> {
        let value = self.get_config(key)?;
        let hmac: Option<Vec<u8>> = self.get_config_hmac_raw(key)?;

        match (value, hmac) {
            (Some(v), Some(h)) => Ok(Some((v, h))),
            (Some(_v), None) => {
                eprintln!(
                    "警告: 配置项 '{}' 缺少 HMAC 完整性标签（数据可能损坏）",
                    key
                );
                Ok(None)
            }
            (None, _) => Ok(None),
        }
    }
}

// ============================================================
// 公用 PRAGMA 配置
// ============================================================

/// 对 SQLite 连接应用安全 PRAGMA 配置
pub fn apply_safe_pragmas(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch("PRAGMA journal_mode = WAL;")?;
    conn.execute_batch("PRAGMA synchronous = NORMAL;")?;
    conn.execute_batch("PRAGMA busy_timeout = 5000;")?;
    conn.execute_batch("PRAGMA temp_store = MEMORY;")?;
    conn.execute_batch("PRAGMA secure_delete = ON;")?;
    conn.execute_batch("PRAGMA mmap_size = 0;")?;
    conn.execute_batch("PRAGMA auto_vacuum = INCREMENTAL;")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_db(name: &str) -> (tempfile::TempDir, FileDb) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(format!("test_{}.db", name));
        let db = FileDb::open(&path).unwrap();
        (dir, db)
    }

    #[test]
    fn test_create_and_insert() {
        let (_dir, db) = test_db("create_insert");

        let record = FileRecord {
            blind_index: vec![0xAA; 32],
            iv: vec![0xBB; 16],
            dek_iv: vec![0xCC; 16],
            encrypted_dek: vec![0xDD; 48],
            encrypted_metadata: vec![0xEE; 64],
            hmac_tag: vec![0xFF; 32],
        };
        db.insert(&record).unwrap();
        assert_eq!(db.count().unwrap(), 1);
    }

    #[test]
    fn test_get_by_blind_index() {
        let (_dir, db) = test_db("get_by_index");

        let record = FileRecord {
            blind_index: vec![0x11; 32],
            iv: vec![0x22; 16],
            dek_iv: vec![0x33; 16],
            encrypted_dek: vec![0x44; 48],
            encrypted_metadata: vec![0x55; 64],
            hmac_tag: vec![0x66; 32],
        };
        db.insert(&record).unwrap();

        let found = db.get_by_blind_index(&[0x11; 32]).unwrap().unwrap();
        assert_eq!(found.iv, vec![0x22; 16]);

        let not_found = db.get_by_blind_index(&[0xFF; 32]).unwrap();
        assert!(not_found.is_none());
    }

    #[test]
    fn test_delete() {
        let (_dir, db) = test_db("delete");

        let record = FileRecord {
            blind_index: vec![0x77; 32],
            iv: vec![0x88; 16],
            dek_iv: vec![0x99; 16],
            encrypted_dek: vec![0xAA; 48],
            encrypted_metadata: vec![0xBB; 64],
            hmac_tag: vec![0xCC; 32],
        };
        db.insert(&record).unwrap();
        assert_eq!(db.count().unwrap(), 1);

        db.delete(&[0x77; 32]).unwrap();
        assert_eq!(db.count().unwrap(), 0);
    }

    #[test]
    fn test_zeroblob_insert_and_blob_io() {
        let (_dir, db) = test_db("blob_io");

        let rowid = db
            .insert_with_zeroblob(
                &[0x99; 32],
                &[0x88; 16],
                &[0x77; 16],
                &[0x66; 48],
                &[0x55; 64],
                256,
            )
            .unwrap();

        // 验证行 ID 有效
        assert!(rowid > 0);

        // 写入 BLOB
        let mut blob = db.open_content_blob(rowid, true).unwrap();
        let data = vec![0xABu8; 256];
        blob.write_at(&data, 0).unwrap();
        assert_eq!(blob.len(), 256);
        drop(blob);

        // 读取 BLOB 验证
        let blob = db.open_content_blob(rowid, false).unwrap();
        assert_eq!(blob.len(), 256);
        let mut buf = vec![0u8; 256];
        blob.read_at(&mut buf, 0).unwrap();
        assert_eq!(buf, vec![0xABu8; 256]);
        drop(blob);

        // 更新 HMAC 标签
        db.update_hmac_tag(&[0x99; 32], &[0xCD; 32]).unwrap();
        let rec = db.get_by_blind_index(&[0x99; 32]).unwrap().unwrap();
        assert_eq!(rec.hmac_tag, vec![0xCD; 32]);
    }
}
