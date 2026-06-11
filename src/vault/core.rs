//! Vault 核心操作：创建、打开、保存数据库

use std::path::Path;

use zeroize::Zeroizing;

use crate::db::FileDb;

use super::helpers::{
    bytes_to_array_32, derive_kek, generate_and_store_sm2_keys, init_audit_log, is_sqlite_file,
    load_sm2_keys, random_bytes_16,
};
use super::{
    CONFIG_KEY_SALT, CONFIG_KEY_VERIFY, DB_ENC_HEADER_SIZE, KDF_ITERATIONS, PWD_VERIFY_CONTEXT,
    Vault, VaultError,
};
use crate::audit_log::AuditEntryType;
use crate::crypto::secure_eq::constant_time_eq_32;
use crate::crypto::sm3::{hmac_sm3, hmac_sm3_concat};
use crate::crypto::sm4_ctr::{Sm4Key, sm4_cbc_decrypt_with_key, sm4_cbc_encrypt};

impl Vault {
    // ============================================================
    // 创建/打开
    // ============================================================

    /// 创建新的文件保险箱（加密数据库模式，文件内容加密存储在 DB 内部）
    pub fn create(vault_dir: &Path, password: &str) -> Result<Self, VaultError> {
        let db_path = vault_dir.join("vault.db");
        let temp_path = vault_dir.join("vault.db.tmp");

        if db_path.exists() {
            return Err(VaultError::InvalidInput(
                "vault.db 已存在，不能覆盖已有保险箱".to_string(),
            ));
        }
        let _ = std::fs::remove_file(&temp_path);
        let _ = std::fs::remove_file(vault_dir.join("vault.db.tmp-wal"));
        let _ = std::fs::remove_file(vault_dir.join("vault.db.tmp-shm"));

        std::fs::create_dir_all(vault_dir).map_err(VaultError::Io)?;

        let vault_salt = random_bytes_16();
        let db = FileDb::open(&temp_path).map_err(VaultError::Db)?;
        let kek = derive_kek(password.as_bytes(), &vault_salt, KDF_ITERATIONS);
        let kek_sm4 = Sm4Key::new(&kek);

        // 密码验证标签
        let verify_tag = hmac_sm3(&*kek, PWD_VERIFY_CONTEXT);
        let verify_hmac = hmac_sm3_concat(&*kek, &[CONFIG_KEY_VERIFY.as_bytes(), &verify_tag]);
        db.set_config_with_hmac(CONFIG_KEY_VERIFY, &verify_tag, &verify_hmac)
            .map_err(VaultError::Db)?;

        // 初始化审计日志
        let audit_log = match init_audit_log(&temp_path) {
            Ok(log) => {
                let _ = log.append(AuditEntryType::VaultCreate, &*kek, b"vault initialized");
                Some(log)
            }
            Err(e) => {
                eprintln!("审计日志初始化警告（非致命）: {}", e);
                None
            }
        };

        // 生成 SM2 密钥对
        let (sm2_pub_key, sm2_priv_key) = match generate_and_store_sm2_keys(&db, &*kek, &*kek) {
            Ok((pub_k, priv_k)) => (Some(pub_k), Some(priv_k)),
            Err(e) => {
                eprintln!("SM2 密钥生成警告（非致命）: {}", e);
                (None, None)
            }
        };

        // 加密临时数据库 → vault.db
        db.checkpoint().map_err(VaultError::Db)?;
        let plaintext = std::fs::read(&temp_path).map_err(VaultError::Io)?;
        let db_iv = random_bytes_16();
        let encrypted = sm4_cbc_encrypt(&kek_sm4, &db_iv, &plaintext);

        let mut output = Vec::with_capacity(DB_ENC_HEADER_SIZE + encrypted.len());
        output.extend_from_slice(&vault_salt);
        output.extend_from_slice(&verify_tag);
        output.extend_from_slice(&db_iv);
        output.extend_from_slice(&encrypted);
        std::fs::write(&db_path, &output).map_err(VaultError::Io)?;

        drop(audit_log);

        // 重新打开审计日志，使返回的 vault 实例立即可用
        let audit_log = init_audit_log(&temp_path).ok();

        Ok(Self {
            db,
            vault_dir: vault_dir.to_path_buf(),
            db_temp_path: temp_path,
            kek,
            kek_sm4,
            vault_salt: Zeroizing::new(vault_salt),
            audit_log,
            sm2_pub_key,
            sm2_priv_key,
        })
    }

    /// 打开已有文件保险箱
    pub fn open(vault_dir: &Path, password: &str) -> Result<Self, VaultError> {
        let db_path = vault_dir.join("vault.db");
        if !db_path.exists() {
            return Err(VaultError::NotFound(
                "保险箱数据库不存在，请先创建".to_string(),
            ));
        }

        let vault_salt = Self::read_vault_salt(vault_dir)?;
        let kek = derive_kek(password.as_bytes(), &vault_salt, KDF_ITERATIONS);
        Self::open_with_kek(vault_dir, &kek)
    }

    /// 用预派生的 KEK 打开保险箱（绕过 PBKDF2）
    pub fn open_with_kek(vault_dir: &Path, kek: &[u8; 16]) -> Result<Self, VaultError> {
        let db_path = vault_dir.join("vault.db");

        if !db_path.exists() {
            return Err(VaultError::NotFound("保险箱数据库不存在".to_string()));
        }

        let (db, temp_path, vault_salt) = if is_sqlite_file(&db_path) {
            // 传统明文数据库
            let db = FileDb::open(&db_path).map_err(VaultError::Db)?;

            let (salt_blob, salt_hmac_stored) = db
                .get_config_with_hmac(CONFIG_KEY_SALT)
                .map_err(VaultError::Db)?
                .ok_or_else(|| VaultError::Corrupt("缺少 vault_salt 配置".to_string()))?;

            if salt_blob.len() != 16 {
                return Err(VaultError::Corrupt("vault_salt 长度异常".to_string()));
            }
            let mut vault_salt = [0u8; 16];
            vault_salt.copy_from_slice(&salt_blob);

            let expected_salt_hmac =
                hmac_sm3_concat(kek, &[CONFIG_KEY_SALT.as_bytes(), &salt_blob]);
            if !constant_time_eq_32(&expected_salt_hmac, &bytes_to_array_32(&salt_hmac_stored)?) {
                return Err(VaultError::Corrupt("vault_salt 完整性校验失败".to_string()));
            }

            let (stored_verify, verify_hmac_stored) = db
                .get_config_with_hmac(CONFIG_KEY_VERIFY)
                .map_err(VaultError::Db)?
                .ok_or_else(|| VaultError::Corrupt("缺少密码验证标记".to_string()))?;

            let expected_verify_hmac =
                hmac_sm3_concat(kek, &[CONFIG_KEY_VERIFY.as_bytes(), &stored_verify]);
            if !constant_time_eq_32(
                &expected_verify_hmac,
                &bytes_to_array_32(&verify_hmac_stored)?,
            ) {
                return Err(VaultError::Corrupt(
                    "密码验证标记完整性校验失败".to_string(),
                ));
            }

            let computed_verify = hmac_sm3(kek, PWD_VERIFY_CONTEXT);
            if !constant_time_eq_32(&computed_verify, &bytes_to_array_32(&stored_verify)?) {
                return Err(VaultError::Crypto(
                    "KEK 验证失败（密码或密钥无效）".to_string(),
                ));
            }

            (db, db_path.clone(), vault_salt)
        } else {
            // 加密数据库格式
            let temp = vault_dir.join("vault.db.tmp");
            let _ = std::fs::remove_file(&temp);
            let _ = std::fs::remove_file(vault_dir.join("vault.db.tmp-wal"));
            let _ = std::fs::remove_file(vault_dir.join("vault.db.tmp-shm"));

            let kek_sm4 = Sm4Key::new(kek);

            let data = std::fs::read(&db_path).map_err(VaultError::Io)?;
            if data.len() < DB_ENC_HEADER_SIZE {
                return Err(VaultError::Corrupt(
                    "数据库文件损坏（加密头不完整）".to_string(),
                ));
            }
            let mut vault_salt = [0u8; 16];
            vault_salt.copy_from_slice(&data[..16]);
            let stored_verify = {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&data[16..48]);
                arr
            };
            let db_iv = {
                let mut arr = [0u8; 16];
                arr.copy_from_slice(&data[48..64]);
                arr
            };

            // 先验证 KEK
            let computed_verify = hmac_sm3(kek, PWD_VERIFY_CONTEXT);
            if !constant_time_eq_32(&computed_verify, &stored_verify) {
                return Err(VaultError::Crypto(
                    "KEK 验证失败（密码或密钥无效）".to_string(),
                ));
            }

            // 解密数据库体
            let encrypted_body = &data[64..];
            let plaintext = sm4_cbc_decrypt_with_key(&kek_sm4, &db_iv, encrypted_body)
                .map_err(|e| VaultError::Crypto(format!("数据库解密失败: {}", e)))?;

            std::fs::write(&temp, &plaintext).map_err(VaultError::Io)?;

            let db = FileDb::open(&temp).map_err(VaultError::Db)?;

            (db, temp, vault_salt)
        };

        let kek_sm4 = Sm4Key::new(kek);
        let kek_owned = Zeroizing::new(*kek);

        // 初始化审计日志
        let audit_log = init_audit_log(&temp_path).ok();

        // 加载 SM2 密钥对（带 HMAC 完整性验证）
        let (sm2_pub_key, sm2_priv_key) =
            load_sm2_keys(&db, kek, kek).ok().unwrap_or_else(|| {
                eprintln!("警告: SM2 密钥加载失败，SM2 功能不可用");
                (None, None)
            });

        // 记录打开事件
        if let Some(ref log) = audit_log {
            let _ = log.append(AuditEntryType::VaultOpen, &*kek_owned, b"");
        }

        Ok(Self {
            db,
            vault_dir: vault_dir.to_path_buf(),
            db_temp_path: temp_path,
            kek: kek_owned,
            kek_sm4,
            vault_salt: Zeroizing::new(vault_salt),
            audit_log,
            sm2_pub_key,
            sm2_priv_key,
        })
    }

    /// 读取 vault salt（支持加密格式和传统 SQLite 格式）
    fn read_vault_salt(vault_dir: &Path) -> Result<[u8; 16], VaultError> {
        let db_path = vault_dir.join("vault.db");
        if !db_path.exists() {
            return Err(VaultError::NotFound("保险箱数据库不存在".to_string()));
        }
        if is_sqlite_file(&db_path) {
            let db = FileDb::open(&db_path).map_err(VaultError::Db)?;
            let salt_blob = db
                .get_config(CONFIG_KEY_SALT)
                .map_err(VaultError::Db)?
                .ok_or_else(|| VaultError::Corrupt("缺少 vault_salt 配置".to_string()))?;
            if salt_blob.len() != 16 {
                return Err(VaultError::Corrupt("vault_salt 长度异常".to_string()));
            }
            let mut salt = [0u8; 16];
            salt.copy_from_slice(&salt_blob);
            Ok(salt)
        } else {
            use std::io::Read;
            let mut file = std::fs::File::open(&db_path).map_err(VaultError::Io)?;
            let mut header = vec![0u8; DB_ENC_HEADER_SIZE];
            file.read_exact(&mut header).map_err(|_| {
                VaultError::Corrupt("数据库文件损坏（加密头不完整）".to_string())
            })?;
            let mut salt = [0u8; 16];
            salt.copy_from_slice(&header[..16]);
            Ok(salt)
        }
    }

    // -------- 加密数据库持久化 --------

    /// 保存当前数据库状态到加密文件 `vault.db`
    ///
    /// # 崩溃安全保证
    ///
    /// 1. 在覆盖 `vault.db` 前先创建备份 `vault.db.bak`
    /// 2. 写入新加密数据到 `vault.db`（覆盖原文件）
    /// 3. 写入成功后删除备份文件
    /// 4. 若写入失败，从备份恢复
    pub fn save_database(&self) -> Result<(), VaultError> {
        let verify_tag = hmac_sm3(&*self.kek, PWD_VERIFY_CONTEXT);
        self.save_database_with(&self.kek_sm4, &self.vault_salt, &verify_tag)
    }

    /// 用指定 KEK/salt/verify_tag 加密并写入 vault.db（供 change_password 使用）
    ///
    /// 与 `save_database` 的区别在于使用传入的 KEK 参数而不是 self.kek_sm4，
    /// 确保密码修改时可以在更新 self.kek 之前先写盘。
    pub(super) fn save_database_with(
        &self,
        kek_sm4: &Sm4Key,
        vault_salt: &[u8; 16],
        verify_tag: &[u8; 32],
    ) -> Result<(), VaultError> {
        let db_path = self.vault_dir.join("vault.db");
        let backup_path = self.vault_dir.join("vault.db.bak");
        let temp_path = &self.db_temp_path;

        self.db.checkpoint().map_err(VaultError::Db)?;

        let plaintext = std::fs::read(temp_path).map_err(VaultError::Io)?;

        let db_iv = random_bytes_16();
        let encrypted = sm4_cbc_encrypt(kek_sm4, &db_iv, &plaintext);

        let mut output = Vec::with_capacity(DB_ENC_HEADER_SIZE + encrypted.len());
        output.extend_from_slice(vault_salt);
        output.extend_from_slice(verify_tag);
        output.extend_from_slice(&db_iv);
        output.extend_from_slice(&encrypted);

        // 崩溃安全：写前备份 → 原子替换 → 成功后删除备份
        if db_path.exists() {
            let _ = std::fs::copy(&db_path, &backup_path);
        }

        let write_result = std::fs::write(&db_path, &output);

        match write_result {
            Ok(()) => {
                // 写入成功，清理备份
                let _ = std::fs::remove_file(&backup_path);
                Ok(())
            }
            Err(e) => {
                // 写入失败，从备份恢复
                eprintln!("数据库写入失败，正在从备份恢复: {}", e);
                if backup_path.exists() {
                    let _ = std::fs::copy(&backup_path, &db_path);
                }
                let _ = std::fs::remove_file(&backup_path);
                Err(VaultError::Io(e))
            }
        }
    }
}
