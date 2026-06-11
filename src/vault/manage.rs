//! Vault 管理操作：密码修改、备份/恢复、批量事务、导入删除

use std::path::Path;

use zeroize::Zeroizing;

use super::helpers::{derive_kek, random_bytes_12, random_bytes_16};
use super::{CONFIG_KEY_VERIFY, KDF_ITERATIONS, PWD_VERIFY_CONTEXT, Vault, VaultError};
use crate::crypto::sm4_ctr::Sm4Key;
use crate::audit_log::AuditEntryType;
use crate::crypto::secure_eq::constant_time_eq_32;
use crate::crypto::sm3::{hmac_sm3, hmac_sm3_concat};
use crate::crypto::sm4_ctr::sm4_ctr_crypt;

impl Vault {
    // ============================================================
    // 修改密码
    // ============================================================

    /// 修改保险箱密码
    pub fn change_password(&mut self, new_password: &str) -> Result<(), VaultError> {
        if new_password.is_empty() {
            return Err(VaultError::InvalidInput("新密码不能为空".to_string()));
        }

        // 验证当前密码
        let computed_verify = hmac_sm3(&*self.kek, PWD_VERIFY_CONTEXT);
        let stored_verify = self
            .db
            .get_config(CONFIG_KEY_VERIFY)
            .map_err(VaultError::Db)?
            .ok_or_else(|| VaultError::Corrupt("缺少密码验证标记".to_string()))?;

        if !constant_time_eq_32(
            &computed_verify,
            &crate::vault::helpers::bytes_to_array_32(&stored_verify)?,
        ) {
            return Err(VaultError::Crypto("当前密码错误".to_string()));
        }

        // 生成新盐值和新 KEK
        let new_salt = random_bytes_16();
        let new_kek = derive_kek(new_password.as_bytes(), &new_salt, KDF_ITERATIONS);
        // 遍历重加密 DEK + 更新 verify_tag
        self.with_transaction(|s| {
            let records = s.db.list_all_with_details().map_err(VaultError::Db)?;
            for record in &records {
                let dek = s.decrypt_dek(record)?;
                let new_dek_nonce = random_bytes_12();
                let new_encrypted_dek = sm4_ctr_crypt(&*new_kek, &new_dek_nonce, &*dek);

                s.db.update_dek(&record.blind_index, &new_dek_nonce, &new_encrypted_dek)
                    .map_err(VaultError::Db)?;
            }

            let new_verify = hmac_sm3(&*new_kek, PWD_VERIFY_CONTEXT);
            let new_verify_hmac =
                hmac_sm3_concat(&*new_kek, &[CONFIG_KEY_VERIFY.as_bytes(), &new_verify]);
            s.db.set_config_with_hmac(CONFIG_KEY_VERIFY, &new_verify, &new_verify_hmac)
                .map_err(VaultError::Db)?;
            Ok(())
        })?;

        // 先用新 KEK 写入 vault.db（如果失败，self.kek 未更新，vault 仍可用旧 KEK 操作）
        let new_verify = hmac_sm3(&*new_kek, PWD_VERIFY_CONTEXT);
        self.save_database_with(&Sm4Key::new(&new_kek), &new_salt, &new_verify)?;

        // 磁盘写入成功后再更新内存
        self.kek = new_kek;
        self.kek_sm4 = Sm4Key::new(&self.kek);
        self.vault_salt = Zeroizing::new(new_salt);

        self.log_audit_event(AuditEntryType::PasswordChange, b"");

        Ok(())
    }

    // ============================================================
    // 备份与恢复
    // ============================================================

    /// 备份保险箱到指定路径（仅需复制加密的 vault.db，文件内容已在内）
    pub fn backup_to(&self, backup_dir: &Path) -> Result<(), VaultError> {
        self.save_database()?;
        let vault_dir = &self.vault_dir;

        std::fs::create_dir_all(backup_dir).map_err(VaultError::Io)?;

        let db_path = vault_dir.join("vault.db");
        let target_db = backup_dir.join("vault.db");
        std::fs::copy(&db_path, &target_db).map_err(VaultError::Io)?;

        {
            let path_bytes = backup_dir.to_string_lossy();
            self.log_audit_event(AuditEntryType::VaultBackup, path_bytes.as_bytes());
        }

        Ok(())
    }

    /// 从备份恢复保险箱（仅需恢复 vault.db，文件内容已在内）
    pub fn restore_from(backup_dir: &Path, target_vault_dir: &Path) -> Result<(), VaultError> {
        if !backup_dir.join("vault.db").exists() {
            return Err(VaultError::InvalidInput(
                "备份目录中未找到 vault.db".to_string(),
            ));
        }

        std::fs::create_dir_all(target_vault_dir).map_err(VaultError::Io)?;

        std::fs::copy(
            backup_dir.join("vault.db"),
            target_vault_dir.join("vault.db"),
        )
        .map_err(VaultError::Io)?;

        Ok(())
    }

    // ============================================================
    // 导入并删除源文件
    // ============================================================

    /// 导入文件并从磁盘删除源文件
    pub fn import_file_and_remove(&self, source_path: &Path) -> Result<(), VaultError> {
        self.import_file(source_path)?;
        if let Err(e) = std::fs::remove_file(source_path) {
            eprintln!("警告: 无法删除源文件 {}: {}", source_path.display(), e);
        }
        Ok(())
    }

    /// 导入整个文件夹并从磁盘删除源文件
    pub fn import_folder_and_remove(&self, folder_path: &Path) -> Result<u32, VaultError> {
        let count = self.import_folder(folder_path)?;
        if let Err(e) = super::helpers::remove_imported_sources(folder_path) {
            eprintln!("警告: 删除部分源文件失败: {}", e);
        }
        Ok(count)
    }

    // ============================================================
    // 辅助方法
    // ============================================================

    /// 获取文件总数
    pub fn file_count(&self) -> Result<u64, VaultError> {
        self.db.count().map_err(VaultError::Db)
    }

    /// 在 SAVEPOINT 中执行闭包（支持嵌套事务）
    ///
    /// 使用 SQLite SAVEPOINT 实现可嵌套事务。闭包返回 Ok 时 RELEASE（提交），
    /// 返回 Err 时 ROLLBACK TO（回滚）。SAVEPOINT 的嵌套特性确保：
    /// - 独立调用时行为等效于 BEGIN/COMMIT
    /// - 嵌套调用时内层 RELEASE 不影响外层，内层 ROLLBACK 只撤销内层操作
    pub(crate) fn with_transaction<F>(&self, f: F) -> Result<(), VaultError>
    where
        F: FnOnce(&Self) -> Result<(), VaultError>,
    {
        self.db.begin_savepoint().map_err(VaultError::Db)?;
        match f(self) {
            Ok(()) => self.db.release_savepoint().map_err(VaultError::Db),
            Err(e) => {
                let _ = self.db.rollback_savepoint();
                Err(e)
            }
        }
    }

    /// 获取审计日志条目总数
    pub fn audit_log_count(&self) -> Result<u64, VaultError> {
        self.audit_log
            .as_ref()
            .ok_or_else(|| VaultError::AuditLog("审计日志未初始化".to_string()))?
            .count()
            .map_err(|e| VaultError::AuditLog(e.to_string()))
    }
}
