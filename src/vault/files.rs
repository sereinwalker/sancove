//! Vault 文件管理：列表、删除、重命名

use zeroize::Zeroizing;

use super::helpers::{bytes_to_array_32, random_bytes_12};
use super::{DEFAULT_FILE_NAME, DEK_SIZE, FileInfo, Vault, VaultError};
use crate::audit_log::AuditEntryType;
use crate::crypto::secure_erase::BLOCK_SIZE;
use crate::crypto::sm3::{HmacSm3, hmac_sm3, hmac_sm3_concat};
use crate::crypto::sm4_ctr::sm4_ctr_crypt;

impl Vault {
    // ============================================================
    // 文件列表
    // ============================================================

    /// 列出保险箱中所有文件
    pub fn list_files(&self) -> Result<Vec<FileInfo>, VaultError> {
        let records = self.db.list_all_with_details().map_err(VaultError::Db)?;

        let mut files = Vec::new();
        let mut decrypt_errors = 0u32;
        for record in &records {
            let blind_index = bytes_to_array_32(&record.blind_index)?;

            let dek = match self.decrypt_dek(record) {
                Ok(d) => d,
                Err(_) => {
                    decrypt_errors += 1;
                    continue;
                }
            };

            let (dek_enc, _dek_mac) = dek.split_at(16);
            let dek_enc_arr: &[u8; 16] = dek_enc
                .try_into()
                .expect("dek.split_at(16) 保证上半部分为 16 字节");
            let metadata = match self.decrypt_metadata(dek_enc_arr, &record.encrypted_metadata) {
                Ok(m) => m,
                Err(_) => {
                    decrypt_errors += 1;
                    continue;
                }
            };

            files.push(FileInfo {
                blind_index,
                filename: metadata.filename,
                original_size: metadata.original_size,
                created_at: metadata.created_at,
            });
        }

        if decrypt_errors > 0 {
            eprintln!(
                "警告: 列表加载完毕，{} 个文件因解密失败被跳过",
                decrypt_errors
            );
        }

        Ok(files)
    }

    // ============================================================
    // 文件移除
    // ============================================================

    /// 移除文件记录（不写审计日志，用于批量/目录删除的内部调用）
    fn remove_file_record(&self, blind_index: &[u8; 32]) -> Result<(), VaultError> {
        if !self.db.delete(blind_index).map_err(VaultError::Db)? {
            return Err(VaultError::NotFound("未找到文件记录".to_string()));
        }
        Ok(())
    }

    /// 按盲索引从保险箱移除文件
    ///
    /// # 事务保证
    ///
    /// DB 删除操作在事务中执行，确保密文文件擦除后 DB 记录的原子性：
    /// 1. 先擦除密文文件（不可逆操作）
    /// 2. 再在事务中删除 DB 记录（失败则回滚，保留记录但密文已不可恢复）
    /// 3. 事务提交后追加审计日志（独立连接，失败不影响数据一致性）
    pub fn remove_file(&self, blind_index: &[u8; 32]) -> Result<(), VaultError> {
        let record = self
            .db
            .get_by_blind_index(blind_index)
            .map_err(VaultError::Db)?
            .ok_or_else(|| VaultError::NotFound("未找到文件记录".to_string()))?;

        // 尝试解密获取文件名（用于审计日志 payload），失败则静默忽略
        let filename = (|| -> Option<String> {
            let dek = self.decrypt_dek(&record).ok()?;
            let meta = self
                .decrypt_metadata(dek[..16].try_into().ok()?, &record.encrypted_metadata)
                .ok()?;
            Some(meta.filename)
        })();

        // 事务：擦除密文 + 原子删除 DB 记录
        self.with_transaction(|s| s.remove_file_record(blind_index))?;

        // 追加审计日志（独立连接，失败不影响数据一致性）
        if let Some(ref name) = filename {
            self.log_audit_event(
                AuditEntryType::FileDelete,
                format!("文件: {}", name).as_bytes(),
            );
        }

        Ok(())
    }

    /// 删除整个目录（含子目录）下的所有文件
    pub fn remove_directory(&self, vault_dir: &str) -> Result<u32, VaultError> {
        let records = self.db.list_all_with_details().map_err(VaultError::Db)?;
        let prefix = format!("{}/", vault_dir);

        struct FileEntry {
            blind_index: [u8; 32],
            filename: String,
        }

        let to_remove: Vec<FileEntry> = records
            .iter()
            .filter_map(|record| {
                let dek = self.decrypt_dek(record).ok()?;
                let metadata = self
                    .decrypt_metadata((&dek[..16]).try_into().ok()?, &record.encrypted_metadata)
                    .ok()?;
                if metadata.filename.starts_with(&prefix) || metadata.filename == *vault_dir {
                    Some(FileEntry {
                        blind_index: bytes_to_array_32(&record.blind_index).ok()?,
                        filename: metadata.filename,
                    })
                } else {
                    None
                }
            })
            .collect();

        if to_remove.is_empty() {
            return Err(VaultError::NotFound("目录中没有找到文件".to_string()));
        }

        // 先事务删除（确保原子性）
        self.with_transaction(|s| {
            for entry in &to_remove {
                s.remove_file_record(&entry.blind_index)?;
            }
            Ok(())
        })?;

        // 删除成功后逐文件记录审计日志（事务外，日志独立连接）
        for entry in &to_remove {
            self.log_audit_event(
                AuditEntryType::FileDelete,
                format!("文件: {}", entry.filename).as_bytes(),
            );
        }
        self.log_audit_event(
            AuditEntryType::FileDelete,
            format!("文件夹删除: {} ({} 个文件)", vault_dir, to_remove.len()).as_bytes(),
        );

        Ok(to_remove.len() as u32)
    }

    // ============================================================
    // 文件重命名
    // ============================================================

    /// 重命名保险箱中的文件
    pub fn rename_file(&self, blind_index: &[u8; 32], new_name: &str) -> Result<(), VaultError> {
        let sanitized = Self::sanitize_filename(new_name);
        if sanitized.is_empty() || (sanitized == DEFAULT_FILE_NAME && new_name.trim().is_empty()) {
            return Err(VaultError::InvalidInput("文件名不能为空".to_string()));
        }

        let record = self
            .db
            .get_by_blind_index(blind_index)
            .map_err(VaultError::Db)?
            .ok_or_else(|| VaultError::NotFound("未找到文件记录".to_string()))?;

        let dek = self.decrypt_dek(&record)?;
        let (dek_enc, dek_mac) = dek.split_at(16);

        let dek_enc_arr: &[u8; 16] = dek_enc
            .try_into()
            .expect("dek.split_at(16) 保证上半部分为 16 字节");
        let mut metadata = self.decrypt_metadata(dek_enc_arr, &record.encrypted_metadata)?;
        let old_name = metadata.filename.clone();
        metadata.filename = sanitized.clone();

        // 重新加密元数据
        let metadata_bytes = bincode::serialize(&metadata).map_err(VaultError::Serialize)?;
        let new_meta_nonce = random_bytes_12();
        let encrypted_meta = sm4_ctr_crypt(dek_enc_arr, &new_meta_nonce, &metadata_bytes);
        let mut new_meta_with_nonce = Vec::with_capacity(12 + encrypted_meta.len());
        new_meta_with_nonce.extend_from_slice(&new_meta_nonce);
        new_meta_with_nonce.extend_from_slice(&encrypted_meta);

        // 新盲索引
        let blind_key = hmac_sm3(dek_mac, super::BLIND_INDEX_CONTEXT);
        let new_blind_index =
            hmac_sm3_concat(&blind_key, &[&*self.vault_salt, sanitized.as_bytes()]);

        // 重新计算 HMAC 标签（块内分配缓冲区，块外复用）
        let rowid = self
            .db
            .get_rowid_by_blind_index(blind_index)
            .map_err(VaultError::Db)?
            .ok_or_else(|| VaultError::NotFound("获取文件 rowid 失败".to_string()))?;

        let (encrypted_len, new_hmac_tag) = {
            let blob = self
                .db
                .open_content_blob(rowid, false)
                .map_err(VaultError::Db)?;
            let len = blob.len();
            let bs = BLOCK_SIZE;
            let mut hm = HmacSm3::new(dek_mac);
            hm.update(&record.iv);
            hm.update(&new_meta_with_nonce);
            let mut buf = vec![0u8; bs];
            let mut offset = 0usize;
            while offset < len {
                let n = std::cmp::min(bs, len - offset);
                blob.read_at(&mut buf[..n], offset)
                    .map_err(VaultError::Db)?;
                hm.update(&buf[..n]);
                offset += n;
            }
            drop(blob);
            (len, hm.finalize())
        };

        // 事务：插入新记录（带 zeroblob 占位）→ 复制密文 → 更新 HMAC → 删除旧记录
        self.db.begin_savepoint().map_err(VaultError::Db)?;
        let result = (|| -> Result<(), VaultError> {
            let new_rowid = self
                .db
                .insert_with_zeroblob(
                    &new_blind_index,
                    &record.iv,
                    &record.dek_iv,
                    &record.encrypted_dek,
                    &new_meta_with_nonce,
                    encrypted_len,
                )
                .map_err(VaultError::Db)?;

            // 复制密文 BLOB（同一数据库内，跨行拷贝）
            let src_blob = self
                .db
                .open_content_blob(rowid, false)
                .map_err(VaultError::Db)?;
            let mut dst_blob = self
                .db
                .open_content_blob(new_rowid, true)
                .map_err(VaultError::Db)?;
            let bs = BLOCK_SIZE;
            let mut buf = vec![0u8; bs];
            let mut off = 0usize;
            while off < encrypted_len {
                let n = std::cmp::min(bs, encrypted_len - off);
                src_blob
                    .read_at(&mut buf[..n], off)
                    .map_err(VaultError::Db)?;
                dst_blob.write_at(&buf[..n], off).map_err(VaultError::Db)?;
                off += n;
            }
            drop(src_blob);
            drop(dst_blob);

            self.db
                .update_hmac_tag(&new_blind_index, &new_hmac_tag)
                .map_err(VaultError::Db)?;

            if !self.db.delete(blind_index).map_err(VaultError::Db)? {
                return Err(VaultError::NotFound("删除旧记录失败".to_string()));
            }
            Ok(())
        })();
        match result {
            Ok(()) => self.db.release_savepoint().map_err(VaultError::Db)?,
            Err(e) => {
                let _ = self.db.rollback_savepoint();
                return Err(e);
            }
        }

        {
            let msg = format!("{} → {}", old_name, sanitized);
            self.log_audit_event(AuditEntryType::FileRename, msg.as_bytes());
        }

        Ok(())
    }

    /// 重命名目录（含子目录），批量更新路径前缀
    pub fn rename_directory(&self, old_dir: &str, new_dir: &str) -> Result<u32, VaultError> {
        let sanitized_new = Self::sanitize_vault_path(new_dir);
        if sanitized_new.is_empty() || sanitized_new == DEFAULT_FILE_NAME {
            return Err(VaultError::InvalidInput("新目录名无效".to_string()));
        }

        let records = self.db.list_all_with_details().map_err(VaultError::Db)?;
        let prefix = format!("{}/", old_dir);

        let to_rename: Vec<(usize, String, Zeroizing<[u8; DEK_SIZE]>)> = records
            .iter()
            .enumerate()
            .filter_map(|(i, r)| {
                let dek = self.decrypt_dek(r).ok()?;
                let meta = self
                    .decrypt_metadata((&dek[..16]).try_into().ok()?, &r.encrypted_metadata)
                    .ok()?;
                if meta.filename == *old_dir {
                    Some((i, sanitized_new.clone(), dek))
                } else if meta.filename.starts_with(&prefix) {
                    let suffix = &meta.filename[prefix.len()..];
                    Some((i, format!("{}/{}", sanitized_new, suffix), dek))
                } else {
                    None
                }
            })
            .collect();

        if to_rename.is_empty() {
            return Err(VaultError::NotFound("目录中没有找到文件".to_string()));
        }

        self.with_transaction(|s| {
            for (idx, new_path, dek) in &to_rename {
                let record = &records[*idx];
                // 使用外层已解密的 DEK，避免重复解密
                let mut metadata = s.decrypt_metadata(
                    (&dek[..16])
                        .try_into()
                        .map_err(|_| VaultError::Crypto("DEK 长度异常".to_string()))?,
                    &record.encrypted_metadata,
                )?;
                metadata.filename = new_path.clone();

                let meta_bytes = bincode::serialize(&metadata).map_err(VaultError::Serialize)?;
                let new_meta_nonce = random_bytes_12();
                let enc_meta = sm4_ctr_crypt(
                    (&dek[..16]).try_into().map_err(|_| VaultError::Crypto("DEK 长度无效".to_string()))?,
                    &new_meta_nonce,
                    &meta_bytes,
                );
                let mut new_meta_with_nonce = Vec::with_capacity(12 + enc_meta.len());
                new_meta_with_nonce.extend_from_slice(&new_meta_nonce);
                new_meta_with_nonce.extend_from_slice(&enc_meta);

                let (_dek_enc, dek_mac) = dek.split_at(16);
                let blind_key = hmac_sm3(dek_mac, super::BLIND_INDEX_CONTEXT);
                let new_bi = hmac_sm3_concat(&blind_key, &[&*s.vault_salt, new_path.as_bytes()]);

                // 从 BLOB 增量读取密文用于 HMAC 重算（块内分配缓冲区，块外复用）
                let old_bi = bytes_to_array_32(&record.blind_index)?;
                let (old_rowid, encrypted_len, new_hmac) = {
                    let rowid =
                        s.db.get_rowid_by_blind_index(&old_bi)
                            .map_err(VaultError::Db)?
                            .ok_or_else(|| VaultError::NotFound("获取文件 rowid 失败".to_string()))?;
                    let blb =
                        s.db.open_content_blob(rowid, false)
                            .map_err(VaultError::Db)?;
                    let len = blb.len();
                    let bs = BLOCK_SIZE;
                    let mut hm = HmacSm3::new(dek_mac);
                    hm.update(&record.iv);
                    hm.update(&new_meta_with_nonce);
                    let mut buf = vec![0u8; bs];
                    let mut off = 0usize;
                    while off < len {
                        let n = std::cmp::min(bs, len - off);
                        blb.read_at(&mut buf[..n], off).map_err(VaultError::Db)?;
                        hm.update(&buf[..n]);
                        off += n;
                    }
                    drop(blb);
                    (rowid, len, hm.finalize())
                };

                // 插入新记录（zeroblob）→ 复制密文 → 更新 HMAC → 删除旧记录
                let new_rowid =
                    s.db.insert_with_zeroblob(
                        &new_bi,
                        &record.iv,
                        &record.dek_iv,
                        &record.encrypted_dek,
                        &new_meta_with_nonce,
                        encrypted_len,
                    )
                    .map_err(VaultError::Db)?;

                let src =
                    s.db.open_content_blob(old_rowid, false)
                        .map_err(VaultError::Db)?;
                let mut dst =
                    s.db.open_content_blob(new_rowid, true)
                        .map_err(VaultError::Db)?;
                let bs = BLOCK_SIZE;
                let mut buf = vec![0u8; bs];
                let mut off2 = 0usize;
                while off2 < encrypted_len {
                    let n = std::cmp::min(bs, encrypted_len - off2);
                    src.read_at(&mut buf[..n], off2).map_err(VaultError::Db)?;
                    dst.write_at(&buf[..n], off2).map_err(VaultError::Db)?;
                    off2 += n;
                }
                drop(src);
                drop(dst);

                s.db.update_hmac_tag(&new_bi, &new_hmac)
                    .map_err(VaultError::Db)?;

                if !s.db.delete(&old_bi).map_err(VaultError::Db)? {
                    return Err(VaultError::NotFound("删除旧记录失败".to_string()));
                }
            }
            Ok(())
        })?;

        {
            let msg = format!(
                "目录重命名: {} → {} ({} 个文件)",
                old_dir,
                sanitized_new,
                to_rename.len()
            );
            self.log_audit_event(AuditEntryType::FileRename, msg.as_bytes());
        }

        Ok(to_rename.len() as u32)
    }
}
