//! Vault 文件导出（含目录导出、共享文件导出）

use std::io::Write;
use std::path::Path;

use zeroize::Zeroize;

use super::helpers::{bytes_to_array_12, bytes_to_array_32};
use super::{DEFAULT_FILE_NAME, Vault, VaultError};
use crate::audit_log::AuditEntryType;
use crate::crypto::secure_eq::constant_time_eq_32;
use crate::crypto::secure_erase::BLOCK_SIZE;
use crate::crypto::sm3::HmacSm3;
use crate::crypto::sm4_ctr::{Sm4Key, sm4_ctr_transform};
use crate::db::FileRecord;

impl Vault {
    // ============================================================
    // 文件导出（Verify-then-Decrypt）
    // ============================================================

    /// 从保险箱导出文件到指定目录（文件名从加密元数据中提取）
    pub fn export_file(&self, blind_index: &[u8; 32], output_dir: &Path) -> Result<(), VaultError> {
        let record = self
            .db
            .get_by_blind_index(blind_index)
            .map_err(VaultError::Db)?
            .ok_or_else(|| VaultError::NotFound("未找到文件记录".to_string()))?;
        let dek = self.decrypt_dek(&record)?;
        let metadata = self.decrypt_metadata(
            (&dek[..16]).try_into().expect("DEK 前半部分为 16 字节"),
            &record.encrypted_metadata,
        )?;
        let safe_name = Self::sanitize_vault_path(&metadata.filename);

        let output_path = output_dir.join(&safe_name);
        self.export_verified_file(
            &record,
            (&dek[..16]).try_into().expect("DEK 前半部分为 16 字节"),
            (&dek[16..]).try_into().expect("DEK 后半部分为 16 字节"),
            &output_path,
        )?;

        self.log_audit_event(
            AuditEntryType::FileExport,
            format!("文件: {}", safe_name).as_bytes(),
        );
        Ok(())
    }

    /// 从保险箱导出文件到指定路径（调用者指定完整输出路径）
    pub fn export_file_to(
        &self,
        blind_index: &[u8; 32],
        output_path: &Path,
    ) -> Result<(), VaultError> {
        // 需解密元数据获取文件名用于审计日志
        let record = self
            .db
            .get_by_blind_index(blind_index)
            .map_err(VaultError::Db)?
            .ok_or_else(|| VaultError::NotFound("未找到文件记录".to_string()))?;
        let dek = self.decrypt_dek(&record)?;
        let metadata = self.decrypt_metadata(
            (&dek[..16]).try_into().expect("DEK 前半部分为 16 字节"),
            &record.encrypted_metadata,
        )?;
        let safe_name = Self::sanitize_vault_path(&metadata.filename);

        self.export_verified_file(
            &record,
            (&dek[..16]).try_into().expect("DEK 前半部分为 16 字节"),
            (&dek[16..]).try_into().expect("DEK 后半部分为 16 字节"),
            output_path,
        )?;
        self.log_audit_event(
            AuditEntryType::FileExport,
            format!("文件: {}", safe_name).as_bytes(),
        );
        Ok(())
    }

    /// 导出整个目录（含子目录），保持文件结构
    pub fn export_directory_to(
        &self,
        vault_dir: &str,
        output_dir: &Path,
    ) -> Result<u32, VaultError> {
        let records = self.db.list_all_with_details().map_err(VaultError::Db)?;
        let prefix = if vault_dir.is_empty() {
            String::new()
        } else {
            format!("{}/", vault_dir)
        };
        let mut count = 0u32;

        for record in &records {
            let dek = self.decrypt_dek(record)?;
            let metadata = self.decrypt_metadata(
                (&dek[..16])
                    .try_into()
                    .map_err(|_| VaultError::Crypto("DEK 长度异常".to_string()))?,
                &record.encrypted_metadata,
            )?;

            let path = &metadata.filename;
            if !vault_dir.is_empty() && !path.starts_with(&prefix) && *path != *vault_dir {
                continue;
            }

            let relative = if vault_dir.is_empty() {
                Self::sanitize_vault_path(path)
            } else if *path == *vault_dir {
                path.rsplit('/')
                    .next()
                    .map(Self::sanitize_vault_path)
                    .unwrap_or_else(|| Self::sanitize_vault_path(path))
            } else {
                Self::sanitize_vault_path(&path[prefix.len()..])
            };

            if relative.is_empty() || relative == DEFAULT_FILE_NAME {
                continue;
            }

            let output_path = output_dir.join(&relative);
            self.export_verified_file(
                record,
                (&dek[..16]).try_into().expect("DEK 前半部分为 16 字节"),
                (&dek[16..]).try_into().expect("DEK 后半部分为 16 字节"),
                &output_path,
            )?;
            // 逐文件记录审计日志（含完整保险箱路径）
            self.log_audit_event(
                AuditEntryType::FileExport,
                format!("文件: {}", path).as_bytes(),
            );
            count += 1;
        }

        if count == 0 {
            return Err(VaultError::NotFound(
                "目录中没有找到可导出的文件".to_string(),
            ));
        }

        {
            let label = if vault_dir.is_empty() {
                "根目录"
            } else {
                vault_dir
            };
            self.log_audit_event(
                AuditEntryType::FileExport,
                format!("文件夹导出: {} ({} 个文件)", label, count).as_bytes(),
            );
        }

        Ok(count)
    }

    /// 内部导出：使用已解密的 DEK 直接从 BLOB 进行 Verify-then-Decrypt
    ///
    /// 供 `export_file`、`export_file_to` 和 `export_directory_to` 在已有解密结果时
    /// 调用，跳过重复查询和 DEK 解密步骤。
    fn export_verified_file(
        &self,
        record: &FileRecord,
        dek_enc: &[u8; 16],
        dek_mac: &[u8; 16],
        output_path: &Path,
    ) -> Result<(), VaultError> {
        let nonce = bytes_to_array_12(&record.iv)?;
        let stored_tag = bytes_to_array_32(&record.hmac_tag)?;
        let sm4_key = Sm4Key::new(dek_enc);

        let rowid = self
            .db
            .get_rowid_by_blind_index(&record.blind_index)
            .map_err(VaultError::Db)?
            .ok_or_else(|| VaultError::NotFound("获取文件 rowid 失败".to_string()))?;
        let blob = self
            .db
            .open_content_blob(rowid, false)
            .map_err(VaultError::Db)?;
        let encrypted_len = blob.len();

        // 第一遍：增量 HMAC 验证
        {
            let mut hm = HmacSm3::new(dek_mac);
            hm.update(&nonce);
            hm.update(&record.encrypted_metadata);
            let mut buf = vec![0u8; BLOCK_SIZE];
            let mut offset = 0usize;
            while offset < encrypted_len {
                let n = std::cmp::min(BLOCK_SIZE, encrypted_len - offset);
                blob.read_at(&mut buf[..n], offset)
                    .map_err(VaultError::Db)?;
                hm.update(&buf[..n]);
                offset += n;
            }
            let computed_tag = hm.finalize();
            if !constant_time_eq_32(&computed_tag, &stored_tag) {
                return Err(VaultError::Integrity(
                    "HMAC 标签验证失败，文件可能被篡改".to_string(),
                ));
            }
        }

        // 第二遍：增量解密写入
        if let Some(parent) = output_path.parent() {
            std::fs::create_dir_all(parent).map_err(VaultError::Io)?;
        }
        let mut output_file = std::fs::File::create(output_path).map_err(VaultError::Io)?;
        let mut buf = vec![0u8; BLOCK_SIZE];
        let mut block_offset = 0u32;
        let mut offset = 0usize;
        while offset < encrypted_len {
            let n = std::cmp::min(BLOCK_SIZE, encrypted_len - offset);
            blob.read_at(&mut buf[..n], offset)
                .map_err(VaultError::Db)?;
            sm4_ctr_transform(&sm4_key, &nonce, block_offset, &mut buf[..n]);
            output_file.write_all(&buf[..n]).map_err(VaultError::Io)?;
            let blocks = ((n as u32) + 15) >> 4;
            block_offset = block_offset.checked_add(blocks).ok_or_else(|| {
                VaultError::Crypto("文件过大，CTR 计数器溢出（上限约 64 GiB）".to_string())
            })?;
            offset += n;
        }
        drop(output_file);
        buf.zeroize();

        Ok(())
    }

    // ============================================================
    // 共享文件导出（SM2）
    // ============================================================

    /// 共享导出文件：用目标方 SM2 公钥加密文件的 DEK，打包导出
    pub fn share_export_file(
        &self,
        blind_index: &[u8; 32],
        target_pub_key: &[u8; 65],
    ) -> Result<Vec<u8>, VaultError> {
        use crate::crypto::sm2::encrypt;

        let record = self
            .db
            .get_by_blind_index(blind_index)
            .map_err(VaultError::Db)?
            .ok_or_else(|| VaultError::NotFound("未找到文件记录".to_string()))?;

        let dek = self.decrypt_dek(&record)?;
        let sm2_enc_dek = encrypt(target_pub_key, &*dek);

        // 从 BLOB 流式读取密文（共享包需要全部密文，走 BLOB I/O 避免冗余 Vec）
        let rowid = self
            .db
            .get_rowid_by_blind_index(blind_index)
            .map_err(VaultError::Db)?
            .ok_or_else(|| VaultError::NotFound("获取文件 rowid 失败".to_string()))?;
        let blob = self
            .db
            .open_content_blob(rowid, false)
            .map_err(VaultError::Db)?;
        let encrypted_len = blob.len();

        let header_size = 4 + sm2_enc_dek.len() + 4 + record.encrypted_metadata.len() + 12 + 32;
        let mut pkg = Vec::with_capacity(header_size + encrypted_len);

        pkg.extend_from_slice(&(sm2_enc_dek.len() as u32).to_le_bytes());
        pkg.extend_from_slice(&sm2_enc_dek);
        pkg.extend_from_slice(&(record.encrypted_metadata.len() as u32).to_le_bytes());
        pkg.extend_from_slice(&record.encrypted_metadata);
        pkg.extend_from_slice(&record.iv);
        pkg.extend_from_slice(&record.hmac_tag);

        let bs = BLOCK_SIZE;
        let mut buf = vec![0u8; bs];
        let mut offset = 0usize;
        while offset < encrypted_len {
            let n = std::cmp::min(bs, encrypted_len - offset);
            blob.read_at(&mut buf[..n], offset)
                .map_err(VaultError::Db)?;
            pkg.extend_from_slice(&buf[..n]);
            offset += n;
        }

        let bi_prefix: String = blind_index[..8]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        self.log_audit_event(
            AuditEntryType::FileExport,
            format!("共享导出: {}...", bi_prefix).as_bytes(),
        );
        Ok(pkg)
    }
}
