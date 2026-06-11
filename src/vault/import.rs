//! Vault 文件导入（含文件夹导入、共享文件导入）

use std::io::Read;
use std::path::Path;

use rand::RngCore;
use rand::rngs::OsRng;
use zeroize::{Zeroize, Zeroizing};

use super::helpers::random_bytes_12;
use super::{DEFAULT_FILE_NAME, DEK_SIZE, FileMetadata, Vault, VaultError};
use crate::audit_log::AuditEntryType;
use crate::crypto::secure_erase::BLOCK_SIZE;
use crate::crypto::sm3::{HmacSm3, hmac_sm3, hmac_sm3_concat};
use crate::crypto::sm4_ctr::sm4_ctr_crypt;

impl Vault {
    /// 将文件导入保险箱
    pub fn import_file(&self, source_path: &Path) -> Result<(), VaultError> {
        let filename = source_path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| VaultError::InvalidInput("无法获取文件名".to_string()))?
            .to_string();
        self.import_file_as(source_path, &filename)
    }

    /// 导入文件到指定 vault 路径（由 caller 指定文件名/子目录）
    /// 与 `import_file` 的区别在于可以指定 vault 中的虚拟路径（含子目录）
    pub(crate) fn import_file_as(
        &self,
        source_path: &Path,
        vault_path: &str,
    ) -> Result<(), VaultError> {
        let file_size = source_path.metadata().map_err(VaultError::Io)?.len();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        // 1. 生成 DEK 和 IV
        let mut dek = Zeroizing::new([0u8; DEK_SIZE]);
        OsRng.fill_bytes(&mut *dek);
        let (dek_enc, dek_mac) = dek.split_at(16);

        let nonce = random_bytes_12();

        // 2. 加密元数据
        let metadata = FileMetadata {
            filename: vault_path.to_string(),
            original_size: file_size,
            created_at: timestamp,
        };
        let metadata_bytes = bincode::serialize(&metadata).map_err(VaultError::Serialize)?;
        let meta_nonce = random_bytes_12();

        let sm4_key = crate::crypto::sm4_ctr::Sm4Key::new(
            dek_enc
                .try_into()
                .expect("dek.split_at(16) 保证前半部分为 16 字节"),
        );

        let encrypted_metadata = sm4_ctr_crypt(
            dek_enc
                .try_into()
                .expect("dek.split_at(16) 保证前半部分为 16 字节"),
            &meta_nonce,
            &metadata_bytes,
        );

        let mut meta_with_iv = Vec::with_capacity(12 + encrypted_metadata.len());
        meta_with_iv.extend_from_slice(&meta_nonce);
        meta_with_iv.extend_from_slice(&encrypted_metadata);

        // 3. 盲索引 + DEK 重加密（均在加密前可计算）
        let blind_key = hmac_sm3(dek_mac, super::BLIND_INDEX_CONTEXT);
        let blind_index = hmac_sm3_concat(&blind_key, &[&*self.vault_salt, vault_path.as_bytes()]);
        let dek_nonce = random_bytes_12();
        let encrypted_dek = sm4_ctr_crypt(&*self.kek, &dek_nonce, &*dek);

        // 4. 插入 zeroblob 占位 + 增量 BLOB I/O 流式写入密文
        let encrypted_size = file_size as usize; // CTR 模式下密文长度 == 明文长度
        let rowid = self
            .db
            .insert_with_zeroblob(
                &blind_index,
                &nonce,
                &dek_nonce,
                &encrypted_dek,
                &meta_with_iv,
                encrypted_size,
            )
            .map_err(VaultError::Db)?;

        let mut blob = self
            .db
            .open_content_blob(rowid, true)
            .map_err(VaultError::Db)?;
        let mut source_file = std::fs::File::open(source_path).map_err(VaultError::Io)?;
        let mut hm = HmacSm3::new(dek_mac);
        hm.update(&nonce);
        hm.update(&meta_with_iv);
        let mut buf = vec![0u8; BLOCK_SIZE];
        let mut block_offset = 0u32;
        let mut write_offset = 0usize;

        loop {
            let n = source_file.read(&mut buf).map_err(VaultError::Io)?;
            if n == 0 {
                break;
            }
            let chunk = &mut buf[..n];
            crate::crypto::sm4_ctr::sm4_ctr_transform(&sm4_key, &nonce, block_offset, chunk);
            blob.write_at(chunk, write_offset).map_err(VaultError::Db)?;
            hm.update(chunk);
            write_offset += n;
            let blocks = ((n as u32) + 15) >> 4;
            block_offset = block_offset.checked_add(blocks).ok_or_else(|| {
                VaultError::Crypto("文件过大，CTR 计数器溢出（上限约 64 GiB）".to_string())
            })?;
        }
        drop(source_file);
        drop(blob);

        let hmac_tag = hm.finalize();
        self.db
            .update_hmac_tag(&blind_index, &hmac_tag)
            .map_err(VaultError::Db)?;

        // 等 SAVEPOINT 释放后再写审计日志（避免跨连接锁竞争）
        self.log_audit_event(AuditEntryType::FileImport, vault_path.as_bytes());

        buf.zeroize();
        Ok(())
    }

    /// 将整个文件夹导入保险箱（保留子目录结构）
    pub fn import_folder(&self, folder_path: &Path) -> Result<u32, VaultError> {
        let folder_canonical = folder_path.canonicalize().map_err(VaultError::Io)?;
        if !folder_canonical.is_dir() {
            return Err(VaultError::InvalidInput("路径不是目录".to_string()));
        }
        let count = std::cell::Cell::new(0u32);
        self.with_transaction(|s| {
            count.set(s.import_folder_recursive(&folder_canonical, &folder_canonical, 0)?);
            Ok(())
        })?;
        let total = count.into_inner();
        self.log_audit_event(
            AuditEntryType::GuiAction,
            format!("文件夹导入: {} 个文件", total).as_bytes(),
        );
        Ok(total)
    }

    /// 递归子目录导入
    fn import_folder_recursive(
        &self,
        base: &Path,
        current: &Path,
        offset: u32,
    ) -> Result<u32, VaultError> {
        let mut count = offset;
        let mut entries: Vec<_> = std::fs::read_dir(current)
            .map_err(VaultError::Io)?
            .filter_map(|e| e.ok())
            .collect();
        entries.sort_by_key(|e| e.file_name());

        for entry in &entries {
            let path = entry.path();
            if path.is_dir() {
                count = self.import_folder_recursive(base, &path, count)?;
            } else if path.is_file() {
                let relative = path
                    .strip_prefix(base)
                    .map_err(|_| VaultError::InvalidInput("路径解析失败".to_string()))?;
                let vault_path = relative.to_string_lossy().replace('\\', "/");
                let vault_path = Self::sanitize_vault_path(&vault_path);
                if vault_path.is_empty() || vault_path == DEFAULT_FILE_NAME {
                    continue;
                }
                self.import_file_as(&path, &vault_path)?;
                count += 1;
            }
        }
        Ok(count)
    }

    // ============================================================
    // 共享文件导入（SM2）
    // ============================================================

    /// 导入共享文件：用本 vault 的 SM2 私钥解密 DEK，存入 vault
    pub fn share_import_file(&self, package: &[u8]) -> Result<(), VaultError> {
        use crate::crypto::sm2::decrypt;

        let priv_key = self.sm2_priv_key.as_ref().ok_or_else(|| {
            VaultError::Crypto("本保险箱无 SM2 私钥，无法导入共享文件".to_string())
        })?;

        let mut offset = 0usize;

        if package.len() < 4 {
            return Err(VaultError::InvalidInput("共享包太短".to_string()));
        }
        let enc_dek_len = u32::from_le_bytes(package[..4].try_into().expect("长度已检查")) as usize;
        offset += 4;

        if package.len() < offset + enc_dek_len + 4 {
            return Err(VaultError::InvalidInput("共享包格式错误 (1)".to_string()));
        }
        let sm2_enc_dek = &package[offset..offset + enc_dek_len];
        offset += enc_dek_len;

        let meta_len =
            u32::from_le_bytes(package[offset..offset + 4].try_into().expect("长度已检查"))
                as usize;
        offset += 4;

        if package.len() < offset + meta_len + 12 + 32 {
            return Err(VaultError::InvalidInput("共享包格式错误 (2)".to_string()));
        }
        let encrypted_metadata = &package[offset..offset + meta_len];
        offset += meta_len;

        let nonce: &[u8; 12] = &package[offset..offset + 12].try_into().expect("长度已检查");
        offset += 12;

        let hmac_tag: &[u8; 32] = &package[offset..offset + 32].try_into().expect("长度已检查");
        offset += 32;

        let file_ct = &package[offset..];

        // SM2 解密 DEK
        let dek_vec = decrypt(priv_key, sm2_enc_dek)
            .map_err(|e| VaultError::Crypto(format!("SM2 DEK 解密失败: {}", e)))?;

        if dek_vec.len() != DEK_SIZE {
            return Err(VaultError::Crypto("DEK 长度异常".to_string()));
        }
        let dek = Zeroizing::new({
            let mut d = [0u8; DEK_SIZE];
            d.copy_from_slice(&dek_vec);
            d
        });
        let (dek_enc, dek_mac) = dek.split_at(16);

        // HMAC 验证：覆盖 nonce + 加密元数据 + 密文，确保文件完整性
        let mut hm = crate::crypto::sm3::HmacSm3::new(dek_mac);
        hm.update(nonce);
        hm.update(encrypted_metadata);
        hm.update(file_ct);
        let computed_tag = hm.finalize();
        if !crate::crypto::secure_eq::constant_time_eq_32(&computed_tag, hmac_tag) {
            return Err(VaultError::Integrity("共享文件完整性校验失败".to_string()));
        }

        // 解密元数据 + 计算盲索引
        let dek_enc_arr: &[u8; 16] = dek_enc
            .try_into()
            .expect("dek.split_at(16) 保证上半部分为 16 字节");
        let metadata = self.decrypt_metadata(dek_enc_arr, encrypted_metadata)?;

        let blind_key = hmac_sm3(dek_mac, super::BLIND_INDEX_CONTEXT);
        let blind_index = hmac_sm3_concat(
            &blind_key,
            &[&*self.vault_salt, metadata.filename.as_bytes()],
        );

        // DEK 重加密 + 增量 BLOB I/O 写入密文
        let dek_nonce = random_bytes_12();
        let encrypted_dek = sm4_ctr_crypt(&*self.kek, &dek_nonce, &*dek);
        let rowid = self
            .db
            .insert_with_zeroblob(
                &blind_index,
                nonce,
                &dek_nonce,
                &encrypted_dek,
                encrypted_metadata,
                file_ct.len(),
            )
            .map_err(VaultError::Db)?;
        let mut blob = self
            .db
            .open_content_blob(rowid, true)
            .map_err(VaultError::Db)?;
        blob.write_at(file_ct, 0).map_err(VaultError::Db)?;
        drop(blob);
        self.db
            .update_hmac_tag(&blind_index, hmac_tag)
            .map_err(VaultError::Db)?;

        // 等 SAVEPOINT 释放后再写审计日志（避免跨连接锁竞争）
        self.log_audit_event(AuditEntryType::FileImport, metadata.filename.as_bytes());

        Ok(())
    }
}
