//! Vault 内部辅助方法（用于其他子模块的 impl Vault）

use zeroize::{Zeroize, Zeroizing};

use crate::db::FileRecord;

use super::helpers::bytes_to_array_12;
use super::{DEFAULT_FILE_NAME, DEK_SIZE, FileMetadata, Vault, VaultError};
use crate::crypto::sm4_ctr::sm4_ctr_crypt;

impl Vault {
    /// 用 KEK 解密 DEK
    pub(crate) fn decrypt_dek(
        &self,
        record: &FileRecord,
    ) -> Result<Zeroizing<[u8; DEK_SIZE]>, VaultError> {
        let nonce = bytes_to_array_12(&record.dek_iv)?;

        let mut dek_vec = sm4_ctr_crypt(&*self.kek, &nonce, &record.encrypted_dek);

        if dek_vec.len() != DEK_SIZE {
            return Err(VaultError::Crypto("DEK 长度异常".to_string()));
        }

        let mut dek = [0u8; DEK_SIZE];
        dek.copy_from_slice(&dek_vec);
        dek_vec.zeroize();
        Ok(Zeroizing::new(dek))
    }

    /// 用 DEK_enc 解密元数据
    pub(crate) fn decrypt_metadata(
        &self,
        dek_enc: &[u8; 16],
        encrypted_metadata: &[u8],
    ) -> Result<FileMetadata, VaultError> {
        if encrypted_metadata.len() < 17 {
            return Err(VaultError::Corrupt("元数据长度异常".to_string()));
        }
        let nonce = bytes_to_array_12(&encrypted_metadata[..12])?;
        let ciphertext = &encrypted_metadata[12..];

        let decrypted = sm4_ctr_crypt(dek_enc, &nonce, ciphertext);

        bincode::deserialize(&decrypted).map_err(VaultError::Serialize)
    }

    // ============================================================
    // 消毒函数（防止路径穿越）
    // ============================================================

    /// 公共字符过滤：将非法文件名字符替换为空格
    fn sanitize_char(c: char) -> char {
        match c {
            // 路径分隔符和 Windows 保留字符 → 空格
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => ' ',
            // 控制字符 → 空格
            '\x00'..='\x1f' => ' ',
            // 其余保留
            _ => c,
        }
    }

    /// 消毒文件名，防止路径穿越攻击
    ///
    /// 过滤 /\\:等非法字符，移除 . 和 ..，返回安全的单文件名。
    pub(crate) fn sanitize_filename(name: &str) -> String {
        let mut result = String::with_capacity(name.len());
        for c in name.chars() {
            result.push(Self::sanitize_char(c));
        }
        let trimmed = result.trim().to_string();
        if trimmed.is_empty() {
            return DEFAULT_FILE_NAME.to_string();
        }

        let parts: Vec<&str> = trimmed
            .split(' ')
            .filter(|s| !s.is_empty() && *s != "." && *s != "..")
            .collect();
        if parts.is_empty() {
            DEFAULT_FILE_NAME.to_string()
        } else {
            parts.join(" ")
        }
    }

    /// 消毒虚拟路径（保留 `/` 作为目录分隔符，防路径穿越）
    ///
    /// 保留 `/` 用于目录结构，逐个消毒路径分量。
    pub(crate) fn sanitize_vault_path(path: &str) -> String {
        let normalized = path.replace('\\', "/");
        let parts: Vec<&str> = normalized
            .split('/')
            .filter(|s| !s.is_empty() && *s != "." && *s != "..")
            .collect();
        if parts.is_empty() {
            return DEFAULT_FILE_NAME.to_string();
        }
        let safe_parts: Vec<String> = parts
            .iter()
            .map(|part| {
                let mut result = String::with_capacity(part.len());
                for c in part.chars() {
                    result.push(Self::sanitize_char(c));
                }
                let trimmed = result.trim().to_string();
                if trimmed == "." || trimmed == ".." || trimmed.is_empty() {
                    "_".to_string()
                } else {
                    trimmed
                }
            })
            .collect();
        safe_parts.join("/")
    }
}
