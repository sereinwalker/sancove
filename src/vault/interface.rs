//! Vault 公共接口：SM2 签名/验签、审计日志查询、Shamir 秘密共享

use zeroize::{Zeroize, Zeroizing};

use super::{Vault, VaultError};
use crate::audit_log::AuditEntryType;

impl Vault {
    // ============================================================
    // SM2 公共接口
    // ============================================================

    /// 获取 SM2 公钥（65 字节未压缩格式）
    pub fn get_sm2_pub_key(&self) -> Option<&[u8; 65]> {
        self.sm2_pub_key.as_ref()
    }

    /// 使用 SM2 对数据进行签名
    pub fn sm2_sign(&self, data: &[u8]) -> Result<[u8; 64], VaultError> {
        let priv_key = self
            .sm2_priv_key
            .as_ref()
            .ok_or_else(|| VaultError::Crypto("SM2 私钥不可用".to_string()))?;
        let pub_key = self
            .sm2_pub_key
            .as_ref()
            .ok_or_else(|| VaultError::Crypto("SM2 公钥不可用".to_string()))?;
        let sig = crate::crypto::sm2::sign(priv_key, pub_key, data).to_bytes();
        self.log_audit_event(
            AuditEntryType::GuiAction,
            format!("SM2 签名: {} 字节", data.len()).as_bytes(),
        );
        Ok(sig)
    }

    /// 使用 SM2 验证签名
    pub fn sm2_verify(&self, data: &[u8], signature: &[u8; 64]) -> Result<bool, VaultError> {
        let pub_key = self
            .sm2_pub_key
            .as_ref()
            .ok_or_else(|| VaultError::Crypto("SM2 公钥不可用".to_string()))?;
        let sig = crate::crypto::sm2::Signature::from_bytes(signature);
        let result = crate::crypto::sm2::verify(pub_key, data, &sig);
        self.log_audit_event(
            AuditEntryType::GuiAction,
            format!("SM2 验签: {}", if result { "通过" } else { "失败" }).as_bytes(),
        );
        Ok(result)
    }

    // ============================================================
    // 审计日志查询
    // ============================================================

    /// 获取最近的审计日志条目
    pub fn audit_log_get_recent(
        &self,
        limit: usize,
    ) -> Result<Vec<(crate::audit_log::AuditEntry, [u8; 32])>, VaultError> {
        self.audit_log
            .as_ref()
            .ok_or_else(|| VaultError::AuditLog("审计日志未初始化".to_string()))?
            .get_recent(limit)
            .map_err(|e| VaultError::AuditLog(e.to_string()))
    }

    /// 验证审计日志哈希链完整性
    pub fn audit_log_verify(&self) -> Result<bool, VaultError> {
        self.audit_log
            .as_ref()
            .ok_or_else(|| VaultError::AuditLog("审计日志未初始化".to_string()))?
            .verify_chain(&*self.kek)
            .map_err(|e| VaultError::AuditLog(e.to_string()))
    }

    /// 导出审计日志为 JSON
    pub fn audit_log_export_json(&self) -> Result<String, VaultError> {
        self.audit_log
            .as_ref()
            .ok_or_else(|| VaultError::AuditLog("审计日志未初始化".to_string()))?
            .export_as_json()
            .map_err(|e| VaultError::AuditLog(e.to_string()))
    }

    /// 记录自定义审计事件
    pub fn log_audit_event(&self, entry_type: AuditEntryType, payload: &[u8]) {
        if let Some(ref log) = self.audit_log {
            if let Err(e) = log.append(entry_type, &*self.kek, payload) {
                eprintln!("审计日志追加失败 (entry_type={:?}): {}", entry_type, e);
            }
        }
    }

    // ============================================================
    // Shamir 秘密共享（KEK 分片灾备）
    // ============================================================

    /// 将当前 KEK 拆分为 `n` 份子秘密，任意 `t` 份可恢复
    pub fn split_kek(&self, n: u8, t: u8) -> Result<Vec<String>, VaultError> {
        if t < 2 || n < t {
            return Err(VaultError::InvalidInput(
                "门限 t 必须 >= 2 且分享数 n >= t".to_string(),
            ));
        }

        let shares = crate::crypto::shamir::split_secret(&*self.kek, n, t);
        self.log_audit_event(
            AuditEntryType::GuiAction,
            format!("KEK 分片: {}/{}", t, n).as_bytes(),
        );
        Ok(shares
            .iter()
            .map(|s| s.iter().map(|b| format!("{:02x}", b)).collect())
            .collect())
    }

    /// 从 `t` 份子秘密重构 KEK 并打开 vault，然后设置新密码
    pub fn recover_from_shares(
        vault_dir: &std::path::Path,
        shares_hex: &[String],
        t: u8,
        new_password: &str,
    ) -> Result<Self, VaultError> {
        if new_password.is_empty() {
            return Err(VaultError::InvalidInput("新密码不能为空".to_string()));
        }

        let shares: Vec<Vec<u8>> = shares_hex
            .iter()
            .map(|hex| {
                (0..hex.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| VaultError::InvalidInput("子秘密十六进制格式错误".to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let shares = Zeroizing::new(shares);

        if shares.len() < t as usize {
            return Err(VaultError::InvalidInput(format!(
                "需要至少 {} 份子秘密，仅提供 {}",
                t,
                shares.len()
            )));
        }

        let kek_bytes = Zeroizing::new(crate::crypto::shamir::recover_secret(&shares, t));
        if kek_bytes.len() != 16 {
            return Err(VaultError::Crypto("重构的 KEK 长度异常".to_string()));
        }
        let mut kek = [0u8; 16];
        kek.copy_from_slice(&kek_bytes);

        let mut vault = Self::open_with_kek(vault_dir, &kek)?;
        vault.change_password(new_password)?;

        kek.zeroize();
        Ok(vault)
    }
}
