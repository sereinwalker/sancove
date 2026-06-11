//! Vault 内部辅助函数

use std::path::Path;

use rand::RngCore;
use rand::rngs::OsRng;
use zeroize::Zeroizing;

use crate::audit_log::AuditLog;
use crate::crypto::sm2::generate_key_pair;
use crate::crypto::sm3::{hmac_sm3_concat, pbkdf2_sm3};
use crate::crypto::sm4_ctr::sm4_ctr_crypt;
use crate::db::FileDb;

/// 从密码派生 KEK: PBKDF2-SM3(password, vault_salt, iterations, 16)
pub(crate) fn derive_kek(password: &[u8], salt: &[u8], iterations: u32) -> Zeroizing<[u8; 16]> {
    let mut kek = Zeroizing::new([0u8; 16]);
    let derived = pbkdf2_sm3(password, salt, iterations, 16);
    kek.copy_from_slice(&derived);
    kek
}

/// 生成 16 字节真随机数
pub(crate) fn random_bytes_16() -> [u8; 16] {
    let mut buf = [0u8; 16];
    OsRng.fill_bytes(&mut buf);
    buf
}

/// 生成 12 字节真随机数（CTR 模式的 nonce）
pub(crate) fn random_bytes_12() -> [u8; 12] {
    let mut buf = [0u8; 12];
    OsRng.fill_bytes(&mut buf);
    buf
}

/// 将字节切片转为 [u8; 12]，长度不对则返回错误
pub(crate) fn bytes_to_array_12(v: &[u8]) -> Result<[u8; 12], super::VaultError> {
    use super::VaultError;
    if v.len() < 12 {
        return Err(VaultError::Corrupt("期望至少 12 字节数据".to_string()));
    }
    let mut arr = [0u8; 12];
    arr.copy_from_slice(&v[..12]);
    Ok(arr)
}

/// 将字节切片转为 [u8; 32]，长度不对则返回错误
pub(crate) fn bytes_to_array_32(v: &[u8]) -> Result<[u8; 32], super::VaultError> {
    use super::VaultError;
    if v.len() != 32 {
        return Err(VaultError::Corrupt("期望 32 字节数据".to_string()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(v);
    Ok(arr)
}

/// 检测文件是否为 SQLite 数据库格式
pub(crate) fn is_sqlite_file(path: &Path) -> bool {
    use std::io::Read;
    let mut f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let mut magic = [0u8; 16];
    if f.read_exact(&mut magic).is_ok() {
        &magic == b"SQLite format 3\0"
    } else {
        false
    }
}

/// 递归删除已导入的源文件和空目录
pub(crate) fn remove_imported_sources(path: &Path) -> Result<(), super::VaultError> {
    use super::VaultError;
    if path.is_dir() {
        for entry in std::fs::read_dir(path).map_err(VaultError::Io)? {
            let entry = entry.map_err(VaultError::Io)?;
            remove_imported_sources(&entry.path())?;
        }
        let _ = std::fs::remove_dir(path);
    } else if path.is_file() {
        std::fs::remove_file(path).map_err(VaultError::Io)?;
    }
    Ok(())
}

// ============================================================
// 审计日志初始化
// ============================================================

/// 初始化审计日志（非致命）
pub(crate) fn init_audit_log(db_path: &Path) -> Result<AuditLog, String> {
    AuditLog::open(db_path).map_err(|e| format!("审计日志打开失败: {}", e))
}

// ============================================================
// SM2 密钥管理
// ============================================================

/// 生成 SM2 密钥对并加密存储到数据库配置（含 HMAC 完整性保护）
pub(crate) fn generate_and_store_sm2_keys(
    db: &FileDb,
    kek: &[u8; 16],
    kek_raw: &[u8; 16],
) -> Result<([u8; 65], Zeroizing<[u8; 32]>), String> {
    let (priv_key, pub_key) = generate_key_pair();

    let sm2_nonce = random_bytes_12();
    let encrypted_priv = sm4_ctr_crypt(kek, &sm2_nonce, &*priv_key);

    // 带 HMAC 完整性标签存储（防篡改）
    let pub_hmac = hmac_sm3_concat(kek_raw, &[super::CONFIG_KEY_SM2_PUB.as_bytes(), &pub_key]);
    db.set_config_with_hmac(super::CONFIG_KEY_SM2_PUB, &pub_key, &pub_hmac)
        .map_err(|e| format!("SM2 公钥存储失败: {}", e))?;

    let nonce_hmac = hmac_sm3_concat(kek_raw, &[super::CONFIG_KEY_SM2_IV.as_bytes(), &sm2_nonce]);
    db.set_config_with_hmac(super::CONFIG_KEY_SM2_IV, &sm2_nonce, &nonce_hmac)
        .map_err(|e| format!("SM2 nonce 存储失败: {}", e))?;

    let priv_hmac = hmac_sm3_concat(
        kek_raw,
        &[super::CONFIG_KEY_SM2_PRIV.as_bytes(), &encrypted_priv],
    );
    db.set_config_with_hmac(super::CONFIG_KEY_SM2_PRIV, &encrypted_priv, &priv_hmac)
        .map_err(|e| format!("SM2 私钥存储失败: {}", e))?;

    Ok((pub_key, priv_key))
}

pub(crate) type Sm2KeyPair = (Option<[u8; 65]>, Option<Zeroizing<[u8; 32]>>);

/// 从数据库配置加载 SM2 密钥对（验证 HMAC 完整性标签）
pub(crate) fn load_sm2_keys(
    db: &FileDb,
    kek: &[u8; 16],
    kek_raw: &[u8; 16],
) -> Result<Sm2KeyPair, String> {
    use super::CONFIG_KEY_SM2_IV;
    use super::CONFIG_KEY_SM2_PRIV;
    use super::CONFIG_KEY_SM2_PUB;

    let pub_key = match db
        .get_config_with_hmac(CONFIG_KEY_SM2_PUB)
        .map_err(|e| format!("SM2 配置读取失败: {}", e))?
    {
        Some((bytes, stored_hmac)) if bytes.len() == 65 => {
            let expected_hmac = hmac_sm3_concat(kek_raw, &[CONFIG_KEY_SM2_PUB.as_bytes(), &bytes]);
            if crate::crypto::secure_eq::constant_time_eq_32(
                &expected_hmac,
                &crate::vault::helpers::bytes_to_array_32(&stored_hmac)
                    .map_err(|_| "SM2 公钥 HMAC 长度异常".to_string())?,
            ) {
                let mut k = [0u8; 65];
                k.copy_from_slice(&bytes);
                Some(k)
            } else {
                eprintln!("警告: SM2 公钥 HMAC 验证失败，丢弃");
                None
            }
        }
        _ => None,
    };

    let priv_key = (|| -> Option<Zeroizing<[u8; 32]>> {
        let nonce_result = db.get_config_with_hmac(CONFIG_KEY_SM2_IV).ok()?;
        let enc_priv_result = db.get_config_with_hmac(CONFIG_KEY_SM2_PRIV).ok()?;

        let (nonce_stored, _nonce_hmac) = match nonce_result {
            Some((v, h)) if v.len() == 12 => {
                let expected_hmac = hmac_sm3_concat(kek_raw, &[CONFIG_KEY_SM2_IV.as_bytes(), &v]);
                if !crate::crypto::secure_eq::constant_time_eq_32(
                    &expected_hmac,
                    &crate::vault::helpers::bytes_to_array_32(&h).ok()?,
                ) {
                    eprintln!("警告: SM2 nonce HMAC 验证失败");
                    return None;
                }
                (v, h)
            }
            _ => return None,
        };

        let enc_priv = match enc_priv_result {
            Some((v, h)) => {
                let expected_hmac = hmac_sm3_concat(kek_raw, &[CONFIG_KEY_SM2_PRIV.as_bytes(), &v]);
                if !crate::crypto::secure_eq::constant_time_eq_32(
                    &expected_hmac,
                    &crate::vault::helpers::bytes_to_array_32(&h).ok()?,
                ) {
                    eprintln!("警告: SM2 加密私钥 HMAC 验证失败");
                    return None;
                }
                v
            }
            _ => return None,
        };

        let nonce = bytes_to_array_12(&nonce_stored).ok()?;

        let decrypted = sm4_ctr_crypt(kek, &nonce, &enc_priv);
        if decrypted.len() != 32 {
            return None;
        }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&decrypted);
        Some(Zeroizing::new(pk))
    })();

    Ok((pub_key, priv_key))
}
