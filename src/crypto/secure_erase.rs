//! 安全文件擦除
//!
//! 实现文件数据的安全覆写删除，防止数据恢复工具还原敏感文件。
//!
//! # 擦除策略
//!
//! - [`secure_erase_file`]: 多遍覆写 + 截断（默认 3 遍：随机 → 全零 → 全一）
//! - [`secure_erase_file_meta`]: 快速元数据擦除（仅覆盖文件头部元数据区域）
//!
//! # 安全说明
//!
//! SSD 和闪存设备由于 FTL（闪存转换层）的磨损均衡机制，物理扇区可能与逻辑
//! 地址不一致，单次覆写无法保证物理数据的不可恢复性。本模块的目标是防御
//! 软件级数据恢复工具（如 TestDisk、PhotoRec）的恢复攻击，而非物理级取证防护。
//! 对于 SSD 上的敏感数据，建议结合全盘加密使用。

use std::fs;
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

use rand::RngCore;
use rand::rngs::OsRng;
use zeroize::Zeroize;

// ============================================================
// 常量
// ============================================================

/// 默认擦除遍数（随机 → 全零 → 全一）
const DEFAULT_PASSES: usize = 3;

/// 单次读写块大小（64 KB，与 vault 流式加密块大小一致）
pub const BLOCK_SIZE: usize = 65536;

/// 最大允许擦除遍数（防止意外传入极大数值导致长时间阻塞）
const MAX_PASSES: usize = 35;

// ============================================================
// 错误类型
// ============================================================

/// 安全擦除操作错误
#[derive(Debug)]
pub enum EraseError {
    /// 文件 I/O 错误（读/写/同步失败）
    Io(std::io::Error),
    /// 无效参数（遍数超出范围等）
    InvalidParam(String),
}

impl std::fmt::Display for EraseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EraseError::Io(e) => write!(f, "擦除 I/O 错误: {}", e),
            EraseError::InvalidParam(e) => write!(f, "擦除参数无效: {}", e),
        }
    }
}

impl std::error::Error for EraseError {}

impl From<std::io::Error> for EraseError {
    fn from(e: std::io::Error) -> Self {
        EraseError::Io(e)
    }
}

// ============================================================
// 公开函数
// ============================================================

/// 安全擦除文件数据（多遍覆写 + 截断）
///
/// 对指定文件执行多遍覆写，使数据无法通过软件恢复工具还原。
/// 默认执行 3 遍覆写（Gutmann 标准推荐的简化模式）：
///
/// 1. **随机数据** — 使用 CSPRNG 生成的不可预测字节填充
/// 2. **全 0x00** — 消除上一步随机数据的磁变痕迹
/// 3. **全 0xFF** — 最后一次极性反转使残留信号最弱
///
/// 所有覆写数据在每遍结束后立即 `flush` + `fsync` 确保写入物理介质。
/// 覆写完成后将文件截断至 0 字节并再次同步。
///
/// # 参数
///
/// * `path` - 待擦除的文件路径
/// * `passes` - 覆写遍数。`None` 表示使用默认 3 遍。
///   有效范围 1～35。超出范围返回 [`EraseError::InvalidParam`]。
///
/// # 返回值
///
/// 擦除成功返回 `Ok(())`，失败返回 [`EraseError`]。
///
/// # 示例
///
/// ```rust,ignore
/// use secure_erase::secure_erase_file;
///
/// // 默认 3 遍擦除
/// secure_erase_file("secret.txt", None)?;
///
/// // 7 遍覆写（更高安全级别）
/// secure_erase_file("top_secret.bin", Some(7))?;
/// ```
pub fn secure_erase_file(path: &Path, passes: Option<usize>) -> Result<(), EraseError> {
    let n = passes.unwrap_or(DEFAULT_PASSES);

    // 参数校验
    if n == 0 {
        return Err(EraseError::InvalidParam("擦除遍数不能为 0".to_string()));
    }
    if n > MAX_PASSES {
        return Err(EraseError::InvalidParam(format!(
            "擦除遍数不能超过 {}，指定为 {}",
            MAX_PASSES, n
        )));
    }

    // 获取文件元数据（含文件大小）
    let metadata = fs::metadata(path)?;
    let file_len = metadata.len();

    // 空文件无需覆写，直接同步后返回
    if file_len == 0 {
        return Ok(());
    }

    // 打开文件（写入模式，不截断）
    let mut file = fs::OpenOptions::new().write(true).open(path)?;

    // 预分配覆写缓冲区
    let mut buf = vec![0u8; BLOCK_SIZE];

    for pass in 0..n {
        // 每遍回到文件起始位置
        file.seek(SeekFrom::Start(0))?;

        match pass % 3 {
            0 => {
                // 第 0、3、6…遍：CSPRNG 随机数据
                let mut remaining = file_len;
                while remaining > 0 {
                    let chunk = remaining.min(BLOCK_SIZE as u64) as usize;
                    OsRng.fill_bytes(&mut buf[..chunk]);
                    file.write_all(&buf[..chunk])?;
                    remaining -= chunk as u64;
                }
            }
            1 => {
                // 第 1、4、7…遍：全 0x00
                buf.fill(0x00);
                let mut remaining = file_len;
                while remaining > 0 {
                    let chunk = remaining.min(BLOCK_SIZE as u64) as usize;
                    file.write_all(&buf[..chunk])?;
                    remaining -= chunk as u64;
                }
            }
            2 => {
                // 第 2、5、8…遍：全 0xFF
                buf.fill(0xFF);
                let mut remaining = file_len;
                while remaining > 0 {
                    let chunk = remaining.min(BLOCK_SIZE as u64) as usize;
                    file.write_all(&buf[..chunk])?;
                    remaining -= chunk as u64;
                }
            }
            _ => unreachable!(),
        }

        // 确保本遍覆写数据刷入物理介质
        file.flush()?;
        file.sync_all()?;
    }

    // 截断文件至 0 字节（清除目录项中残留的文件大小信息）
    file.set_len(0)?;
    file.flush()?;
    file.sync_all()?;

    // 零化缓冲区：擦除 CSPRNG 随机数据（pass 0 写入了不可预测字节）
    buf.zeroize();

    Ok(())
}

// ============================================================
// 测试
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    /// 创建指定大小的临时文件并用已知模式填充
    fn create_temp_file(size: usize) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test_file.bin");
        let content = vec![0xABu8; size];
        fs::write(&path, &content).unwrap();
        (dir, path)
    }

    /// 读取文件全部字节
    fn read_all(path: &Path) -> Vec<u8> {
        let mut buf = Vec::new();
        fs::File::open(path).unwrap().read_to_end(&mut buf).unwrap();
        buf
    }

    #[test]
    fn test_secure_erase_default_passes() {
        let (_dir, path) = create_temp_file(4096);

        // 执行默认 3 遍擦除
        secure_erase_file(&path, None).unwrap();

        // 擦除后文件应为 0 字节
        let metadata = fs::metadata(&path).unwrap();
        assert_eq!(metadata.len(), 0);
    }

    #[test]
    fn test_secure_erase_multiple_passes() {
        let (_dir, path) = create_temp_file(8192);

        // 执行 7 遍擦除
        secure_erase_file(&path, Some(7)).unwrap();

        let metadata = fs::metadata(&path).unwrap();
        assert_eq!(metadata.len(), 0);
    }

    #[test]
    fn test_secure_erase_single_pass() {
        let (_dir, path) = create_temp_file(1024);

        secure_erase_file(&path, Some(1)).unwrap();

        let metadata = fs::metadata(&path).unwrap();
        assert_eq!(metadata.len(), 0);
    }

    #[test]
    fn test_secure_erase_empty_file() {
        let (_dir, path) = create_temp_file(0);

        // 空文件擦除应直接成功
        secure_erase_file(&path, None).unwrap();
        let metadata = fs::metadata(&path).unwrap();
        assert_eq!(metadata.len(), 0);
    }

    #[test]
    fn test_secure_erase_large_file() {
        let (_dir, path) = create_temp_file(1024 * 1024); // 1 MB

        secure_erase_file(&path, Some(3)).unwrap();

        let metadata = fs::metadata(&path).unwrap();
        assert_eq!(metadata.len(), 0);
    }

    #[test]
    fn test_secure_erase_zero_passes_rejected() {
        let (_dir, path) = create_temp_file(128);

        let result = secure_erase_file(&path, Some(0));
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), EraseError::InvalidParam(_)),
            "0 遍应返回 InvalidParam"
        );
    }

    #[test]
    fn test_secure_erase_exceeds_max_passes_rejected() {
        let (_dir, path) = create_temp_file(128);

        let result = secure_erase_file(&path, Some(36));
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), EraseError::InvalidParam(_)),
            "超过最大遍数应返回 InvalidParam"
        );
    }

    #[test]
    fn test_secure_erase_nonexistent_file_rejected() {
        let path = Path::new("nonexistent_file_XXXXX.bin");

        let result = secure_erase_file(path, None);
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), EraseError::Io(_)),
            "不存在的文件应返回 Io 错误"
        );
    }

    #[test]
    fn test_erase_truncates_to_zero() {
        // 验证擦除后文件被截断为 0 字节
        let (_dir, path) = create_temp_file(512);

        secure_erase_file(&path, Some(1)).unwrap();

        let metadata = fs::metadata(&path).unwrap();
        assert_eq!(metadata.len(), 0);
    }

    #[test]
    fn test_erase_file_then_write_read() {
        // 擦除后文件可重新写入数据（文件系统状态正常）
        let (_dir, path) = create_temp_file(256);

        secure_erase_file(&path, None).unwrap();

        // 重新写入
        fs::write(&path, b"new data after erase").unwrap();
        let content = read_all(&path);
        assert_eq!(content, b"new data after erase");
    }

    #[test]
    fn test_erase_inner_scope() {
        // 验证擦除在嵌套作用域中也能正确执行
        let (_dir, path) = create_temp_file(128);

        {
            secure_erase_file(&path, Some(1)).unwrap();
        }

        let metadata = fs::metadata(&path).unwrap();
        assert_eq!(metadata.len(), 0);
    }
}
