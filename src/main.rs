//! 基于国密算法的保密文件库 - CLI 入口
//!
//! # 使用方式
//!
//! ```bash
//! cargo run -- create /path/to/vault          # 需输入密码（二次确认）
//! cargo run -- list /path/to/vault            # 需输入密码
//! cargo run -- import /path/to/vault file     # 需输入密码
//! cargo run -- gui /path/to/vault             # 文件关联用
//! ```
//!
//! # 安全方案
//!
//! - 密码学算法：纯 Rust 实现 SM3/SM4，无第三方加密库依赖
//! - 密钥体系：KEK/DEK 双层密钥，PBKDF2-SM3 密钥派生
//! - 加密模式：SM4-CTR（流密码，无填充侧信道）+ Encrypt-then-MAC
//! - 完整性：HMAC-SM3 常数时间比较，Verify-then-Decrypt 协议
//! - 元数据：零知识行级加密 + 盲哈希索引
//! - 内存保护：ZeroizeOnDrop 自动零化密钥

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use sancove::audit_log::AuditEntryType;
use sancove::vault::{Vault, VaultError};
use zeroize::Zeroizing;

// ============================================================
// 常量
// ============================================================

/// SM2 签名长度（字节）
const SM2_SIG_BYTES: usize = 64;
/// SM2 公钥长度（65 字节未压缩格式，含 0x04 前缀）
const SM2_PUBKEY_BYTES: usize = 65;
/// SM2 公钥十六进制字符串长度（130 字符）
const SM2_PUBKEY_HEX_LEN: usize = 130;
/// 盲索引十六进制字符串长度（64 字符 = 32 字节）
const BLIND_INDEX_HEX_LEN: usize = 64;
/// 审计日志显示最大条数
const AUDIT_LOG_DISPLAY_LIMIT: usize = 50;

/// 基于国密算法 (SM4/SM3) 的保密文件库
#[derive(Parser)]
#[command(name = "sancove", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// 创建新的保险箱
    Create {
        /// 保险箱存储目录
        vault_dir: PathBuf,
    },
    /// 将文件导入保险箱
    Import {
        /// 保险箱存储目录
        vault_dir: PathBuf,
        /// 要导入的文件路径
        file: PathBuf,
    },
    /// 列出保险箱中的文件
    List {
        /// 保险箱存储目录
        vault_dir: PathBuf,
    },
    /// 从保险箱导出文件
    Export {
        /// 保险箱存储目录
        vault_dir: PathBuf,
        /// 盲索引（64 位十六进制字符串）
        blind_index: String,
        /// 输出目录
        output_dir: PathBuf,
    },
    /// 从保险箱移除文件
    Remove {
        /// 保险箱存储目录
        vault_dir: PathBuf,
        /// 盲索引（64 位十六进制字符串）
        blind_index: String,
    },
    /// 重命名文件
    Rename {
        /// 保险箱存储目录
        vault_dir: PathBuf,
        /// 盲索引（64 位十六进制字符串）
        blind_index: String,
        /// 新文件名
        new_name: String,
    },
    /// 剪切文件（导出并删除）
    Cut {
        /// 保险箱存储目录
        vault_dir: PathBuf,
        /// 盲索引（64 位十六进制字符串）
        blind_index: String,
        /// 输出路径
        output: PathBuf,
    },
    /// 导入文件夹（递归导入子目录）
    ImportFolder {
        /// 保险箱存储目录
        vault_dir: PathBuf,
        /// 要导入的文件夹路径
        folder: PathBuf,
    },
    /// 导出保险箱目录到本地
    ExportDirectory {
        /// 保险箱存储目录
        vault_dir: PathBuf,
        /// vault 中目录路径（空字符串=根目录）
        vault_path: String,
        /// 输出目录
        output_dir: PathBuf,
    },
    /// 删除保险箱目录
    RemoveDirectory {
        /// 保险箱存储目录
        vault_dir: PathBuf,
        /// vault 中目录路径
        vault_path: String,
    },
    /// 重命名保险箱目录
    RenameDirectory {
        /// 保险箱存储目录
        vault_dir: PathBuf,
        /// 旧目录路径
        old_path: String,
        /// 新目录名
        new_name: String,
    },
    /// 运行性能基准测试
    Bench {
        /// 保险箱存储目录（用于 I/O 基准测试）
        vault_dir: PathBuf,
    },
    /// 启动图形界面模式（文件关联：sancove gui /path/to/vault）
    ///
    /// 不带参数时打开登录界面，由用户输入路径。
    Gui {
        /// 保险箱存储目录（可选，文件关联时自动传入）
        vault_dir: Option<PathBuf>,
    },
    /// 修改保险箱密码
    ChangePassword {
        /// 保险箱存储目录
        vault_dir: PathBuf,
    },
    /// 备份保险箱
    Backup {
        /// 保险箱存储目录
        vault_dir: PathBuf,
        /// 备份目标路径
        backup_dir: PathBuf,
    },
    /// 从备份恢复保险箱
    Restore {
        /// 备份目录
        backup_dir: PathBuf,
        /// 保险箱存储目录（恢复目标）
        vault_dir: PathBuf,
    },
    /// 查看审计日志
    AuditLog {
        /// 保险箱存储目录
        vault_dir: PathBuf,
    },
    /// 验证审计日志完整性
    AuditLogVerify {
        /// 保险箱存储目录
        vault_dir: PathBuf,
    },
    /// 导出审计日志为 JSON
    AuditLogExport {
        /// 保险箱存储目录
        vault_dir: PathBuf,
        /// 输出 JSON 文件路径
        output: PathBuf,
    },
    /// 显示 SM2 公钥
    Sm2Pubkey {
        /// 保险箱存储目录
        vault_dir: PathBuf,
    },
    /// 使用 SM2 签名文件
    Sm2Sign {
        /// 保险箱存储目录
        vault_dir: PathBuf,
        /// 待签名文件路径
        file: PathBuf,
        /// 签名输出路径（64 字节原始签名）
        output: PathBuf,
    },
    /// 使用 SM2 验证签名
    Sm2Verify {
        /// 保险箱存储目录（用于加载 SM2 公钥）
        vault_dir: PathBuf,
        /// 原始文件路径
        file: PathBuf,
        /// 签名文件（64 字节）
        signature: PathBuf,
    },
    /// 导出共享文件（用对方 SM2 公钥加密 DEK）
    ShareExport {
        /// 保险箱存储目录
        vault_dir: PathBuf,
        /// 盲索引（64 位十六进制字符串）
        blind_index: String,
        /// 目标方 SM2 公钥（130 字符十六进制，65 字节未压缩格式）
        target_pubkey: String,
        /// 共享包输出路径
        output: PathBuf,
    },
    /// 导入共享文件（用本 vault SM2 私钥解密 DEK）
    ShareImport {
        /// 保险箱存储目录
        vault_dir: PathBuf,
        /// 共享包文件路径
        package: PathBuf,
    },
    /// 将 KEK 拆分为 Shamir 子秘密（灾备恢复用）
    SplitKek {
        /// 保险箱存储目录
        vault_dir: PathBuf,
        /// 总分享份数
        n: u8,
        /// 恢复门限（至少 t 份可恢复）
        t: u8,
    },
    /// 从 Shamir 子秘密重构 KEK 并设置新密码
    RecoverKek {
        /// 保险箱存储目录
        vault_dir: PathBuf,
        /// 恢复门限
        t: u8,
        /// t 份子秘密（每份为 34 字符十六进制字符串，共 17 字节）
        shares: Vec<String>,
    },
}

// ============================================================
// 安全密码读取辅助函数
// ============================================================

/// 隐藏回显读取密码，失败时提示重试（直至成功或 Ctrl+C 退出）
fn read_password(prompt: &str) -> Zeroizing<String> {
    loop {
        print!("{}", prompt);
        io::stdout().flush().unwrap();
        match rpassword::read_password() {
            Ok(pwd) => return Zeroizing::new(pwd),
            Err(e) => {
                eprintln!("\n⚠️  密码读取失败: {}（终端不支持隐藏输入？）", e);
                eprintln!("   请重试或按 Ctrl+C 退出");
            }
        }
    }
}

/// 读取密码并二次确认（用于创建/修改密码场景）
fn read_password_with_confirm(prompt: &str) -> Zeroizing<String> {
    loop {
        let pwd = read_password(prompt);
        let confirm = read_password("请再次输入密码: ");
        if *pwd == *confirm {
            return pwd;
        }
        eprintln!("⚠️  两次输入的密码不一致，请重新输入");
    }
}

// ============================================================
// 审计日志辅助
// ============================================================

/// 对已打开的 vault 记录 CLI 操作审计日志（格式与 GUI 层 gui_log 一致）
fn log_cli_action(vault: &Vault, entry_type: AuditEntryType, payload: &str) {
    vault.log_audit_event(entry_type, payload.as_bytes());
}

fn main() {
    let cli = Cli::parse();

    let is_gui = matches!(&cli.command, Command::Gui { .. });
    let password: Zeroizing<String> = if is_gui {
        Zeroizing::new(String::new())
    } else {
        read_password("请输入保险箱密码: ")
    };

    let result = match &cli.command {
        Command::Create { vault_dir } => {
            // 创建保险箱：密码需二次确认
            let pwd = read_password_with_confirm("请设置保险箱密码: ");
            cmd_create(vault_dir, &pwd)
        }
        Command::Import { vault_dir, file } => cmd_import(vault_dir, &password, file),
        Command::List { vault_dir } => cmd_list(vault_dir, &password),
        Command::Export {
            vault_dir,
            blind_index,
            output_dir,
        } => cmd_export(vault_dir, &password, blind_index, output_dir),
        Command::Remove {
            vault_dir,
            blind_index,
        } => cmd_remove(vault_dir, &password, blind_index),
        Command::Rename {
            vault_dir,
            blind_index,
            new_name,
        } => cmd_rename(vault_dir, &password, blind_index, new_name),
        Command::Cut {
            vault_dir,
            blind_index,
            output,
        } => cmd_cut(vault_dir, &password, blind_index, output),
        Command::ImportFolder { vault_dir, folder } => {
            cmd_import_folder(vault_dir, &password, folder)
        }
        Command::ExportDirectory {
            vault_dir,
            vault_path,
            output_dir,
        } => cmd_export_directory(vault_dir, &password, vault_path, output_dir),
        Command::RemoveDirectory {
            vault_dir,
            vault_path,
        } => cmd_remove_directory(vault_dir, &password, vault_path),
        Command::RenameDirectory {
            vault_dir,
            old_path,
            new_name,
        } => cmd_rename_directory(vault_dir, &password, old_path, new_name),
        Command::Bench { vault_dir } => cmd_bench(vault_dir, &password),
        Command::Gui { vault_dir } => {
            match vault_dir {
                Some(dir) => sancove::gui::VaultApp::run_with_vault(dir),
                None => sancove::gui::VaultApp::run(),
            }
            .unwrap_or_else(|e| {
                eprintln!("GUI 错误: {}", e);
                std::process::exit(1);
            });
            Ok(())
        }
        Command::ChangePassword { vault_dir } => cmd_change_password(vault_dir, &password),
        Command::Backup {
            vault_dir,
            backup_dir,
        } => cmd_backup(vault_dir, backup_dir, &password),
        Command::Restore {
            backup_dir,
            vault_dir,
        } => cmd_restore(backup_dir, vault_dir, &password),
        Command::AuditLog { vault_dir } => cmd_audit_log(vault_dir, &password),
        Command::AuditLogVerify { vault_dir } => cmd_audit_log_verify(vault_dir, &password),
        Command::AuditLogExport { vault_dir, output } => {
            cmd_audit_log_export(vault_dir, &password, output)
        }
        Command::Sm2Pubkey { vault_dir } => cmd_sm2_pubkey(vault_dir, &password),
        Command::Sm2Sign {
            vault_dir,
            file,
            output,
        } => cmd_sm2_sign(vault_dir, &password, file, output),
        Command::Sm2Verify {
            vault_dir,
            file,
            signature,
        } => cmd_sm2_verify(vault_dir, &password, file, signature),
        Command::ShareExport {
            vault_dir,
            blind_index,
            target_pubkey,
            output,
        } => cmd_share_export(vault_dir, &password, blind_index, target_pubkey, output),
        Command::ShareImport { vault_dir, package } => {
            cmd_share_import(vault_dir, &password, package)
        }
        Command::SplitKek { vault_dir, n, t } => cmd_split_kek(vault_dir, &password, *n, *t),
        Command::RecoverKek {
            vault_dir,
            t,
            shares,
        } => cmd_recover_kek(vault_dir, *t, shares),
    };

    if let Err(e) = result {
        eprintln!("错误: {}", e);
        std::process::exit(1);
    }
    // password (Zeroizing<String>) 会在 drop 时自动零化
}

// ============================================================
// 命令实现
// ============================================================

fn cmd_create(vault_dir: &Path, password: &str) -> Result<(), VaultError> {
    if vault_dir.exists() {
        eprintln!("警告: 目录已存在，可能覆盖已有数据");
    }
    let _vault = Vault::create(vault_dir, password)?;
    println!("保险箱已创建: {}", vault_dir.display());
    Ok(())
}

fn cmd_import(vault_dir: &Path, password: &str, file: &Path) -> Result<(), VaultError> {
    if !file.exists() {
        return Err(VaultError::InvalidInput(format!(
            "文件不存在: {}",
            file.display()
        )));
    }
    let vault = Vault::open(vault_dir, password)?;
    vault.import_file(file)?;
    println!("已导入: {}", file.file_name().unwrap().to_string_lossy());
    Ok(())
}

fn cmd_list(vault_dir: &Path, password: &str) -> Result<(), VaultError> {
    let vault = Vault::open(vault_dir, password)?;
    log_cli_action(&vault, AuditEntryType::GuiAction, "列出文件");
    let files = vault.list_files()?;

    if files.is_empty() {
        println!("保险箱为空");
        return Ok(());
    }

    println!("保险箱文件 (共 {} 个):", files.len());
    if let Ok(count) = vault.file_count()
        && count as usize != files.len()
    {
        println!("   (数据库总数: {})", count);
    }
    println!("{}", "-".repeat(100));
    for f in &files {
        let hex_index: String = f.blind_index.iter().map(|b| format!("{:02x}", b)).collect();
        let size_str = if f.original_size >= 1_000_000 {
            format!("{:.2} MB", f.original_size as f64 / 1_000_000.0)
        } else if f.original_size >= 1_000 {
            format!("{:.1} KB", f.original_size as f64 / 1_000.0)
        } else {
            format!("{} B", f.original_size)
        };
        println!("  - {}", f.filename);
        println!("     盲索引: {}...", &hex_index[..16]);
        println!("     大小: {} | 时间戳: {}", size_str, f.created_at);
    }
    Ok(())
}

fn cmd_export(
    vault_dir: &Path,
    password: &str,
    blind_index_hex: &str,
    output_dir: &Path,
) -> Result<(), VaultError> {
    if !output_dir.exists() {
        return Err(VaultError::InvalidInput(format!(
            "输出目录不存在: {}",
            output_dir.display()
        )));
    }

    let blind_index = parse_hex_blind_index(blind_index_hex)?;
    let vault = Vault::open(vault_dir, password)?;
    vault.export_file(&blind_index, output_dir)?;
    println!("文件已导出到: {}", output_dir.display());
    Ok(())
}

fn cmd_remove(vault_dir: &Path, password: &str, blind_index_hex: &str) -> Result<(), VaultError> {
    let blind_index = parse_hex_blind_index(blind_index_hex)?;
    let vault = Vault::open(vault_dir, password)?;
    vault.remove_file(&blind_index)?;
    println!("文件已移除");
    Ok(())
}

// ============================================================
// 备份/恢复命令
// ============================================================

fn cmd_backup(vault_dir: &Path, backup_dir: &Path, password: &str) -> Result<(), VaultError> {
    let vault = Vault::open(vault_dir, password)?;
    vault.backup_to(backup_dir)?;
    println!("保险箱已备份到: {}", backup_dir.display());
    Ok(())
}

fn cmd_restore(backup_dir: &Path, vault_dir: &Path, password: &str) -> Result<(), VaultError> {
    if !backup_dir.join("vault.db").exists() {
        return Err(VaultError::InvalidInput(
            "备份目录中未找到 vault.db".to_string(),
        ));
    }
    // 先验证密码：尝试用密码打开备份 vault（会校验 HMAC 完整性标签）
    // 确保只有知道密码的用户才能恢复
    let _vault = Vault::open(backup_dir, password)?;

    println!(
        "将要从 {} 恢复到 {}\n   此操作将覆盖目标目录的现有数据",
        backup_dir.display(),
        vault_dir.display()
    );
    print!("确认恢复? (y/N): ");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    if input.trim().to_lowercase() != "y" {
        println!("已取消");
        return Ok(());
    }
    Vault::restore_from(backup_dir, vault_dir)?;

    // 在恢复后的 vault 中记录审计日志
    let vault = Vault::open(vault_dir, password)?;
    log_cli_action(
        &vault,
        AuditEntryType::VaultRestore,
        &format!("从 {} 恢复", backup_dir.display()),
    );

    println!("保险箱已恢复");
    Ok(())
}

fn cmd_change_password(vault_dir: &Path, old_password: &str) -> Result<(), VaultError> {
    let mut vault = Vault::open(vault_dir, old_password)?;

    let new_password = read_password("请输入新密码: ");
    let confirm_password = read_password("请再次输入新密码: ");

    if *new_password != *confirm_password {
        return Err(VaultError::InvalidInput("两次输入的密码不一致".to_string()));
    }
    if new_password.is_empty() {
        return Err(VaultError::InvalidInput("密码不能为空".to_string()));
    }

    vault.change_password(&new_password)?;
    println!("保险箱密码已修改");
    Ok(())
}

// ============================================================
// 审计日志命令
// ============================================================

fn cmd_audit_log(vault_dir: &Path, password: &str) -> Result<(), VaultError> {
    let vault = Vault::open(vault_dir, password)?;

    // 显示总数
    let total = vault.audit_log_count().unwrap_or(0);
    println!("审计日志 (共 {} 条):", total);
    println!("{}", "-".repeat(90));

    match vault.audit_log_get_recent(AUDIT_LOG_DISPLAY_LIMIT) {
        Ok(entries) => {
            if entries.is_empty() {
                println!("  （空）");
            }
            for (entry, _hmac) in &entries {
                let ts = sancove::audit_log::chrono_from_timestamp(entry.timestamp);
                let type_name = sancove::audit_log::AuditEntryType::from_u8(entry.entry_type)
                    .map(|t| t.display_name().to_string())
                    .unwrap_or_else(|| format!("未知({})", entry.entry_type));
                let payload = String::from_utf8_lossy(&entry.payload);
                println!("  #{} [{}] {} — {}", entry.idx, ts, type_name, payload);
            }
        }
        Err(e) => eprintln!("审计日志读取错误: {}", e),
    }
    Ok(())
}

fn cmd_audit_log_verify(vault_dir: &Path, password: &str) -> Result<(), VaultError> {
    let vault = Vault::open(vault_dir, password)?;
    match vault.audit_log_verify() {
        Ok(true) => println!("审计日志完整性验证通过 — 哈希链 + HMAC 均正确"),
        Ok(false) => println!("审计日志完整性验证失败 — 数据可能被篡改"),
        Err(e) => eprintln!("审计日志验证错误: {}", e),
    }
    Ok(())
}

fn cmd_audit_log_export(vault_dir: &Path, password: &str, output: &Path) -> Result<(), VaultError> {
    let vault = Vault::open(vault_dir, password)?;
    match vault.audit_log_export_json() {
        Ok(json) => {
            std::fs::write(output, &json).map_err(VaultError::Io)?;
            println!("审计日志已导出到: {}", output.display());
        }
        Err(e) => eprintln!("审计日志导出错误: {}", e),
    }
    Ok(())
}

// ============================================================
// SM2 命令
// ============================================================

fn cmd_sm2_pubkey(vault_dir: &Path, password: &str) -> Result<(), VaultError> {
    let vault = Vault::open(vault_dir, password)?;
    match vault.get_sm2_pub_key() {
        Some(key) => {
            let hex: String = key.iter().map(|b| format!("{:02x}", b)).collect();
            println!("SM2 公钥 (65 字节, 未压缩格式):");
            println!("  {}", hex);
            println!("  完整 hex ({} 字符):", hex.len());
            println!("  {}", hex);
        }
        None => println!("此保险箱未生成 SM2 密钥对"),
    }
    Ok(())
}

fn cmd_sm2_sign(
    vault_dir: &Path,
    password: &str,
    file: &Path,
    output: &Path,
) -> Result<(), VaultError> {
    let vault = Vault::open(vault_dir, password)?;
    let data = std::fs::read(file).map_err(VaultError::Io)?;
    let sig = vault.sm2_sign(&data)?;
    std::fs::write(output, sig).map_err(VaultError::Io)?;
    let hex: String = sig.iter().map(|b| format!("{:02x}", b)).collect();
    println!("SM2 签名已写入: {}", output.display());
    println!("  签名: {}", hex);
    Ok(())
}

fn cmd_sm2_verify(
    vault_dir: &Path,
    password: &str,
    file: &Path,
    sig_path: &Path,
) -> Result<(), VaultError> {
    let vault = Vault::open(vault_dir, password)?;
    let data = std::fs::read(file).map_err(VaultError::Io)?;
    let sig_bytes = std::fs::read(sig_path).map_err(VaultError::Io)?;
    if sig_bytes.len() != SM2_SIG_BYTES {
        return Err(VaultError::InvalidInput(
            "签名文件必须为 64 字节".to_string(),
        ));
    }
    let mut sig = [0u8; SM2_SIG_BYTES];
    sig.copy_from_slice(&sig_bytes);
    match vault.sm2_verify(&data, &sig)? {
        true => println!("SM2 签名验证通过"),
        false => println!("SM2 签名验证失败"),
    }
    Ok(())
}

// ============================================================
// 文件共享命令
// ============================================================

fn cmd_share_export(
    vault_dir: &Path,
    password: &str,
    blind_index_hex: &str,
    target_pubkey_hex: &str,
    output: &Path,
) -> Result<(), VaultError> {
    let blind_index = parse_hex_blind_index(blind_index_hex)?;
    let vault = Vault::open(vault_dir, password)?;

    // 解析对方 SM2 公钥
    let target_pubkey = parse_sm2_pubkey(target_pubkey_hex)?;

    let pkg = vault.share_export_file(&blind_index, &target_pubkey)?;
    std::fs::write(output, &pkg).map_err(VaultError::Io)?;
    println!("共享包已导出 ({} 字节): {}", pkg.len(), output.display());
    Ok(())
}

fn cmd_share_import(vault_dir: &Path, password: &str, package: &Path) -> Result<(), VaultError> {
    let vault = Vault::open(vault_dir, password)?;
    let pkg = std::fs::read(package).map_err(VaultError::Io)?;
    vault.share_import_file(&pkg)?;
    println!("共享文件已导入: {}", package.display());
    Ok(())
}

fn parse_sm2_pubkey(hex: &str) -> Result<[u8; SM2_PUBKEY_BYTES], VaultError> {
    let hex = hex.trim();
    if hex.len() != SM2_PUBKEY_HEX_LEN {
        return Err(VaultError::InvalidInput(
            "SM2 公钥应为 130 字符十六进制 (65 字节未压缩格式)".to_string(),
        ));
    }
    let mut key = [0u8; SM2_PUBKEY_BYTES];
    for i in 0..SM2_PUBKEY_BYTES {
        let byte_str = &hex[i * 2..i * 2 + 2];
        key[i] = u8::from_str_radix(byte_str, 16)
            .map_err(|_| VaultError::InvalidInput("SM2 公钥包含非法字符".to_string()))?;
    }
    if key[0] != 0x04 {
        return Err(VaultError::InvalidInput(
            "SM2 公钥必须以 04 开头（未压缩格式）".to_string(),
        ));
    }
    Ok(key)
}

// ============================================================
// Shamir KEK 分片/恢复命令
// ============================================================

fn cmd_split_kek(vault_dir: &Path, password: &str, n: u8, t: u8) -> Result<(), VaultError> {
    let vault = Vault::open(vault_dir, password)?;
    let shares = vault.split_kek(n, t)?;

    println!("KEK 已拆分为 {}/{} 份 Shamir 子秘密：", n, t);
    println!("  任意 {} 份可恢复保险箱访问", t);
    println!(
        "  每份格式：1字节索引(01..={:02}) | 16字节KEK (共17字节=34 hex)",
        n
    );
    println!("{}", "-".repeat(60));
    for (i, share) in shares.iter().enumerate() {
        println!("  [{:02}/{:02}] {}", i + 1, n, share);
    }
    println!("{}", "-".repeat(60));
    println!("请安全保管各份子秘密！丢失 {} 份将无法恢复。", n - t + 1);
    Ok(())
}

fn cmd_recover_kek(vault_dir: &Path, t: u8, shares: &[String]) -> Result<(), VaultError> {
    if shares.len() < t as usize {
        return Err(VaultError::InvalidInput(format!(
            "需要至少 {} 份子秘密，提供了 {}",
            t,
            shares.len()
        )));
    }

    // 提示输入新密码（隐藏回显，失败时退出）
    print!("请输入新密码: ");
    std::io::stdout().flush().unwrap();
    let pwd = rpassword::read_password().unwrap_or_else(|e| {
        eprintln!("\n密码输入失败: {}（终端可能不支持隐藏输入）", e);
        std::process::exit(1);
    });
    let new_password = Zeroizing::new(pwd);

    if new_password.is_empty() {
        return Err(VaultError::InvalidInput("密码不能为空".to_string()));
    }

    let _vault = Vault::recover_from_shares(vault_dir, shares, t, &new_password)?;
    println!("KEK 已恢复，保险箱密码已重置");
    Ok(())
}

// ============================================================
// 新增命令（与 GUI 功能对齐）
// ============================================================

fn cmd_rename(
    vault_dir: &Path,
    password: &str,
    blind_index_hex: &str,
    new_name: &str,
) -> Result<(), VaultError> {
    let blind_index = parse_hex_blind_index(blind_index_hex)?;
    let vault = Vault::open(vault_dir, password)?;
    vault.rename_file(&blind_index, new_name)?;
    println!("文件已重命名为: {}", new_name);
    Ok(())
}

fn cmd_cut(
    vault_dir: &Path,
    password: &str,
    blind_index_hex: &str,
    output: &Path,
) -> Result<(), VaultError> {
    let blind_index = parse_hex_blind_index(blind_index_hex)?;
    let vault = Vault::open(vault_dir, password)?;
    // 先导出
    vault.export_file_to(&blind_index, output)?;
    // 再删除
    vault.remove_file(&blind_index)?;
    println!("文件已剪切到: {}（已从保险箱移除）", output.display());
    Ok(())
}

fn cmd_import_folder(vault_dir: &Path, password: &str, folder: &Path) -> Result<(), VaultError> {
    if !folder.is_dir() {
        return Err(VaultError::InvalidInput(format!(
            "路径不是目录: {}",
            folder.display()
        )));
    }
    let vault = Vault::open(vault_dir, password)?;
    let count = vault.import_folder(folder)?;
    println!("文件夹导入完成: {} 个文件", count);
    Ok(())
}

fn cmd_export_directory(
    vault_dir: &Path,
    password: &str,
    vault_path: &str,
    output_dir: &Path,
) -> Result<(), VaultError> {
    let vault = Vault::open(vault_dir, password)?;
    let count = vault.export_directory_to(vault_path, output_dir)?;
    println!("目录导出完成: {} 个文件 → {}", count, output_dir.display());
    Ok(())
}

fn cmd_remove_directory(
    vault_dir: &Path,
    password: &str,
    vault_path: &str,
) -> Result<(), VaultError> {
    let vault = Vault::open(vault_dir, password)?;
    let count = vault.remove_directory(vault_path)?;
    println!("目录删除完成: 已移除 {} 个文件", count);
    Ok(())
}

fn cmd_bench(vault_dir: &Path, password: &str) -> Result<(), VaultError> {
    let _vault = Vault::open(vault_dir, password)?;
    println!("运行基准测试...");
    let mut results = sancove::bench::run_all_benches();
    let io = sancove::bench::run_io_benches();
    results.import_1kb_us = io.import_1kb_us;
    results.export_1kb_us = io.export_1kb_us;
    results.import_1mb_ms = io.import_1mb_ms;
    results.export_1mb_ms = io.export_1mb_ms;
    results.import_10mb_ms = io.import_10mb_ms;
    results.export_10mb_ms = io.export_10mb_ms;
    results.vault_open_ms = io.vault_open_ms;
    results.batch_import_10x1mb_ms = io.batch_import_10x1mb_ms;

    // ── HMAC-SM3 ──
    println!("HMAC-SM3 完整性校验:     {:.1} MB/s", results.hmac_sm3_mbps);
    // ── PBKDF2 ──
    println!("PBKDF2-SM3 密钥派生:");
    println!("  100,000 次:         {:.0} ms", results.pbkdf2_100k_ms);
    println!("  600,000 次:         {:.0} ms", results.pbkdf2_ms);
    // ── SM2 ──
    println!(
        "SM2 公钥密码:         密钥生成 {:.1} ms | 签名 {:.1} ms | 验签 {:.1} ms",
        results.sm2_keygen_ms, results.sm2_sign_ms, results.sm2_verify_ms
    );
    // ── Shamir ──
    println!(
        "Shamir 秘密共享 (KEK): 分片 {:.1} μs | 恢复 {:.1} μs",
        results.shamir_split_us, results.shamir_recover_us
    );
    // ── 文件操作 ──
    println!("全链路文件操作:");
    if let Some(v) = results.import_1kb_us {
        println!("  1KB 导入:  {:.1} μs", v);
    }
    if let Some(v) = results.export_1kb_us {
        println!("  1KB 导出:  {:.1} μs", v);
    }
    if let Some(imp) = results.import_1mb_ms {
        println!("  1MB 导入:  {:.1} ms", imp);
    }
    if let Some(exp) = results.export_1mb_ms {
        println!("  1MB 导出:  {:.1} ms", exp);
    }
    if let Some(imp) = results.import_10mb_ms {
        println!("  10MB 导入: {:.1} ms", imp);
    }
    if let Some(exp) = results.export_10mb_ms {
        println!("  10MB 导出: {:.1} ms", exp);
    }
    if let Some(batch) = results.batch_import_10x1mb_ms {
        println!("  批量 10×1MB: {:.1} ms", batch);
    }
    // ── 保险箱 ──
    println!("保险箱打开（登录）:     {:.0} ms", results.vault_open_ms);
    Ok(())
}

// ============================================================
fn cmd_rename_directory(
    vault_dir: &Path,
    password: &str,
    old_path: &str,
    new_name: &str,
) -> Result<(), VaultError> {
    let vault = Vault::open(vault_dir, password)?;
    let count = vault.rename_directory(old_path, new_name)?;
    println!(
        "目录重命名完成: {} → {}（{} 个文件）",
        old_path, new_name, count
    );
    Ok(())
}

// ============================================================
// 辅助函数
// ============================================================

/// 将 64 字符十六进制字符串解析为 32 字节盲索引
fn parse_hex_blind_index(hex: &str) -> Result<[u8; 32], VaultError> {
    let hex = hex.trim();
    if hex.len() != BLIND_INDEX_HEX_LEN {
        return Err(VaultError::InvalidInput(
            "盲索引应为 64 位十六进制字符串".to_string(),
        ));
    }

    let mut bytes = [0u8; 32];
    for i in 0..32 {
        let byte_str = &hex[i * 2..i * 2 + 2];
        bytes[i] = u8::from_str_radix(byte_str, 16)
            .map_err(|_| VaultError::InvalidInput("盲索引包含非法字符".to_string()))?;
    }
    Ok(bytes)
}
