//! 基于 SM2/SM3/SM4 国密标准的保密文件库 - CLI 入口
//!
//! 所有 CLI 命令通过交互式密码输入（隐藏回显），不支持无交互密码参数。
//!
//! 使用 `sancove --help` 查看所有子命令和参数说明。

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

/// 基于 SM2/SM3/SM4 国密标准的保密文件库
///
/// 支持图形界面（GUI）和命令行（CLI）双模式操作。
/// 所有 CLI 命令通过交互式密码输入（隐藏回显），不支持无交互密码参数。
///
/// 使用示例:
///   sancove gui                              # 启动图形界面
///   sancove create /path/to/vault             # 创建保险箱（需密码二次确认）
///   sancove list /path/to/vault               # 列出文件
///   sancove import /path/to/vault file.pdf    # 导入文件
#[derive(Parser)]
#[command(
    name = "sancove",
    version,
    author = "sereinwalker",
    long_about = None,
)]
struct Cli {
    /// 无子命令时默认启动图形界面
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// 创建新的保险箱
    ///
    /// 在指定目录创建保险箱数据库。密码需二次确认输入。
    #[command(visible_alias = "new")]
    Create {
        #[arg(value_name = "保险箱目录")]
        vault_dir: PathBuf,
    },

    /// 将文件导入保险箱
    ///
    /// 加密文件并存入保险箱。文件路径可以是相对路径或绝对路径。
    #[command(visible_alias = "add")]
    Import {
        #[arg(value_name = "保险箱目录")]
        vault_dir: PathBuf,
        #[arg(value_name = "文件路径")]
        file: PathBuf,
    },

    /// 列出保险箱中的文件
    ///
    /// 显示文件名、大小、时间戳和盲索引（前 16 位供后续操作）。
    #[command(visible_alias = "ls")]
    List {
        #[arg(value_name = "保险箱目录")]
        vault_dir: PathBuf,
    },

    /// 从保险箱导出文件
    ///
    /// 通过盲索引定位文件、验证完整性（HMAC-SM3）后解密输出到指定目录。
    /// 盲索引可通过 `list` 命令获取（前 16 位 + 完整 64 位）。
    #[command(visible_alias = "exp")]
    Export {
        #[arg(value_name = "保险箱目录")]
        vault_dir: PathBuf,
        #[arg(value_name = "盲索引", help = "64 位十六进制盲索引字符串，通过 list 命令获取")]
        blind_index: String,
        #[arg(value_name = "输出目录")]
        output_dir: PathBuf,
    },

    /// 从保险箱移除文件
    ///
    /// 删除文件密文和数据库记录。此操作不可逆。
    #[command(visible_alias = "rm")]
    Remove {
        #[arg(value_name = "保险箱目录")]
        vault_dir: PathBuf,
        #[arg(value_name = "盲索引", help = "64 位十六进制盲索引字符串")]
        blind_index: String,
    },

    /// 重命名文件
    ///
    /// 修改保险箱内文件的显示名称，不影响加密内容。
    #[command(visible_alias = "mv")]
    Rename {
        #[arg(value_name = "保险箱目录")]
        vault_dir: PathBuf,
        #[arg(value_name = "盲索引", help = "64 位十六进制盲索引字符串")]
        blind_index: String,
        #[arg(value_name = "新文件名")]
        new_name: String,
    },

    /// 剪切文件（导出并删除）
    ///
    /// 将文件解密导出到本地文件系统，然后从保险箱移除。
    /// 等价于依次执行 export + remove。
    Cut {
        #[arg(value_name = "保险箱目录")]
        vault_dir: PathBuf,
        #[arg(value_name = "盲索引", help = "64 位十六进制盲索引字符串")]
        blind_index: String,
        #[arg(value_name = "输出路径", help = "导出到本地的文件路径")]
        output: PathBuf,
    },

    /// 导入文件夹（递归导入子目录）
    ///
    /// 递归扫描文件夹内所有文件并导入到保险箱，保持虚拟目录结构。
    #[command(visible_alias = "import-dir")]
    ImportFolder {
        #[arg(value_name = "保险箱目录")]
        vault_dir: PathBuf,
        #[arg(value_name = "文件夹路径")]
        folder: PathBuf,
    },

    /// 导出保险箱目录到本地
    ///
    /// 将保险箱内的虚拟目录树解密导出到本地文件系统。
    /// 虚拟路径为空字符串时导出根目录全部文件。
    #[command(visible_alias = "export-dir")]
    ExportDirectory {
        #[arg(value_name = "保险箱目录")]
        vault_dir: PathBuf,
        #[arg(value_name = "虚拟路径", help = "保险箱内的目录路径，空串=根目录")]
        vault_path: String,
        #[arg(value_name = "输出目录")]
        output_dir: PathBuf,
    },

    /// 删除保险箱目录
    ///
    /// 删除虚拟目录及其下所有文件。此操作不可逆。
    #[command(visible_alias = "rmdir")]
    RemoveDirectory {
        #[arg(value_name = "保险箱目录")]
        vault_dir: PathBuf,
        #[arg(value_name = "虚拟路径", help = "保险箱内要删除的目录路径")]
        vault_path: String,
    },

    /// 重命名保险箱目录
    ///
    /// 修改虚拟目录的名称。
    #[command(visible_alias = "mvdir")]
    RenameDirectory {
        #[arg(value_name = "保险箱目录")]
        vault_dir: PathBuf,
        #[arg(value_name = "旧路径", help = "保险箱内目录的当前路径")]
        old_path: String,
        #[arg(value_name = "新名称", help = "目录的新名称（仅名称，不含路径）")]
        new_name: String,
    },

    /// 运行性能基准测试
    ///
    /// 测试 SM4 S-Box/T-Table/CT-Bitslice、CBC、HMAC-SM3、PBKDF2-SM3、
    /// SM2、Shamir、全链路 I/O（1KB/1MB/10MB）、保险箱打开等指标。
    #[command(visible_alias = "benchmark")]
    Bench {
        #[arg(value_name = "保险箱目录", help = "用于 I/O 基准测试")]
        vault_dir: PathBuf,
    },

    /// 启动图形界面
    ///
    /// 不带路径时打开登录界面由用户输入；带路径时直接打开指定保险箱（文件关联用）。
    Gui {
        #[arg(value_name = "保险箱目录")]
        vault_dir: Option<PathBuf>,
    },

    /// 修改保险箱密码
    ///
    /// 输入旧密码验证身份，设置新密码（需二次确认）。
    /// 更改后所有文件 DEK 将用新 KEK 重新加密。
    #[command(visible_alias = "passwd")]
    ChangePassword {
        #[arg(value_name = "保险箱目录")]
        vault_dir: PathBuf,
    },

    /// 备份保险箱
    ///
    /// 将保险箱数据库和密文文件完整复制到备份目录。
    #[command(visible_alias = "bak")]
    Backup {
        #[arg(value_name = "保险箱目录")]
        vault_dir: PathBuf,
        #[arg(value_name = "备份目录")]
        backup_dir: PathBuf,
    },

    /// 从备份恢复保险箱
    ///
    /// 从备份目录恢复保险箱到目标目录。会覆盖目标目录已有数据，需确认。
    /// 恢复前验证备份密码（校验 HMAC 完整性标签）。
    #[command(visible_alias = "rest")]
    Restore {
        #[arg(value_name = "备份目录")]
        backup_dir: PathBuf,
        #[arg(value_name = "目标目录", help = "恢复到的保险箱存储目录")]
        vault_dir: PathBuf,
    },

    /// 查看审计日志
    ///
    /// 显示最近 50 条审计日志记录（操作类型、时间戳、payload）。
    #[command(visible_alias = "audit")]
    AuditLog {
        #[arg(value_name = "保险箱目录")]
        vault_dir: PathBuf,
    },

    /// 验证审计日志完整性
    ///
    /// 校验 SM3 哈希链 + HMAC-SM3 双重完整性保护。
    /// 返回验证通过或数据被篡改。
    #[command(visible_alias = "audit-verify")]
    AuditLogVerify {
        #[arg(value_name = "保险箱目录")]
        vault_dir: PathBuf,
    },

    /// 导出审计日志为 JSON
    ///
    /// 将全部审计日志导出为 JSON 格式文件。
    #[command(visible_alias = "audit-export")]
    AuditLogExport {
        #[arg(value_name = "保险箱目录")]
        vault_dir: PathBuf,
        #[arg(value_name = "输出文件", help = "JSON 输出路径")]
        output: PathBuf,
    },

    /// 显示 SM2 公钥
    ///
    /// 输出保险箱 SM2 公钥（65 字节未压缩格式，130 字符 hex）。
    #[command(visible_alias = "pubkey")]
    Sm2Pubkey {
        #[arg(value_name = "保险箱目录")]
        vault_dir: PathBuf,
    },

    /// 使用 SM2 签名文件
    ///
    /// 用保险箱 SM2 私钥对文件签名，输出 64 字节原始签名。
    #[command(visible_alias = "sign")]
    Sm2Sign {
        #[arg(value_name = "保险箱目录")]
        vault_dir: PathBuf,
        #[arg(value_name = "待签名文件")]
        file: PathBuf,
        #[arg(value_name = "签名输出", help = "签名文件输出路径（64 字节原始签名）")]
        output: PathBuf,
    },

    /// 使用 SM2 验证签名
    ///
    /// 用保险箱 SM2 公钥验证文件的 64 字节原始签名。
    #[command(visible_alias = "verify-sig")]
    Sm2Verify {
        #[arg(value_name = "保险箱目录")]
        vault_dir: PathBuf,
        #[arg(value_name = "原始文件")]
        file: PathBuf,
        #[arg(value_name = "签名文件", help = "64 字节签名文件路径")]
        signature: PathBuf,
    },

    /// 导出共享文件（用对方 SM2 公钥加密 DEK）
    ///
    /// 将文件用接收方 SM2 公钥重新加密 DEK，生成可传输的共享包。
    /// 接收方用其保险箱 SM2 私钥解密导入。
    #[command(visible_alias = "share")]
    ShareExport {
        #[arg(value_name = "保险箱目录")]
        vault_dir: PathBuf,
        #[arg(value_name = "盲索引", help = "64 位十六进制盲索引字符串")]
        blind_index: String,
        #[arg(value_name = "对方公钥", help = "接收方 SM2 公钥（130 字符 hex，65 字节未压缩格式）")]
        target_pubkey: String,
        #[arg(value_name = "共享包", help = "共享包输出路径（二进制格式）")]
        output: PathBuf,
    },

    /// 导入共享文件
    ///
    /// 用本保险箱 SM2 私钥解密共享包中的 DEK，将文件导入到保险箱。
    #[command(visible_alias = "share-in")]
    ShareImport {
        #[arg(value_name = "保险箱目录")]
        vault_dir: PathBuf,
        #[arg(value_name = "共享包", help = "共享包文件路径")]
        package: PathBuf,
    },

    /// 将 KEK 拆分为 Shamir 子秘密（灾备恢复用）
    ///
    /// 将当前 KEK 拆分为 n 份 Shamir 子秘密，任意 t 份可恢复保险箱访问权限。
    /// 每份为 34 字符 hex（1 字节索引 + 16 字节 KEK），请安全保管各份子秘密。
    #[command(visible_alias = "split")]
    SplitKek {
        #[arg(value_name = "保险箱目录")]
        vault_dir: PathBuf,
        #[arg(short = 'n', long, value_name = "总份数", default_value = "5", help = "Shamir 子秘密总份数")]
        n: u8,
        #[arg(short = 't', long, value_name = "门限", default_value = "3", help = "恢复所需最少份数（门限值）")]
        t: u8,
    },

    /// 从 Shamir 子秘密重构 KEK 并设置新密码
    ///
    /// 提供 t 份子秘密 hex 字符串，重构 KEK 并设置新的保险箱密码。
    /// 每份子秘密为 34 字符 hex（由 split-kek 命令生成）。
    #[command(visible_alias = "recover")]
    RecoverKek {
        #[arg(value_name = "保险箱目录")]
        vault_dir: PathBuf,
        #[arg(short = 't', long, value_name = "门限", help = "恢复所需的最少子秘密份数")]
        t: u8,
        #[arg(value_name = "子秘密", required = true, num_args = 1.., help = "Shamir 子秘密 hex 字符串（每份 34 字符，至少提供 t 份）")]
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

    // 无子命令时默认启动 GUI（双击 exe 直接进图形界面）
    let command = cli.command.unwrap_or(Command::Gui { vault_dir: None });

    let is_gui = matches!(&command, Command::Gui { .. });
    let password: Zeroizing<String> = if is_gui {
        Zeroizing::new(String::new())
    } else {
        read_password("请输入保险箱密码: ")
    };

    let result = match &command {
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
