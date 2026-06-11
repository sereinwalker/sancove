//! VaultApp 主结构体定义、默认实现及启动入口

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::AtomicU32;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

use crate::bench;
use eframe::egui;

use super::task::TaskResult;
use super::types::{AuditLogEntryDisplay, FileEntry, ImportFileItem, configure_fonts};

/// 主窗口默认尺寸
const WINDOW_INNER_SIZE: [f32; 2] = [820.0, 600.0];
/// 主窗口最小尺寸
const WINDOW_MIN_SIZE: [f32; 2] = [640.0, 480.0];

// ============================================================
// GUI 应用主结构体
// ============================================================

pub struct VaultApp {
    // ---- 登录 ----
    pub(super) vault_path: String,
    pub(super) password: String,
    pub(super) password_confirm: String,
    pub(super) logged_in: bool,
    pub(super) vault: Option<Arc<Mutex<crate::vault::Vault>>>,
    pub(super) vault_dir: PathBuf,
    pub(super) login_error: String,
    pub(super) login_busy: bool,
    pub(super) login_channel:
        Option<mpsc::Receiver<Result<Arc<Mutex<crate::vault::Vault>>, String>>>,

    // ---- 文件列表 ----
    pub(super) files: Vec<FileEntry>,
    pub(super) search_query: String,
    pub(super) current_vault_dir: String,
    pub(super) last_logged_search: String,

    // ---- 导出 ----
    pub(super) export_output_dir: String,

    // ---- 基准测试 ----
    pub(super) show_bench: bool,
    pub(super) bench_results: Option<bench::BenchResults>,
    pub(super) bench_pending: Arc<Mutex<Option<bench::BenchResults>>>,
    pub(super) bench_running: bool,

    // ---- 密码强度 ----
    pub(super) password_strength: Option<crate::crypto::password_strength::PasswordStrength>,

    // ---- 修改密码 ----
    pub(super) show_change_password: bool,
    pub(super) change_password_pending: bool,
    pub(super) change_old_password: String,
    pub(super) change_new_password: String,
    pub(super) change_new_password_confirm: String,

    // ---- 移除 ----
    pub(super) confirm_remove: Option<[u8; 32]>,
    pub(super) confirm_remove_filename: String,
    pub(super) confirm_remove_dir: Option<String>,
    pub(super) confirm_remove_dir_name: String,

    // ---- 重命名 ----
    pub(super) rename_target: Option<[u8; 32]>,
    pub(super) rename_old_name: String,
    pub(super) rename_new_name: String,
    pub(super) rename_dir: Option<String>,
    pub(super) rename_dir_new_name: String,

    // ---- 批量操作 ----
    pub(super) selected_indices: HashSet<[u8; 32]>,
    pub(super) show_batch_remove_confirm: bool,
    pub(super) batch_remove_filenames: Vec<String>,

    // ---- 批量导入确认 ----
    pub(super) show_batch_import_confirm: bool,
    pub(super) batch_import_files: Vec<ImportFileItem>,
    pub(super) import_overwrite_choices: std::collections::HashMap<String, bool>,

    // ---- 导出覆盖确认 ----
    pub(super) show_export_overwrite_confirm: bool,
    pub(super) export_overwrite_files: Vec<String>,
    pub(super) export_overwrite_selected: Option<Vec<[u8; 32]>>,
    pub(super) export_overwrite_dir: String,
    pub(super) export_overwrite_choices: std::collections::HashMap<String, bool>,
    pub(super) export_exists_set: std::collections::HashSet<String>,

    // ---- 导入确认 ----
    pub(super) import_existing_in_vault: std::collections::HashSet<String>,

    // ---- 后台任务 ----
    pub(super) task_busy: bool,
    pub(super) task_busy_message: String,
    pub(super) pending_result: TaskResult,
    pub(super) status_message: Option<(bool, String)>,
    pub(super) status_set_at: Option<std::time::Instant>,

    // ---- 密码可见性 ----
    pub(super) password_visible: bool,
    pub(super) change_password_visible: bool,

    // ---- 批量导入进度 ----
    pub(super) batch_import_progress: Option<Arc<AtomicU32>>,
    pub(super) batch_import_total: usize,

    // ---- 交互式错误处理（批量操作中遇到失败由用户选择跳过/取消）----
    pub(super) batch_decision_tx: Option<std::sync::mpsc::Sender<super::ops::BatchDecision>>,
    pub(super) batch_error_pending:
        Option<std::sync::Arc<std::sync::Mutex<Option<super::ops::BatchErrorInfo>>>>,

    // ---- 审计日志 ----
    pub(super) show_audit_log: bool,
    pub(super) audit_log_entries: Vec<AuditLogEntryDisplay>,

    // ---- SM2 签名/验签 ----
    pub(super) show_sm2_sign: bool,
    pub(super) show_sm2_verify: bool,

    // ---- KEK 分片 ----
    pub(super) show_kek_split: bool,
    pub(super) kek_split_n: String,
    pub(super) kek_split_t: String,
    pub(super) kek_split_result: Vec<String>,

    // ---- KEK 恢复 ----
    pub(super) show_kek_recover: bool,
    pub(super) kek_recover_t: String,
    pub(super) kek_recover_shares: Vec<String>,
    pub(super) kek_recover_new_password: String,
    pub(super) kek_recover_confirm_password: String,

    // ---- 目录导出冲突检查 ----
    pub(super) show_dir_export_conflict: bool,
    pub(super) dir_export_cut_mode: bool,           // true=剪切, false=纯导出
    pub(super) dir_export_vault_dir: String,        // vault 内的目录路径
    pub(super) dir_export_base_path: PathBuf,       // 输出根路径 = 用户选择的目标路径
    pub(super) dir_export_items: Vec<(String, String, [u8; 32])>,  // (full_vault_path, relative_path, blind_index)
    pub(super) dir_export_choices: std::collections::HashMap<String, bool>,

    // ---- 后缀修改确认对话框 ----
    pub(super) show_ext_warning: bool,
    pub(super) ext_warning_old_name: String,
    pub(super) ext_warning_new_name: String,
    // 重命名待确认 (blind_index, new_name)
    pub(super) ext_warning_rename: Option<([u8; 32], String)>,
    // 导出/剪切待确认 (save_path, blind_index, is_cut)
    pub(super) ext_warning_export: Option<(std::path::PathBuf, [u8; 32], bool)>,
    pub(super) ext_warning_export_vault:
        Option<std::sync::Arc<std::sync::Mutex<crate::vault::Vault>>>,
    pub(super) ext_warning_export_result: Option<super::task::TaskResult>,
}

impl Default for VaultApp {
    fn default() -> Self {
        Self {
            vault_path: String::new(),
            password: String::new(),
            password_confirm: String::new(),
            logged_in: false,
            vault: None,
            vault_dir: PathBuf::new(),
            login_error: String::new(),
            login_busy: false,
            login_channel: None,
            files: Vec::new(),
            search_query: String::new(),
            current_vault_dir: String::new(),
            last_logged_search: String::new(),
            export_output_dir: String::new(),
            show_bench: false,
            bench_results: None,
            bench_pending: Arc::new(Mutex::new(None)),
            bench_running: false,
            password_strength: None,
            show_change_password: false,
            change_password_pending: false,
            change_old_password: String::new(),
            change_new_password: String::new(),
            change_new_password_confirm: String::new(),
            confirm_remove: None,
            confirm_remove_filename: String::new(),
            confirm_remove_dir: None,
            confirm_remove_dir_name: String::new(),
            rename_target: None,
            rename_old_name: String::new(),
            rename_new_name: String::new(),
            rename_dir: None,
            rename_dir_new_name: String::new(),
            selected_indices: HashSet::new(),
            show_batch_remove_confirm: false,
            batch_remove_filenames: Vec::new(),
            show_batch_import_confirm: false,
            batch_import_files: Vec::new(),
            import_overwrite_choices: std::collections::HashMap::new(),
            show_export_overwrite_confirm: false,
            export_overwrite_files: Vec::new(),
            export_overwrite_selected: None,
            export_overwrite_dir: String::new(),
            export_overwrite_choices: std::collections::HashMap::new(),
            export_exists_set: std::collections::HashSet::new(),
            import_existing_in_vault: std::collections::HashSet::new(),
            task_busy: false,
            task_busy_message: String::new(),
            pending_result: Arc::new(Mutex::new(None)),
            status_message: None,
            status_set_at: None,
            password_visible: false,
            change_password_visible: false,
            batch_import_progress: None,
            batch_import_total: 0,
            batch_decision_tx: None,
            batch_error_pending: None,
            show_audit_log: false,
            audit_log_entries: Vec::new(),
            show_sm2_sign: false,
            show_sm2_verify: false,
            show_kek_split: false,
            kek_split_n: String::new(),
            kek_split_t: String::new(),
            kek_split_result: Vec::new(),
            show_kek_recover: false,
            kek_recover_t: String::new(),
            kek_recover_shares: Vec::new(),
            kek_recover_new_password: String::new(),
            kek_recover_confirm_password: String::new(),
            show_dir_export_conflict: false,
            dir_export_cut_mode: false,
            dir_export_vault_dir: String::new(),
            dir_export_base_path: PathBuf::new(),
            dir_export_items: Vec::new(),
            dir_export_choices: std::collections::HashMap::new(),
            show_ext_warning: false,
            ext_warning_old_name: String::new(),
            ext_warning_new_name: String::new(),
            ext_warning_rename: None,
            ext_warning_export: None,
            ext_warning_export_vault: None,
            ext_warning_export_result: None,
        }
    }
}

impl VaultApp {
    /// 创建并启动 GUI 应用
    pub fn run() -> Result<(), eframe::Error> {
        Self::run_with_vault(&std::path::PathBuf::new())
    }

    /// 创建并启动 GUI 应用（指定保险箱路径，文件关联时使用）
    pub fn run_with_vault(vault_dir: &std::path::Path) -> Result<(), eframe::Error> {
        let options = eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_inner_size(WINDOW_INNER_SIZE)
                .with_min_inner_size(WINDOW_MIN_SIZE),
            ..Default::default()
        };

        let vault_path_str = vault_dir.to_string_lossy().to_string();

        eframe::run_native(
            "基于国密算法的保密文件库",
            options,
            Box::new(move |cc| {
                configure_fonts(&cc.egui_ctx);
                // 默认箭头光标，仅 TextEdit 输入框显示 I 型光标
                cc.egui_ctx.style_mut(|s| s.interaction.selectable_labels = false);
                let mut app = Self::default();
                app.vault_path = vault_path_str;
                Box::new(app)
            }),
        )
    }
}
