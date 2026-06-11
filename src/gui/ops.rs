//! GUI 后台操作：导入、导出、删除、剪切、重命名、状态管理
//!
//! # 操作语义
//!
//! - **导入**：复制文件到保险箱（保留原文件），故障文件跳过/继续
//! - **导出**：从保险箱复制到磁盘（纯读操作），不修改保险箱状态
//! - **剪切**：导出后删除（先复制到磁盘，再从保险箱移除）
//! - **删除**：从保险箱永久移除（不可恢复）
//!
//! # 事务模型
//!
//! 每个 vault 方法内部使用 SAVEPOINT 保证单操作原子性。
//! 批量操作无需外层事务——各文件独立提交，失败文件仅回滚自身。

use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use eframe::egui;

use super::app::VaultApp;
use super::task::{reset_pending, run_task_mut, set_pending, spawn_task, take_pending, zeroize_password_string};
use super::types::{ImportFileItem, scan_folder_for_items};
use crate::audit_log::AuditEntryType;

// ============================================================
// 交互式批处理错误处理类型
// ============================================================

/// 用户对批量操作中失败文件的选择
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum BatchDecision {
    /// 跳过当前失败文件，继续处理下一个
    Skip,
    /// 取消整个批量操作
    Cancel,
}

/// 传递给 UI 的批处理错误信息
#[derive(Clone, Debug)]
pub struct BatchErrorInfo {
    /// 当前失败的文件名
    pub file_name: String,
    /// 错误描述
    pub error_message: String,
    /// 已处理/总共 (done, total)
    pub progress: (u32, u32),
}

impl VaultApp {
    // -------- 状态信息 --------

    pub(super) fn set_status_error(&mut self, msg: &str) {
        set_pending(&self.pending_result, Err(msg.to_string()));
    }

    /// 记录 GUI 操作到审计日志
    pub(super) fn gui_log(&self, entry_type: AuditEntryType, payload: &str) {
        if let Some(ref vault_arc) = self.vault
            && let Ok(v) = vault_arc.lock()
        {
            v.log_audit_event(entry_type, payload.as_bytes());
        }
    }

    /// 检查后台任务是否完成，消费结果
    pub(super) fn check_pending_result(&mut self) {
        let result = take_pending(&self.pending_result);
        if let Some(result) = result {
            self.task_busy = false;
            self.task_busy_message.clear();
            match result {
                Ok(msg) => {
                    let log_msg = if msg.len() > 120 {
                        format!("{}...", &msg[..120])
                    } else {
                        msg.clone()
                    };
                    self.gui_log(AuditEntryType::GuiAction, &log_msg);
                    self.status_message = Some((true, msg.clone()));
                    self.status_set_at = Some(std::time::Instant::now());
                    self.refresh_files();
                    if msg.contains("导出") {
                        self.selected_indices.clear();
                    }
                    if self.change_password_pending {
                        self.show_change_password = false;
                        self.change_password_pending = false;
                        zeroize_password_string(&mut self.change_old_password);
                        zeroize_password_string(&mut self.change_new_password);
                        zeroize_password_string(&mut self.change_new_password_confirm);
                    }
                }
                Err(msg) => {
                    self.gui_log(AuditEntryType::GuiAction, &format!("操作失败: {}", msg));
                    self.status_message = Some((false, msg));
                    self.status_set_at = Some(std::time::Instant::now());
                }
            }
        }
    }

    // -------- 批量导入 --------

    /// 选择批量导入文件
    pub(super) fn start_batch_import(&mut self) {
        let files = match rfd::FileDialog::new()
            .set_title("选择要批量导入的文件")
            .pick_files()
        {
            Some(f) => f,
            None => return,
        };
        if files.is_empty() {
            self.set_status_error("未选择任何文件");
            return;
        }
        self.batch_import_files = files
            .iter()
            .map(|f| {
                let name = f
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unnamed_file")
                    .to_string();
                ImportFileItem {
                    source: f.clone(),
                    vault_path: name,
                }
            })
            .collect();
        self.init_batch_import_ui();
    }

    pub(super) fn init_batch_import_ui(&mut self) {
        self.import_overwrite_choices.clear();
        self.import_existing_in_vault.clear();
        let existing: HashSet<&str> = self.files.iter().map(|f| f.filename.as_str()).collect();
        for item in &self.batch_import_files {
            self.import_overwrite_choices
                .insert(item.vault_path.clone(), true);
            if existing.contains(item.vault_path.as_str()) {
                self.import_existing_in_vault
                    .insert(item.vault_path.clone());
            }
        }
        self.show_batch_import_confirm = true;
    }

    /// 执行批量导入
    ///
    /// 每个文件独立调用 `import_file_as`（各自 SAVEPOINT 保护）。
    /// 遇到失败文件时通知 UI 层弹出对话框，由用户选择「跳过」继续或「取消」。
    /// 导入后原文件保留在磁盘上。
    pub(super) fn execute_batch_import(&mut self, ctx: &egui::Context) {
        let items = std::mem::take(&mut self.batch_import_files);
        let overwrite_choices = std::mem::take(&mut self.import_overwrite_choices);
        self.import_existing_in_vault.clear();
        if items.is_empty() {
            self.set_status_error("未选择任何文件");
            return;
        }

        let checked: HashSet<String> = overwrite_choices
            .iter()
            .filter(|&(_, &v)| v)
            .map(|(k, _)| k.clone())
            .collect();
        let existing_vault: std::collections::HashMap<String, [u8; 32]> = self
            .files
            .iter()
            .map(|f| (f.filename.clone(), f.blind_index))
            .collect();

        let vault = match &self.vault {
            Some(v) => v.clone(),
            None => return,
        };
        let result = Arc::clone(&self.pending_result);
        reset_pending(&result);

        let total = items.len();
        let progress = Arc::new(AtomicU32::new(0));
        self.batch_import_progress = Some(progress.clone());
        self.batch_import_total = total;
        self.task_busy = true;
        self.task_busy_message = format!("正在导入 {} 个文件...", total);

        // 交互式错误处理通道
        let (decision_tx, decision_rx) = std::sync::mpsc::channel::<BatchDecision>();
        let pending_error = Arc::new(std::sync::Mutex::new(None::<BatchErrorInfo>));
        self.batch_decision_tx = Some(decision_tx);
        self.batch_error_pending = Some(pending_error.clone());

        let ctx_clone = ctx.clone();
        std::thread::spawn(move || {
            let v = match vault.lock() {
                Ok(v) => v,
                Err(e) => {
                    set_pending(&result, Err(format!("保险箱访问错误: {}", e)));
                    ctx_clone.request_repaint();
                    return;
                }
            };
            let mut ok = 0u32;
            let mut overwritten = 0u32;
            let mut skipped = 0u32;
            let mut errors = Vec::new();
            let mut cancelled = false;

            for item in items.iter() {
                if cancelled {
                    break;
                }
                if !checked.contains(&item.vault_path) {
                    skipped += 1;
                    progress.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let old_bi = existing_vault.get(&item.vault_path).copied();
                match v.import_file_as(&item.source, &item.vault_path) {
                    Ok(()) => {
                        // 导入成功后再删旧文件（防止导入失败时丢失原文件）
                        if let Some(old_bi) = old_bi {
                            match v.remove_file(&old_bi) {
                                Ok(()) => overwritten += 1,
                                Err(e) => {
                                    eprintln!("警告: 导入成功但删除旧文件失败: {}", e);
                                }
                            }
                        }
                        ok += 1;
                    }
                    Err(e) => {
                        // 导入失败，旧文件保留不变
                        // 通知 UI 层显示错误对话框
                        *pending_error.lock().unwrap() = Some(BatchErrorInfo {
                            file_name: item.vault_path.clone(),
                            error_message: e.to_string(),
                            progress: (ok + errors.len() as u32, total as u32),
                        });
                        ctx_clone.request_repaint();

                        // 等待用户选择（阻塞当前线程）
                        match decision_rx.recv() {
                            Ok(BatchDecision::Skip) => {
                                errors.push(format!("{}: {}", item.vault_path, e));
                            }
                            Ok(BatchDecision::Cancel) => {
                                errors.push(format!("{}: {}（已取消）", item.vault_path, e));
                                cancelled = true;
                            }
                            Err(_) => {
                                // 通道关闭 = 窗口关闭，停止处理
                                errors.push(format!("{}: {}（通道关闭）", item.vault_path, e));
                                cancelled = true;
                            }
                        }
                    }
                }
                progress.fetch_add(1, Ordering::Relaxed);
            }

            // 清理错误状态
            *pending_error.lock().unwrap() = None;

            if errors.is_empty() {
                let mut extra_parts = Vec::new();
                if overwritten > 0 {
                    extra_parts.push(format!("覆盖 {} 个", overwritten));
                }
                if skipped > 0 {
                    extra_parts.push(format!("跳过 {} 个", skipped));
                }
                let details = if extra_parts.is_empty() {
                    String::new()
                } else {
                    format!("（{}）", extra_parts.join("，"))
                };
                set_pending(&result, Ok(format!("导入完成: {} 个文件{}", ok, details)));
            } else {
                let err_summary = errors
                    .iter()
                    .take(3)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("; ");
                let extra = if errors.len() > 3 {
                    format!("... (共 {} 个错误)", errors.len())
                } else {
                    String::new()
                };
                set_pending(
                    &result,
                    Ok(format!(
                        "! 导入 {}/{} 成功 | 失败: {}",
                        ok,
                        total,
                        err_summary + &extra
                    )),
                );
            }
            ctx_clone.request_repaint();
        });
    }

    /// 选择文件夹扫描
    pub(super) fn start_folder_import(&mut self) {
        let folder = match rfd::FileDialog::new()
            .set_title("选择要导入的文件夹")
            .pick_folder()
        {
            Some(f) => f,
            None => return,
        };
        let mut items = Vec::new();
        scan_folder_for_items(&folder, &mut items);
        if items.is_empty() {
            self.set_status_error("目录中未找到任何文件");
            return;
        }
        self.batch_import_files = items;
        self.init_batch_import_ui();
    }

    // -------- 批量导出/剪切（共享 UI 准备）--------

    /// 批量导出/剪切的 UI 前置准备（目录验证、文件列表、choices 初始化）
    ///
    /// `action_name` 用于错误提示（"导出"或"导出并移除"），返回 `false` 表示准备失败。
    fn prepare_batch_export_cut_ui(&mut self, action_name: &str) -> bool {
        let output_dir = self.export_output_dir.trim().to_string();
        if output_dir.is_empty() {
            self.set_status_error("请先设置输出目录");
            return false;
        }
        if !Path::new(&output_dir).is_dir() {
            self.set_status_error("输出目录不存在或不是目录");
            return false;
        }

        let selected: Vec<[u8; 32]> = self.selected_indices.iter().copied().collect();
        if selected.is_empty() {
            self.set_status_error(&format!("请先选择要{}的文件", action_name));
            return false;
        }

        let all_names: Vec<String> = self
            .files
            .iter()
            .filter(|f| self.selected_indices.contains(&f.blind_index))
            .map(|f| f.filename.clone())
            .collect();

        self.export_overwrite_choices.clear();
        self.export_exists_set.clear();
        for name in &all_names {
            self.export_overwrite_choices.insert(name.clone(), true);
            if Path::new(&output_dir).join(name).exists() {
                self.export_exists_set.insert(name.clone());
            }
        }
        self.export_overwrite_files = all_names;
        self.export_overwrite_selected = Some(selected);
        self.export_overwrite_dir = output_dir;
        true
    }

    /// 批量剪切的前置 UI 准备（与批量导出共享确认对话框）
    pub(super) fn start_batch_cut(&mut self) {
        if self.prepare_batch_export_cut_ui("导出并移除") {
            self.show_export_overwrite_confirm = true;
        }
    }

    // -------- 批量导出（纯导出，不删除） --------

    pub(super) fn start_batch_export(&mut self) {
        if self.prepare_batch_export_cut_ui("导出") {
            self.show_export_overwrite_confirm = true;
        }
    }

    /// 执行批量导出（纯导出——不删除源文件）
    /// 遇到失败文件时通知 UI 层，由用户选择跳过/取消。
    pub(super) fn do_batch_export(
        &mut self,
        ctx: &egui::Context,
        selected: Vec<[u8; 32]>,
        filenames: Vec<String>,
        output_dir: String,
    ) {
        let vault = match &self.vault {
            Some(v) => v.clone(),
            None => return,
        };
        let result = Arc::clone(&self.pending_result);
        reset_pending(&result);
        let total = selected.len();
        self.task_busy = true;
        self.task_busy_message = format!("正在批量导出 {} 个文件...", total);
        let out_dir = output_dir.clone();

        let (decision_tx, decision_rx) = std::sync::mpsc::channel::<BatchDecision>();
        let pending_error = Arc::new(std::sync::Mutex::new(None::<BatchErrorInfo>));
        self.batch_decision_tx = Some(decision_tx);
        self.batch_error_pending = Some(pending_error.clone());

        let ctx_clone = ctx.clone();
        std::thread::spawn(move || {
            let v = match vault.lock() {
                Ok(v) => v,
                Err(_) => {
                    set_pending(&result, Err("保险箱访问错误".to_string()));
                    ctx_clone.request_repaint();
                    return;
                }
            };

            let mut ok = 0u32;
            let mut export_errors = Vec::new();
            let mut cancelled = false;

            for (i, idx) in selected.iter().enumerate() {
                if cancelled {
                    break;
                }

                match v.export_file(idx, Path::new(&out_dir)) {
                    Ok(()) => ok += 1,
                    Err(e) => {
                        let fname = filenames
                            .get(i)
                            .cloned()
                            .unwrap_or_else(|| format!("索引 {}", i));
                        *pending_error.lock().unwrap() = Some(BatchErrorInfo {
                            file_name: fname.clone(),
                            error_message: e.to_string(),
                            progress: (ok + export_errors.len() as u32, total as u32),
                        });
                        ctx_clone.request_repaint();

                        match decision_rx.recv() {
                            Ok(BatchDecision::Skip) => {
                                export_errors.push(format!("{}: {}", fname, e));
                            }
                            Ok(BatchDecision::Cancel) => {
                                export_errors.push(format!("{}: {}（已取消）", fname, e));
                                cancelled = true;
                            }
                            Err(_) => {
                                export_errors.push(format!("{}: {}（通道关闭）", fname, e));
                                cancelled = true;
                            }
                        }
                    }
                }
            }

            *pending_error.lock().unwrap() = None;

            if export_errors.is_empty() {
                set_pending(
                    &result,
                    Ok(format!("导出完成: {} 个文件 → {}", ok, out_dir)),
                );
            } else {
                let s = export_errors
                    .iter()
                    .take(3)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("; ");
                let extra = if export_errors.len() > 3 {
                    format!("... (共 {} 个错误)", export_errors.len())
                } else {
                    String::new()
                };
                if ok > 0 {
                    set_pending(
                        &result,
                        Ok(format!(
                            "! 导出 {}/{} 成功 | 失败: {}",
                            ok,
                            total,
                            s + &extra
                        )),
                    );
                } else {
                    set_pending(&result, Err(format!("导出全部失败: {}", s + &extra)));
                }
            }
            ctx_clone.request_repaint();
        });
    }

    // -------- 批量剪切（导出+删除） --------

    /// 批量剪切：先导出到磁盘，成功后从保险箱移除
    pub(super) fn do_batch_cut(
        &mut self,
        ctx: &egui::Context,
        selected: Vec<[u8; 32]>,
        filenames: Vec<String>,
        output_dir: String,
    ) {
        let vault = match &self.vault {
            Some(v) => v.clone(),
            None => return,
        };
        let result = Arc::clone(&self.pending_result);
        reset_pending(&result);
        let total = selected.len();
        self.task_busy = true;
        self.task_busy_message = format!("正在批量剪切 {} 个文件...", total);
        let out_dir = output_dir.clone();

        let (decision_tx, decision_rx) = std::sync::mpsc::channel::<BatchDecision>();
        let pending_error = Arc::new(std::sync::Mutex::new(None::<BatchErrorInfo>));
        self.batch_decision_tx = Some(decision_tx);
        self.batch_error_pending = Some(pending_error.clone());

        let ctx_clone = ctx.clone();
        std::thread::spawn(move || {
            let v = match vault.lock() {
                Ok(v) => v,
                Err(_) => {
                    set_pending(&result, Err("保险箱访问错误".to_string()));
                    ctx_clone.request_repaint();
                    return;
                }
            };

            // 第一阶段：导出到磁盘（交互式错误处理）
            let mut export_ok = Vec::new();
            let mut export_errors = Vec::new();
            let mut cancelled = false;

            for (i, idx) in selected.iter().enumerate() {
                if cancelled {
                    break;
                }

                match v.export_file(idx, Path::new(&out_dir)) {
                    Ok(()) => export_ok.push(*idx),
                    Err(e) => {
                        let fname = filenames
                            .get(i)
                            .cloned()
                            .unwrap_or_else(|| format!("索引 {}", i));
                        *pending_error.lock().unwrap() = Some(BatchErrorInfo {
                            file_name: fname.clone(),
                            error_message: format!("导出失败: {}", e),
                            progress: (i as u32, total as u32),
                        });
                        ctx_clone.request_repaint();

                        match decision_rx.recv() {
                            Ok(BatchDecision::Skip) => {
                                export_errors.push(format!("{}: {}", fname, e))
                            }
                            Ok(BatchDecision::Cancel) => {
                                export_errors.push(format!("{}: {}（已取消）", fname, e));
                                cancelled = true;
                            }
                            Err(_) => {
                                export_errors.push(format!("{}: {}（通道关闭）", fname, e));
                                cancelled = true;
                            }
                        }
                    }
                }
            }

            *pending_error.lock().unwrap() = None;

            if cancelled && export_ok.is_empty() {
                let s = export_errors
                    .iter()
                    .take(3)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("; ");
                set_pending(&result, Err(format!("剪切已取消: {}", s)));
                ctx_clone.request_repaint();
                return;
            }

            // 第二阶段：删除已导出文件（SAVEPOINT 保护）
            if !export_ok.is_empty() {
                let mut delete_errors: Vec<String> = Vec::new();
                for idx in &export_ok {
                    if let Err(e) = v.remove_file(idx) {
                        delete_errors.push(format!("删除失败: {}", e));
                    }
                }

                if !delete_errors.is_empty() {
                    let s = delete_errors
                        .iter()
                        .take(3)
                        .cloned()
                        .collect::<Vec<_>>()
                        .join("; ");
                    set_pending(
                        &result,
                        Err(format!(
                            "导出成功但部分删除失败（文件仍保留在保险箱）: {}",
                            s
                        )),
                    );
                    ctx_clone.request_repaint();
                    return;
                }
            }

            let err_detail = if export_errors.is_empty() {
                String::new()
            } else {
                format!("（{} 个导出失败，已跳过）", export_errors.len())
            };
            set_pending(
                &result,
                Ok(format!(
                    "剪切完成: {} 个文件 → {} {}",
                    export_ok.len(),
                    out_dir,
                    err_detail
                )),
            );
            ctx_clone.request_repaint();
        });
    }

    // -------- 单文件导出（纯导出） --------

    /// 导出单文件到用户指定路径（纯导出，不删除）
    pub(super) fn start_export_by_index(&mut self, ctx: &egui::Context, blind_index: [u8; 32]) {
        let Some((save_path, vault, result)) =
            self.prepare_single_export("选择导出位置", blind_index, "正在导出文件...")
        else {
            return;
        };

        // 检查后缀是否被修改（只提醒，不拦截）
        if let Some(orig_name) = self
            .files
            .iter()
            .find(|f| f.blind_index == blind_index)
            .map(|f| f.filename.rsplit('/').next().unwrap_or(&f.filename).to_string())
        {
            let orig_ext = std::path::Path::new(&orig_name)
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("");
            let save_ext = save_path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("");
            if !orig_ext.is_empty() && orig_ext != save_ext {
                self.ext_warning_old_name = orig_name;
                self.ext_warning_new_name = save_path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("")
                    .to_string();
                self.ext_warning_export = Some((save_path, blind_index, false));
                self.ext_warning_export_vault = Some(vault);
                self.ext_warning_export_result = Some(result);
                self.show_ext_warning = true;
                return; // 等待用户确认后再执行
            }
        }

        spawn_task(ctx, result, move || match vault.lock() {
            Ok(v) => {
                v.export_file_to(&blind_index, &save_path)
                    .map_err(|e| e.to_string())?;
                Ok(format!("文件已导出到: {}", save_path.display()))
            }
            Err(e) => Err(format!("保险箱访问错误: {}", e)),
        });
    }

    // -------- 单文件剪切（导出+删除） --------

    /// 剪切单文件：导出到用户指定路径后从保险箱移除
    pub(super) fn start_cut_by_index(&mut self, ctx: &egui::Context, blind_index: [u8; 32]) {
        let Some((save_path, vault, result)) = self.prepare_single_export(
            "选择剪切位置（导出并删除）",
            blind_index,
            "正在剪切文件...",
        ) else {
            return;
        };

        // 检查后缀是否被修改（只提醒，不拦截）
        if let Some(orig_name) = self
            .files
            .iter()
            .find(|f| f.blind_index == blind_index)
            .map(|f| f.filename.rsplit('/').next().unwrap_or(&f.filename).to_string())
        {
            let orig_ext = std::path::Path::new(&orig_name)
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("");
            let save_ext = save_path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("");
            if !orig_ext.is_empty() && orig_ext != save_ext {
                self.ext_warning_old_name = orig_name;
                self.ext_warning_new_name = save_path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("")
                    .to_string();
                self.ext_warning_export = Some((save_path, blind_index, true));
                self.ext_warning_export_vault = Some(vault);
                self.ext_warning_export_result = Some(result);
                self.show_ext_warning = true;
                return; // 等待用户确认后再执行
            }
        }

        spawn_task(ctx, result, move || match vault.lock() {
            Ok(v) => {
                v.export_file_to(&blind_index, &save_path)
                    .map_err(|e| e.to_string())?;
                // remove_file 内部已有 SAVEPOINT 事务保护
                v.remove_file(&blind_index)
                    .map_err(|e| e.to_string())?;
                Ok(format!(
                    "文件已剪切到: {}（已从保险箱移除）",
                    save_path.display()
                ))
            }
            Err(e) => Err(format!("保险箱访问错误: {}", e)),
        });
    }

    // -------- 单文件导出/剪切通用准备 --------

    /// 准备单文件导出/剪切：查找文件名、选择保存路径、设置 busy 标志
    fn prepare_single_export(
        &mut self,
        dialog_title: &str,
        blind_index: [u8; 32],
        busy_message: &str,
    ) -> Option<(
        std::path::PathBuf,
        std::sync::Arc<std::sync::Mutex<crate::vault::Vault>>,
        super::task::TaskResult,
    )> {
        let file_name = self
            .files
            .iter()
            .find(|f| f.blind_index == blind_index)
            .map(|f| {
                // 取 vault 路径中最后一个 / 之后的部分作为默认文件名
                f.filename.rsplit('/').next().unwrap_or(&f.filename).to_string()
            })
            .unwrap_or_default();

        let save_path = rfd::FileDialog::new()
            .set_title(dialog_title)
            .set_file_name(&file_name)
            .save_file()?;

        let vault = self.vault.clone()?;
        let result = std::sync::Arc::clone(&self.pending_result);
        reset_pending(&result);
        self.task_busy = true;
        self.task_busy_message = busy_message.to_string();

        Some((save_path, vault, result))
    }

    // -------- 删除 --------

    pub(super) fn execute_remove(&mut self, ctx: &egui::Context, blind_index: [u8; 32]) {
        let vault = match self.vault.clone() {
            Some(v) => v,
            None => return,
        };
        self.selected_indices.remove(&blind_index);
        self.task_busy = true;
        self.task_busy_message = "正在删除文件...".to_string();
        let result = Arc::clone(&self.pending_result);
        let removed_idx = blind_index;

        spawn_task(ctx, result, move || match vault.lock() {
            Ok(v) => {
                v.remove_file(&removed_idx).map_err(|e| e.to_string())?;
                Ok("文件已移除".to_string())
            }
            Err(e) => Err(format!("保险箱访问错误: {}", e)),
        });
    }

    // -------- 重命名 --------

    pub(super) fn execute_rename(
        &mut self,
        ctx: &egui::Context,
        blind_index: [u8; 32],
        new_name: &str,
    ) {
        let new_name = new_name.trim().to_string();
        if new_name.is_empty() {
            set_pending(&self.pending_result, Err("文件名不能为空".to_string()));
            return;
        }
        run_task_mut(
            &self.vault.clone().unwrap(),
            &self.pending_result,
            &mut self.task_busy,
            &mut self.task_busy_message,
            ctx,
            "正在重命名...",
            move |guard| {
                guard
                    .rename_file(&blind_index, &new_name)
                    .map(|_| "重命名成功".to_string())
                    .map_err(|e| e.to_string())
            },
        );
    }

    // -------- 目录操作 --------

    /// 准备目录导出：选择目标目录 → 扫描 vault 文件 → 检查文件系统冲突 → 展示对话框
    pub(super) fn start_directory_export(&mut self, _ctx: &egui::Context, vault_path: &str) {
        let output_dir = match rfd::FileDialog::new()
            .set_title("选择导出目录")
            .pick_folder()
        {
            Some(d) => d,
            None => return,
        };

        let vdir = vault_path.to_string();
        // 构建保持目录层级的输出根路径
        let base = if vdir.is_empty() {
            output_dir.clone()
        } else {
            output_dir.join(&vdir)
        };

        // 扫描 self.files 中属于该目录的文件，计算相对路径
        let prefix = if vdir.is_empty() {
            String::new()
        } else {
            format!("{}/", vdir)
        };
        let mut items: Vec<(String, String, [u8; 32])> = Vec::new();
        for f in &self.files {
            if !vdir.is_empty() && !f.filename.starts_with(&prefix) && f.filename != vdir {
                continue;
            }
            let relative = if vdir.is_empty() {
                f.filename.clone()
            } else if f.filename == vdir {
                continue;
            } else {
                f.filename[prefix.len()..].to_string()
            };
            items.push((f.filename.clone(), relative, f.blind_index));
        }

        if items.is_empty() {
            self.set_status_error("目录中没有找到可导出的文件");
            return;
        }

        self.dir_export_cut_mode = false;
        self.dir_export_vault_dir = vdir;
        self.dir_export_base_path = base;
        self.dir_export_items = items;
        self.dir_export_choices.clear();
        for (_, rel, _) in &self.dir_export_items {
            self.dir_export_choices.insert(rel.clone(), true);
        }
        self.show_dir_export_conflict = true;
    }

    /// 准备目录剪切：选择目标目录 → 检查冲突 → 展示对话框
    pub(super) fn start_directory_cut(&mut self, _ctx: &egui::Context, vault_dir: &str) {
        let output_dir = match rfd::FileDialog::new()
            .set_title("选择导出位置并移除（剪切）")
            .pick_folder()
        {
            Some(d) => d,
            None => return,
        };

        let vdir = vault_dir.to_string();
        let base = if vdir.is_empty() {
            output_dir.clone()
        } else {
            output_dir.join(&vdir)
        };

        let prefix = if vdir.is_empty() {
            String::new()
        } else {
            format!("{}/", vdir)
        };
        let mut items: Vec<(String, String, [u8; 32])> = Vec::new();
        for f in &self.files {
            if !vdir.is_empty() && !f.filename.starts_with(&prefix) && f.filename != vdir {
                continue;
            }
            let relative = if vdir.is_empty() {
                f.filename.clone()
            } else if f.filename == vdir {
                continue;
            } else {
                f.filename[prefix.len()..].to_string()
            };
            items.push((f.filename.clone(), relative, f.blind_index));
        }

        if items.is_empty() {
            self.set_status_error("目录中没有找到可导出的文件");
            return;
        }

        self.dir_export_cut_mode = true;
        self.dir_export_vault_dir = vdir;
        self.dir_export_base_path = base;
        self.dir_export_items = items;
        self.dir_export_choices.clear();
        for (_, rel, _) in &self.dir_export_items {
            self.dir_export_choices.insert(rel.clone(), true);
        }
        self.show_dir_export_conflict = true;
    }

    /// 执行目录导出（导出已选文件）
    pub(super) fn execute_directory_export_selected(&mut self, ctx: &egui::Context) {
        let items = std::mem::take(&mut self.dir_export_items);
        let choices = std::mem::take(&mut self.dir_export_choices);
        let base_path = std::mem::take(&mut self.dir_export_base_path);
        let vdir = std::mem::take(&mut self.dir_export_vault_dir);
        self.show_dir_export_conflict = false;

        // 过滤出用户选择的文件（用 relative_path 作为 choices 键）
        let selected: Vec<(String, String, [u8; 32])> = items
            .into_iter()
            .filter(|(_, rel, _)| *choices.get(rel).unwrap_or(&false))
            .collect();

        if selected.is_empty() {
            self.set_status_error("未选择任何文件");
            return;
        }

        let vault = match &self.vault {
            Some(v) => v.clone(),
            None => return,
        };
        let result = Arc::clone(&self.pending_result);
        reset_pending(&result);
        let total = selected.len();
        self.task_busy = true;
        self.task_busy_message = format!("正在导出目录 ({} 个文件)...", total);

        let base = base_path.clone();
        spawn_task(ctx, result, move || match vault.lock() {
            Ok(v) => {
                let mut ok = 0u32;
                let mut errors = Vec::new();
                for (_, rel, idx) in &selected {
                    let output_path = base.join(rel);
                    if let Some(parent) = output_path.parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    match v.export_file_to(idx, &output_path) {
                        Ok(()) => ok += 1,
                        Err(e) => errors.push(format!("{}: {}", rel, e)),
                    }
                }
                if errors.is_empty() {
                    Ok(format!(
                        "文件夹「{}」导出完成: {} 个文件 → {}",
                        vdir,
                        ok,
                        base.display()
                    ))
                } else {
                    let s = errors.iter().take(3).cloned().collect::<Vec<_>>().join("; ");
                    let extra = if errors.len() > 3 { format!("... (共 {} 个错误)", errors.len()) } else { String::new() };
                    Ok(format!("! 导出 {}/{} 成功 | 失败: {}", ok, total, s + &extra))
                }
            }
            Err(e) => Err(format!("保险箱访问错误: {}", e)),
        });
    }

    /// 执行目录剪切（导出已选文件后从保险箱删除）
    pub(super) fn execute_directory_cut_selected(&mut self, ctx: &egui::Context) {
        let items = std::mem::take(&mut self.dir_export_items);
        let choices = std::mem::take(&mut self.dir_export_choices);
        let base_path = std::mem::take(&mut self.dir_export_base_path);
        let vdir = std::mem::take(&mut self.dir_export_vault_dir);
        self.show_dir_export_conflict = false;

        let selected: Vec<(String, String, [u8; 32])> = items
            .into_iter()
            .filter(|(_, rel, _)| *choices.get(rel).unwrap_or(&false))
            .collect();

        if selected.is_empty() {
            self.set_status_error("未选择任何文件");
            return;
        }

        let vault = match &self.vault {
            Some(v) => v.clone(),
            None => return,
        };
        let result = Arc::clone(&self.pending_result);
        reset_pending(&result);
        let total = selected.len();
        self.task_busy = true;
        self.task_busy_message = format!("正在导出并移除目录 ({} 个文件)...", total);

        self.selected_indices.clear();
        let base = base_path.clone();
        spawn_task(ctx, result, move || match vault.lock() {
            Ok(v) => {
                // 第一阶段：导出所有文件
                let mut exported = Vec::new();
                let mut errors = Vec::new();
                for (_, rel, idx) in &selected {
                    let output_path = base.join(rel);
                    if let Some(parent) = output_path.parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    match v.export_file_to(idx, &output_path) {
                        Ok(()) => exported.push(*idx),
                        Err(e) => errors.push(format!("{}: {}", rel, e)),
                    }
                }

                if errors.is_empty() && !exported.is_empty() {
                    // 第二阶段：删除已导出文件
                    let mut delete_errors = Vec::new();
                    for idx in &exported {
                        if let Err(e) = v.remove_file(idx) {
                            delete_errors.push(format!("删除失败: {}", e));
                        }
                    }
                    if !delete_errors.is_empty() {
                        return Err(format!(
                            "导出成功但部分删除失败（文件仍保留在保险箱）: {}",
                            delete_errors.join("; ")
                        ));
                    }
                    Ok(format!(
                        "文件夹「{}」导出并移除完成: {}（已从保险箱移除 {} 个文件）",
                        vdir,
                        base.display(),
                        exported.len()
                    ))
                } else if exported.is_empty() {
                    Err(format!("导出并移除失败: 没有任何文件成功导出"))
                } else {
                    let s = errors.iter().take(3).cloned().collect::<Vec<_>>().join("; ");
                    let extra = if errors.len() > 3 { format!("... (共 {} 个错误)", errors.len()) } else { String::new() };
                    Ok(format!("! 剪切 {}/{} 成功，已删除已导出部分 | 失败: {}", exported.len(), total, s + &extra))
                }
            }
            Err(e) => Err(format!("保险箱访问错误: {}", e)),
        });
    }

    pub(super) fn execute_directory_remove(&mut self, ctx: &egui::Context, vault_dir: &str) {
        let vault = match &self.vault {
            Some(v) => v.clone(),
            None => return,
        };
        let result = Arc::clone(&self.pending_result);
        reset_pending(&result);
        let dir = vault_dir.to_string();
        // 目录下文件可能已选，全部清理
        self.selected_indices.clear();
        self.task_busy = true;
        self.task_busy_message = "正在删除文件夹...".to_string();

        spawn_task(ctx, result, move || match vault.lock() {
            Ok(v) => {
                let count = v.remove_directory(&dir).map_err(|e| e.to_string())?;
                Ok(format!("文件夹「{}」删除完成: 已移除 {} 个文件", dir, count))
            }
            Err(e) => Err(format!("保险箱访问错误: {}", e)),
        });
    }

    // -------- 基准测试 --------

    /// 启动后台基准测试线程（布局/对话框两处共用）
    pub(super) fn spawn_bench_task(&mut self, ctx: &egui::Context) {
        self.bench_running = true;
        let pending = self.bench_pending.clone();
        let ctx_clone = ctx.clone();
        std::thread::spawn(move || {
            let mut r = crate::bench::run_all_benches();
            let io = crate::bench::run_io_benches();
            r.import_1kb_us = io.import_1kb_us;
            r.export_1kb_us = io.export_1kb_us;
            r.import_1mb_ms = io.import_1mb_ms;
            r.export_1mb_ms = io.export_1mb_ms;
            r.import_10mb_ms = io.import_10mb_ms;
            r.export_10mb_ms = io.export_10mb_ms;
            r.vault_open_ms = io.vault_open_ms;
            r.batch_import_10x1mb_ms = io.batch_import_10x1mb_ms;
            *pending.lock().unwrap() = Some(r);
            ctx_clone.request_repaint();
        });
    }
}
