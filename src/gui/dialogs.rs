//! GUI 对话框：删除确认、导入确认、导出覆盖、修改密码、重命名等

use eframe::egui;
use egui::{Color32, Frame, Margin, RichText, ScrollArea, TextEdit};

use super::app::VaultApp;
use super::icons;
use super::ops::BatchDecision;
use super::task::{run_task_mut, set_pending, spawn_task, zeroize_password_string};
use super::types::{
    C_ERROR, C_PRIMARY, C_ROW_ALT_BG, C_SUCCESS, C_TABLE_HEADER_BG, C_WARNING,
    strength_color_to_egui,
};
use crate::crypto::password_strength::{evaluate_password, strength_color, strength_progress};
use zeroize::Zeroize;

use crate::bench::BenchResults;

impl VaultApp {
    // ============================================================
    // 对话框渲染入口（由 draw_main_screen 调用）
    // ============================================================

    pub(super) fn draw_dialogs(&mut self, ctx: &egui::Context) {
        self.draw_bench_window(ctx);
        self.draw_audit_log_window(ctx);
        self.draw_confirm_remove_dialog(ctx);
        self.draw_batch_remove_dialog(ctx);
        self.draw_confirm_remove_dir_dialog(ctx);
        self.draw_batch_import_dialog(ctx);
        self.draw_batch_error_dialog(ctx);
        self.draw_export_overwrite_dialog(ctx);
        self.draw_change_password_dialog(ctx);
        self.draw_rename_dialog(ctx);
        self.draw_rename_dir_dialog(ctx);
        self.draw_sm2_sign_dialog(ctx);
        self.draw_sm2_verify_dialog(ctx);
        self.draw_kek_split_dialog(ctx);
        self.draw_kek_recover_dialog(ctx);
        self.draw_dir_export_conflict_dialog(ctx);
        self.draw_ext_warning_dialog(ctx);
    }

    // ===== 基准测试窗口 =====

    fn draw_bench_window(&mut self, ctx: &egui::Context) {
        if !self.show_bench {
            return;
        }
        egui::Window::new("基准测试")
            .resizable(false)
            .default_size([460.0, 560.0])
            .show(ctx, |ui| {
                if self.bench_running {
                    ui.horizontal(|ui| {
                        ui.add(egui::Spinner::new().size(20.0));
                        ui.label("  运行基准测试中...（约 10 秒）");
                    });
                    return;
                }
                if let Some(ref r) = self.bench_results {
                    ui.horizontal(|ui| {
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.button(format!("{} 关闭", icons::ICON_CLOSE)).clicked() {
                                self.show_bench = false;
                            }
                            if ui.button("复制结果").clicked() {
                                let text = format_bench_results(r);
                                ui.ctx().copy_text(text);
                            }
                        });
                    });
                    ui.add_space(4.0);

                    ScrollArea::vertical()
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            // === SM4 加密 ===
                            ui.label(RichText::new("SM4 加密吞吐量 (1MB)").strong().size(14.0));
                            ui.separator();
                            ui.horizontal(|ui| {
                                ui.label(format!("基线 (S-Box):    {:.1} MB/s", r.sm4_baseline_mbps));
                            });
                            ui.horizontal(|ui| {
                                ui.label(format!("优化 (T-Table):   {:.1} MB/s", r.sm4_t_table_mbps));
                            });
                            ui.horizontal(|ui| {
                                ui.label(format!("常数时间 (CT):   {:.1} KB/s", r.sm4_ct_kbps));
                            });
                            ui.horizontal(|ui| {
                                ui.label(format!("加速比:           {:.2}x", r.speedup));
                            });
                            ui.add_space(4.0);

                            // === SM4-CBC（KEK 路径） ===
                            ui.label(RichText::new("SM4-CBC 密钥包裹 (1MB)").strong().size(13.0));
                            ui.separator();
                            ui.horizontal(|ui| {
                                ui.label(format!("加密: {:.1} MB/s", r.sm4_cbc_encrypt_mbps));
                            });
                            ui.horizontal(|ui| {
                                ui.label(format!("解密: {:.1} MB/s", r.sm4_cbc_decrypt_mbps));
                            });
                            ui.add_space(4.0);

                            // === HMAC-SM3 ===
                            ui.label(RichText::new("HMAC-SM3 完整性校验 (1MB)").strong().size(13.0));
                            ui.separator();
                            ui.horizontal(|ui| {
                                ui.label(format!("吞吐量: {:.1} MB/s", r.hmac_sm3_mbps));
                            });
                            ui.add_space(4.0);

                            // === PBKDF2 ===
                            ui.label(RichText::new("PBKDF2-SM3 密钥派生").strong().size(13.0));
                            ui.separator();
                            ui.horizontal(|ui| {
                                ui.label(format!("100,000 次: {:.0} ms", r.pbkdf2_100k_ms));
                            });
                            ui.horizontal(|ui| {
                                ui.label(format!("600,000 次: {:.0} ms", r.pbkdf2_ms));
                            });
                            ui.add_space(4.0);

                            // === SM2 ===
                            ui.label(RichText::new("SM2 公钥密码").strong().size(13.0));
                            ui.separator();
                            ui.horizontal(|ui| {
                                ui.label(format!("密钥生成: {:.1} ms", r.sm2_keygen_ms));
                            });
                            ui.horizontal(|ui| {
                                ui.label(format!("签名:     {:.1} ms", r.sm2_sign_ms));
                            });
                            ui.horizontal(|ui| {
                                ui.label(format!("验签:     {:.1} ms", r.sm2_verify_ms));
                            });
                            ui.add_space(4.0);

                            // === Shamir ===
                            ui.label(RichText::new("Shamir 秘密共享 (KEK 灾备)").strong().size(13.0));
                            ui.separator();
                            ui.horizontal(|ui| {
                                ui.label(format!("5-of-3 分片: {:.1} μs", r.shamir_split_us));
                            });
                            ui.horizontal(|ui| {
                                ui.label(format!("3 份恢复:    {:.1} μs", r.shamir_recover_us));
                            });
                            ui.add_space(4.0);

                            // === 全链路文件操作 ===
                            ui.label(RichText::new("全链路文件操作").strong().size(13.0));
                            ui.separator();
                            if let Some(v) = r.import_1kb_us {
                                ui.horizontal(|ui| {
                                    ui.label(format!("1KB 导入: {:.1} μs", v));
                                });
                            }
                            if let Some(v) = r.export_1kb_us {
                                ui.horizontal(|ui| {
                                    ui.label(format!("1KB 导出: {:.1} μs", v));
                                });
                            }
                            if let Some(v) = r.import_1mb_ms {
                                ui.horizontal(|ui| {
                                    ui.label(format!("1MB 导入: {:.1} ms", v));
                                });
                            }
                            if let Some(v) = r.export_1mb_ms {
                                ui.horizontal(|ui| {
                                    ui.label(format!("1MB 导出: {:.1} ms", v));
                                });
                            }
                            if let Some(v) = r.import_10mb_ms {
                                ui.horizontal(|ui| {
                                    ui.label(format!("10MB 导入: {:.1} ms", v));
                                });
                            }
                            if let Some(v) = r.export_10mb_ms {
                                ui.horizontal(|ui| {
                                    ui.label(format!("10MB 导出: {:.1} ms", v));
                                });
                            }
                            if let Some(v) = r.batch_import_10x1mb_ms {
                                ui.horizontal(|ui| {
                                    ui.label(format!("批量导入 10×1MB: {:.1} ms", v));
                                });
                            }
                            ui.add_space(4.0);

                            // === 保险箱 ===
                            ui.label(RichText::new("保险箱操作").strong().size(13.0));
                            ui.separator();
                            ui.horizontal(|ui| {
                                ui.label(format!("打开（登录）: {:.0} ms", r.vault_open_ms));
                            });
                        });
                } else {
                    ui.label("尚未运行基准测试。");
                    if ui.button("运行测试").clicked() {
                        self.spawn_bench_task(ctx);
                    }
                }
            });
    }

    // ===== 审计日志窗口 =====

    fn draw_audit_log_window(&mut self, ctx: &egui::Context) {
        if !self.show_audit_log {
            return;
        }
        egui::Window::new("审计日志")
            .resizable(true)
            .default_size([600.0, 400.0])
            .min_size([400.0, 300.0])
            .collapsible(false)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(format!("共 {} 条记录", self.audit_log_entries.len()))
                            .size(14.0)
                            .strong(),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button(format!("{} 关闭", icons::ICON_CLOSE)).clicked() {
                            self.show_audit_log = false;
                        }
                        if ui.button("验证完整性").clicked()
                            && let Some(ref vault_arc) = self.vault
                            && let Ok(v) = vault_arc.lock()
                        {
                            match v.audit_log_verify() {
                                Ok(true) => {
                                    set_pending(
                                        &self.pending_result,
                                        Ok("审计日志完整性验证通过 ✓".to_string()),
                                    );
                                }
                                Ok(false) => {
                                    set_pending(
                                        &self.pending_result,
                                        Err("审计日志完整性验证失败 ✗".to_string()),
                                    );
                                }
                                Err(e) => {
                                    set_pending(
                                        &self.pending_result,
                                        Err(format!("审计日志验证错误: {}", e)),
                                    );
                                }
                            }
                        }
                        if ui.button("导出 JSON").clicked()
                            && let Some(ref vault_arc) = self.vault
                            && let Ok(v) = vault_arc.lock()
                        {
                            if let Some(save) = rfd::FileDialog::new()
                                .set_title("导出审计日志")
                                .set_file_name("audit_log.json")
                                .save_file()
                            {
                                match v.audit_log_export_json() {
                                    Ok(json) => {
                                        let _ = std::fs::write(&save, &json);
                                        set_pending(
                                            &self.pending_result,
                                            Ok(format!("审计日志已导出到: {}", save.display())),
                                        );
                                    }
                                    Err(e) => set_pending(
                                        &self.pending_result,
                                        Err(format!("导出失败: {}", e)),
                                    ),
                                }
                            }
                        }
                        if ui.button(format!("{} 刷新", icons::ICON_REFRESH)).clicked()
                            && let Some(ref vault_arc) = self.vault
                            && let Ok(v) = vault_arc.lock()
                        {
                            let entries = v.audit_log_get_recent(500).unwrap_or_default();
                            self.audit_log_entries =
                                super::types::audit_entries_to_display(&entries, true);
                        }
                    });
                });
                ui.add_space(6.0);
                let hdr_bg = C_TABLE_HEADER_BG;
                Frame::none()
                    .fill(hdr_bg)
                    .inner_margin(Margin::symmetric(6.0, 3.0))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.spacing_mut().item_spacing.x = 0.0;
                            ui.add_sized(
                                [50.0, 20.0],
                                egui::Label::new(RichText::new("序号").size(12.0).strong()),
                            );
                            ui.add_sized(
                                [140.0, 20.0],
                                egui::Label::new(RichText::new("时间").size(12.0).strong()),
                            );
                            ui.add_sized(
                                [100.0, 20.0],
                                egui::Label::new(RichText::new("类型").size(12.0).strong()),
                            );
                            ui.add_sized(
                                [240.0, 20.0],
                                egui::Label::new(RichText::new("详情").size(12.0).strong()),
                            );
                        });
                    });
                if self.audit_log_entries.is_empty() {
                    ui.add_space(20.0);
                    ui.vertical_centered(|ui| {
                        ui.label(
                            RichText::new("暂无审计日志记录")
                                .size(14.0)
                                .color(Color32::GRAY),
                        );
                    });
                } else {
                    let row_bg_a = Color32::WHITE;
                    let row_bg_b = Color32::from_rgb(0xf3, 0xf5, 0xf9);
                    ScrollArea::vertical()
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            for (row_i, entry) in self.audit_log_entries.iter().enumerate() {
                                let bg = if row_i % 2 == 0 { row_bg_a } else { row_bg_b };
                                Frame::none()
                                    .fill(bg)
                                    .inner_margin(Margin::symmetric(6.0, 3.0))
                                    .show(ui, |ui| {
                                        ui.horizontal(|ui| {
                                            ui.spacing_mut().item_spacing.x = 0.0;
                                            ui.add_sized(
                                                [50.0, 20.0],
                                                egui::Label::new(
                                                    RichText::new(&entry.idx)
                                                        .size(12.0)
                                                        .color(Color32::GRAY),
                                                ),
                                            );
                                            ui.add_sized(
                                                [140.0, 20.0],
                                                egui::Label::new(
                                                    RichText::new(&entry.time_str).size(12.0),
                                                ),
                                            );
                                            ui.add_sized(
                                                [100.0, 20.0],
                                                egui::Label::new(
                                                    RichText::new(&entry.type_name)
                                                        .size(12.0)
                                                        .strong(),
                                                ),
                                            );
                                            ui.add_sized(
                                                [240.0, 20.0],
                                                egui::Label::new(
                                                    RichText::new(&entry.payload)
                                                        .size(12.0)
                                                        .color(Color32::from_rgb(0x55, 0x55, 0x55)),
                                                ),
                                            );
                                        });
                                    });
                                ui.separator();
                            }
                        });
                }
            });
    }

    // ===== 删除确认 =====

    fn draw_confirm_remove_dialog(&mut self, ctx: &egui::Context) {
        let blind_index = match self.confirm_remove {
            Some(bi) => bi,
            None => return,
        };
        let filename = self.confirm_remove_filename.clone();
        egui::Window::new("确认删除")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .fixed_size([360.0, 150.0])
            .show(ctx, |ui| {
                ui.vertical_centered(|ui| {
                    ui.add_space(16.0);
                    ui.label(
                        RichText::new(format!("确定要永久删除「{}」吗？", filename))
                            .size(14.0)
                            .color(Color32::from_rgb(0xcc, 0x33, 0x33)),
                    );
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new("此操作无法撤销，文件将从保险箱中彻底移除。")
                            .size(12.0)
                            .color(Color32::GRAY),
                    );
                    ui.add_space(20.0);
                    ui.horizontal(|ui| {
                        ui.add_space(40.0);
                        if ui
                            .add_sized(
                                [110.0, 32.0],
                                egui::Button::new(
                                    RichText::new("确认删除").size(14.0).color(Color32::WHITE),
                                )
                                .fill(C_ERROR),
                            )
                            .clicked()
                        {
                            self.execute_remove(ctx, blind_index);
                            self.confirm_remove = None;
                        }
                        ui.add_space(20.0);
                        if ui
                            .add_sized(
                                [110.0, 32.0],
                                egui::Button::new(RichText::new("取消").size(14.0)),
                            )
                            .clicked()
                        {
                            self.confirm_remove = None;
                        }
                    });
                });
            });
    }

    // ===== 批量删除确认 =====

    fn draw_batch_remove_dialog(&mut self, ctx: &egui::Context) {
        if !self.show_batch_remove_confirm {
            return;
        }
        let count = self.selected_indices.len();
        let names = self.batch_remove_filenames.clone();
        let vault = self.vault.clone();
        let indices: Vec<[u8; 32]> = self.selected_indices.iter().copied().collect();

        egui::Window::new("确认批量删除")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .fixed_size([400.0, 260.0])
            .show(ctx, |ui| {
                ui.vertical_centered(|ui| {
                    ui.add_space(12.0);
                    ui.label(
                        RichText::new(format!("确定要永久删除 {} 个文件吗？", count))
                            .size(14.0)
                            .color(C_ERROR),
                    );
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new("此操作无法撤销，以下文件将从保险箱中彻底移除：")
                            .size(12.0)
                            .color(Color32::GRAY),
                    );
                    ui.add_space(8.0);
                    ScrollArea::vertical().max_height(100.0).show(ui, |ui| {
                        for name in &names {
                            ui.label(RichText::new(name).size(12.0));
                        }
                    });
                    ui.add_space(12.0);
                    ui.horizontal(|ui| {
                        ui.add_space(40.0);
                        if ui
                            .add_sized(
                                [120.0, 32.0],
                                egui::Button::new(
                                    RichText::new(format!("确认删除 {} 个", count))
                                        .size(14.0)
                                        .color(Color32::WHITE),
                                )
                                .fill(C_ERROR),
                            )
                            .clicked()
                            && let Some(ref v) = vault
                        {
                            let vault_clone = v.clone();
                            let indices_clone = indices.clone();
                            spawn_task(ctx, self.pending_result.clone(), move || {
                                let vault_ref = vault_clone
                                    .lock()
                                    .map_err(|e| format!("保险箱访问错误: {}", e))?;
                                let mut success = 0u32;
                                let mut errors = 0u32;
                                for idx in &indices_clone {
                                    // remove_file 内部已有 SAVEPOINT 保护
                                    match vault_ref.remove_file(idx) {
                                        Ok(()) => success += 1,
                                        Err(_) => errors += 1,
                                    }
                                }
                                if errors == 0 {
                                    Ok(format!("批量删除完成: {} 个文件", success))
                                } else {
                                    Ok(format!("! 批量删除: {} 成功, {} 失败", success, errors))
                                }
                            });
                            self.selected_indices.clear();
                            self.show_batch_remove_confirm = false;
                        }
                        ui.add_space(20.0);
                        if ui
                            .add_sized([100.0, 32.0], egui::Button::new("取消".to_string()))
                            .clicked()
                        {
                            self.show_batch_remove_confirm = false;
                        }
                    });
                });
            });
    }

    // ===== 目录删除确认 =====

    fn draw_confirm_remove_dir_dialog(&mut self, ctx: &egui::Context) {
        let remove_dir = match &self.confirm_remove_dir.clone() {
            Some(d) => d.clone(),
            None => return,
        };
        let dir_display = self.confirm_remove_dir_name.clone();
        egui::Window::new("确认删除目录")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .fixed_size([380.0, 170.0])
            .show(ctx, |ui| {
                ui.vertical_centered(|ui| {
                    ui.add_space(16.0);
                    ui.label(
                        RichText::new(format!("确定要永久删除目录「{}」吗？", dir_display))
                            .size(14.0)
                            .color(Color32::from_rgb(0xcc, 0x33, 0x33)),
                    );
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new("将删除目录下的所有文件及子目录，此操作无法撤销。")
                            .size(12.0)
                            .color(Color32::GRAY),
                    );
                    ui.add_space(20.0);
                    ui.horizontal(|ui| {
                        ui.add_space(40.0);
                        if ui
                            .add_sized(
                                [110.0, 32.0],
                                egui::Button::new(
                                    RichText::new("确认删除").size(14.0).color(Color32::WHITE),
                                )
                                .fill(C_ERROR),
                            )
                            .clicked()
                        {
                            self.execute_directory_remove(ctx, &remove_dir);
                            self.confirm_remove_dir = None;
                        }
                        ui.add_space(20.0);
                        if ui
                            .add_sized(
                                [110.0, 32.0],
                                egui::Button::new(RichText::new("取消").size(14.0)),
                            )
                            .clicked()
                        {
                            self.confirm_remove_dir = None;
                        }
                    });
                });
            });
    }

    // ===== 批处理错误交互对话框 =====

    fn draw_batch_error_dialog(&mut self, ctx: &egui::Context) {
        let error_info = match &self.batch_error_pending {
            Some(pending) => match pending.lock() {
                Ok(guard) => match guard.as_ref() {
                    Some(info) => info.clone(),
                    None => return,
                },
                Err(_) => return,
            },
            None => return,
        };

        egui::Window::new("文件处理错误")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .fixed_size([420.0, 200.0])
            .show(ctx, |ui| {
                ui.vertical_centered(|ui| {
                    ui.add_space(16.0);
                    ui.label(
                        RichText::new(format!("处理文件时出错"))
                            .size(15.0)
                            .color(C_ERROR)
                            .strong(),
                    );
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        ui.add_space(20.0);
                        ui.label(
                            RichText::new(format!("文件: {}", &error_info.file_name)).size(13.0),
                        );
                    });
                    ui.horizontal(|ui| {
                        ui.add_space(20.0);
                        ui.label(
                            RichText::new(format!("错误: {}", &error_info.error_message))
                                .size(12.0)
                                .color(Color32::from_rgb(0xcc, 0x44, 0x44)),
                        );
                    });
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new(format!(
                            "进度: {}/{}",
                            error_info.progress.0, error_info.progress.1
                        ))
                        .size(11.0)
                        .color(Color32::GRAY),
                    );
                    ui.add_space(16.0);
                    let decision_tx = self.batch_decision_tx.clone();
                    if let Some(tx) = decision_tx {
                        ui.horizontal(|ui| {
                            ui.add_space(60.0);
                            if ui
                                .add_sized(
                                    [120.0, 32.0],
                                    egui::Button::new(
                                        RichText::new("跳过并继续")
                                            .size(14.0)
                                            .color(Color32::WHITE),
                                    )
                                    .fill(Color32::from_rgb(0xe6, 0x8a, 0x00)),
                                )
                                .clicked()
                            {
                                let _ = tx.send(BatchDecision::Skip);
                                self.batch_decision_tx = None;
                            }
                            ui.add_space(20.0);
                            if ui
                                .add_sized(
                                    [120.0, 32.0],
                                    egui::Button::new(
                                        RichText::new("取消操作").size(14.0).color(Color32::WHITE),
                                    )
                                    .fill(C_ERROR),
                                )
                                .clicked()
                            {
                                let _ = tx.send(BatchDecision::Cancel);
                                self.batch_decision_tx = None;
                            }
                        });
                    }
                });
            });
    }

    // ===== 批量导入确认 =====

    fn draw_batch_import_dialog(&mut self, ctx: &egui::Context) {
        if !self.show_batch_import_confirm {
            return;
        }
        let count = self.batch_import_files.len();
        let filenames: Vec<String> = self
            .batch_import_files
            .iter()
            .map(|item| item.vault_path.clone())
            .collect();

        egui::Window::new("确认导入")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .fixed_size([560.0, 420.0])
            .show(ctx, |ui| {
                ui.vertical_centered(|ui| {
                    ui.add_space(6.0);
                    ui.label(
                        RichText::new(format!("确认导入 {} 个文件？", count))
                            .size(14.0)
                            .strong(),
                    );
                    ui.add_space(4.0);
                    let hdr_bg = C_TABLE_HEADER_BG;
                    Frame::none()
                        .fill(hdr_bg)
                        .inner_margin(Margin::symmetric(6.0, 3.0))
                        .show(ui, |ui| {
                            let hdr_w = ui.available_width();
                            ui.horizontal(|ui| {
                                ui.spacing_mut().item_spacing.x = 0.0;
                                let all_ck = self.import_overwrite_choices.values().all(|&v| v);
                                let mut a = all_ck;
                                if ui
                                    .add_sized([24.0, 18.0], egui::Checkbox::new(&mut a, ""))
                                    .changed()
                                {
                                    for v in self.import_overwrite_choices.values_mut() {
                                        *v = a;
                                    }
                                }
                                let path_w = hdr_w - 24.0 - 80.0 - 12.0;
                                ui.add_sized(
                                    [path_w, 18.0],
                                    egui::Label::new(RichText::new("文件名").size(12.0).strong()),
                                );
                                ui.add_sized(
                                    [80.0, 18.0],
                                    egui::Label::new(RichText::new("状态").size(12.0).strong()),
                                );
                            });
                        });
                    let avail_h = ui.available_height().max(100.0);
                    let row_w = ui.available_width();
                    ScrollArea::vertical().max_height(avail_h).show(ui, |ui| {
                        let row_bg = C_ROW_ALT_BG;
                        for name in &filenames {
                            Frame::none()
                                .fill(row_bg)
                                .inner_margin(Margin::symmetric(6.0, 3.0))
                                .show(ui, |ui| {
                                    ui.horizontal(|ui| {
                                        ui.spacing_mut().item_spacing.x = 0.0;
                                        let mut chk = self
                                            .import_overwrite_choices
                                            .get(name)
                                            .copied()
                                            .unwrap_or(true);
                                        ui.add_sized(
                                            [24.0, 18.0],
                                            egui::Checkbox::new(&mut chk, ""),
                                        );
                                        self.import_overwrite_choices.insert(name.clone(), chk);
                                        let path_w = row_w - 24.0 - 80.0 - 12.0;
                                        ui.add_sized(
                                            [path_w, 18.0],
                                            egui::Label::new(RichText::new(name).size(12.0)),
                                        );
                                        if chk {
                                            if self.import_existing_in_vault.contains(name.as_str())
                                            {
                                                ui.add_sized(
                                                    [80.0, 18.0],
                                                    egui::Label::new(
                                                        RichText::new("覆盖")
                                                            .size(12.0)
                                                            .color(C_WARNING),
                                                    ),
                                                );
                                            } else {
                                                ui.add_sized(
                                                    [80.0, 18.0],
                                                    egui::Label::new(
                                                        RichText::new("新增")
                                                            .size(12.0)
                                                            .color(C_SUCCESS),
                                                    ),
                                                );
                                            }
                                        } else {
                                            ui.add_sized(
                                                [80.0, 18.0],
                                                egui::Label::new(
                                                    RichText::new("取消")
                                                        .size(12.0)
                                                        .color(Color32::GRAY),
                                                ),
                                            );
                                        }
                                    });
                                });
                        }
                    });
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        ui.add_space(50.0);
                        if ui
                            .add_sized(
                                [130.0, 32.0],
                                egui::Button::new(
                                    RichText::new("导入已选文件")
                                        .size(13.0)
                                        .color(Color32::WHITE),
                                )
                                .fill(C_PRIMARY),
                            )
                            .clicked()
                        {
                            self.execute_batch_import(ctx);
                            self.show_batch_import_confirm = false;
                        }
                        ui.add_space(10.0);
                        if ui
                            .add_sized([100.0, 32.0], egui::Button::new("取消".to_string()))
                            .clicked()
                        {
                            self.show_batch_import_confirm = false;
                            self.batch_import_files.clear();
                            self.import_overwrite_choices.clear();
                            self.import_existing_in_vault.clear();
                        }
                    });
                });
            });
    }

    // ===== 导出覆盖确认 =====

    fn draw_export_overwrite_dialog(&mut self, ctx: &egui::Context) {
        if !self.show_export_overwrite_confirm {
            return;
        }
        let files = self.export_overwrite_files.clone();
        let count = files.len();
        let selected = self.export_overwrite_selected.clone();
        let dir = self.export_overwrite_dir.clone();

        egui::Window::new("确认导出")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .fixed_size([560.0, 420.0])
            .show(ctx, |ui| {
                ui.vertical_centered(|ui| {
                    ui.add_space(6.0);
                    ui.label(
                        RichText::new(format!("确认导出 {} 个文件到：{}", count, dir))
                            .size(14.0)
                            .strong(),
                    );
                    ui.add_space(4.0);
                    let hdr_bg = C_TABLE_HEADER_BG;
                    Frame::none()
                        .fill(hdr_bg)
                        .inner_margin(Margin::symmetric(6.0, 3.0))
                        .show(ui, |ui| {
                            let hdr_w = ui.available_width();
                            ui.horizontal(|ui| {
                                ui.spacing_mut().item_spacing.x = 0.0;
                                let ack = self.export_overwrite_choices.values().all(|&v| v);
                                let mut a = ack;
                                if ui
                                    .add_sized([24.0, 18.0], egui::Checkbox::new(&mut a, ""))
                                    .changed()
                                {
                                    for v in self.export_overwrite_choices.values_mut() {
                                        *v = a;
                                    }
                                }
                                let path_w = hdr_w - 24.0 - 80.0 - 12.0;
                                ui.add_sized(
                                    [path_w, 18.0],
                                    egui::Label::new(RichText::new("文件名").size(12.0).strong()),
                                );
                                ui.add_sized(
                                    [80.0, 18.0],
                                    egui::Label::new(RichText::new("状态").size(12.0).strong()),
                                );
                            });
                        });
                    let avail_h = ui.available_height().max(100.0);
                    let row_w = ui.available_width();
                    ScrollArea::vertical().max_height(avail_h).show(ui, |ui| {
                        let row_bg = C_ROW_ALT_BG;
                        for name in &files {
                            Frame::none()
                                .fill(row_bg)
                                .inner_margin(Margin::symmetric(6.0, 3.0))
                                .show(ui, |ui| {
                                    ui.horizontal(|ui| {
                                        ui.spacing_mut().item_spacing.x = 0.0;
                                        let mut v = *self
                                            .export_overwrite_choices
                                            .get(name)
                                            .unwrap_or(&true);
                                        ui.add_sized([24.0, 18.0], egui::Checkbox::new(&mut v, ""));
                                        self.export_overwrite_choices.insert(name.clone(), v);
                                        let path_w = row_w - 24.0 - 80.0 - 12.0;
                                        ui.add_sized(
                                            [path_w, 18.0],
                                            egui::Label::new(RichText::new(name).size(12.0)),
                                        );
                                        if v {
                                            if self.export_exists_set.contains(name.as_str()) {
                                                ui.add_sized(
                                                    [80.0, 18.0],
                                                    egui::Label::new(
                                                        RichText::new("已存在")
                                                            .size(12.0)
                                                            .color(C_WARNING),
                                                    ),
                                                );
                                            } else {
                                                ui.add_sized(
                                                    [80.0, 18.0],
                                                    egui::Label::new(
                                                        RichText::new("新增")
                                                            .size(12.0)
                                                            .color(C_SUCCESS),
                                                    ),
                                                );
                                            }
                                        } else {
                                            ui.add_sized(
                                                [80.0, 18.0],
                                                egui::Label::new(
                                                    RichText::new("取消")
                                                        .size(12.0)
                                                        .color(Color32::GRAY),
                                                ),
                                            );
                                        }
                                    });
                                });
                        }
                    });
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        ui.add_space(40.0);
                        if ui
                            .add_sized(
                                [130.0, 32.0],
                                egui::Button::new(
                                    RichText::new("导出已选文件")
                                        .size(13.0)
                                        .color(Color32::WHITE),
                                )
                                .fill(C_PRIMARY),
                            )
                            .clicked()
                        {
                            let (filtered, filtered_names) =
                                self.filter_export_overwrite_selection(&selected, &files);
                            if !filtered.is_empty() {
                                self.do_batch_export(ctx, filtered, filtered_names, dir.clone());
                            }
                            self.show_export_overwrite_confirm = false;
                            self.export_overwrite_choices.clear();
                            self.export_exists_set.clear();
                        }
                        ui.add_space(6.0);
                        if ui
                            .add_sized(
                                [130.0, 32.0],
                                egui::Button::new(
                                    RichText::new("剪切已选文件（导出并删除）")
                                        .size(13.0)
                                        .color(Color32::WHITE),
                                )
                                .fill(C_PRIMARY),
                            )
                            .clicked()
                        {
                            let (filtered, filtered_names) =
                                self.filter_export_overwrite_selection(&selected, &files);
                            if !filtered.is_empty() {
                                self.do_batch_cut(ctx, filtered, filtered_names, dir.clone());
                            }
                            self.show_export_overwrite_confirm = false;
                            self.export_overwrite_choices.clear();
                            self.export_exists_set.clear();
                        }
                        ui.add_space(10.0);
                        if ui
                            .add_sized([100.0, 32.0], egui::Button::new("取消".to_string()))
                            .clicked()
                        {
                            self.show_export_overwrite_confirm = false;
                            self.export_overwrite_choices.clear();
                            self.export_exists_set.clear();
                        }
                    });
                });
            });
    }

    // ===== 目录导出冲突检查对话框 =====

    /// 目录导出/剪切前检查目标路径冲突，让用户选择要导出的文件
    fn draw_dir_export_conflict_dialog(&mut self, ctx: &egui::Context) {
        if !self.show_dir_export_conflict {
            return;
        }
        let items = self.dir_export_items.clone();
        let count = items.len();
        let base = self.dir_export_base_path.clone();
        let vdir = self.dir_export_vault_dir.clone();
        let cut_mode = self.dir_export_cut_mode;
        let action_label = if cut_mode { "导出并移除" } else { "导出" };

        egui::Window::new(format!("确认{}目录", action_label))
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .fixed_size([600.0, 460.0])
            .show(ctx, |ui| {
                ui.vertical_centered(|ui| {
                    ui.add_space(6.0);
                    ui.label(
                        RichText::new(format!("确认{}目录「{}」到：", action_label, vdir))
                            .size(14.0)
                            .strong(),
                    );
                    ui.label(
                        RichText::new(base.display().to_string())
                            .size(12.0)
                            .color(Color32::from_rgb(0x66, 0x66, 0x66)),
                    );
                    ui.add_space(2.0);
                    ui.label(
                        RichText::new(format!("共 {} 个文件，选择要{}的文件：", count, action_label))
                            .size(12.0),
                    );
                    ui.add_space(4.0);

                    // 表头（占满宽度）
                    let header_w = ui.available_width();
                    let hdr_bg = C_TABLE_HEADER_BG;
                    Frame::none()
                        .fill(hdr_bg)
                        .inner_margin(Margin::symmetric(6.0, 3.0))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.spacing_mut().item_spacing.x = 0.0;
                                // 全选框
                                let all_checked = self.dir_export_choices.values().all(|&v| v);
                                let mut a = all_checked;
                                if ui
                                    .add_sized([24.0, 18.0], egui::Checkbox::new(&mut a, ""))
                                    .changed()
                                {
                                    for v in self.dir_export_choices.values_mut() {
                                        *v = a;
                                    }
                                }
                                let path_w = header_w - 24.0 - 80.0 - 12.0;
                                ui.add_sized(
                                    [path_w, 18.0],
                                    egui::Label::new(RichText::new("文件路径").size(12.0).strong()),
                                );
                                ui.add_sized(
                                    [80.0, 18.0],
                                    egui::Label::new(RichText::new("状态").size(12.0).strong()),
                                );
                            });
                        });

                    // 文件列表（占满宽度）
                    let avail_h = ui.available_height().max(100.0);
                    let row_w = ui.available_width();
                    ScrollArea::vertical().max_height(avail_h).show(ui, |ui| {
                        let row_bg = C_ROW_ALT_BG;
                        for (full_path_vault, rel, _) in &items {
                            let full_path = base.join(rel);
                            let exists = full_path.exists();
                            Frame::none()
                                .fill(row_bg)
                                .inner_margin(Margin::symmetric(6.0, 3.0))
                                .show(ui, |ui| {
                                    ui.horizontal(|ui| {
                                        ui.spacing_mut().item_spacing.x = 0.0;
                                        let mut v = *self
                                            .dir_export_choices
                                            .get(rel)
                                            .unwrap_or(&true);
                                        ui.add_sized([24.0, 18.0], egui::Checkbox::new(&mut v, ""));
                                        self.dir_export_choices.insert(rel.clone(), v);
                                        let path_w = row_w - 24.0 - 80.0 - 12.0;
                                        ui.add_sized(
                                            [path_w, 18.0],
                                            egui::Label::new(RichText::new(full_path_vault).size(12.0)),
                                        );
                                        if v {
                                            if exists {
                                                ui.add_sized(
                                                    [80.0, 18.0],
                                                    egui::Label::new(
                                                        RichText::new("已存在")
                                                            .size(12.0)
                                                            .color(C_WARNING),
                                                    ),
                                                );
                                            } else {
                                                ui.add_sized(
                                                    [80.0, 18.0],
                                                    egui::Label::new(
                                                        RichText::new("新增")
                                                            .size(12.0)
                                                            .color(C_SUCCESS),
                                                    ),
                                                );
                                            }
                                        } else {
                                            ui.add_sized(
                                                [80.0, 18.0],
                                                egui::Label::new(
                                                    RichText::new("跳过")
                                                        .size(12.0)
                                                        .color(Color32::GRAY),
                                                ),
                                            );
                                        }
                                    });
                                });
                        }
                    });

                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        ui.add_space(40.0);
                        let btn_label = format!("{}已选文件", action_label);
                        let btn_w = ui.available_width() - 160.0;
                        if ui
                            .add_sized(
                                [btn_w.max(140.0), 32.0],
                                egui::Button::new(
                                    RichText::new(&btn_label)
                                        .size(13.0)
                                        .color(Color32::WHITE),
                                )
                                .fill(C_PRIMARY),
                            )
                            .clicked()
                        {
                            if cut_mode {
                                self.execute_directory_cut_selected(ctx);
                            } else {
                                self.execute_directory_export_selected(ctx);
                            }
                        }
                        ui.add_space(10.0);
                        if ui
                            .add_sized([100.0, 32.0], egui::Button::new("取消".to_string()))
                            .clicked()
                        {
                            self.show_dir_export_conflict = false;
                            self.dir_export_items.clear();
                            self.dir_export_choices.clear();
                        }
                    });
                });
            });
    }

    // ===== 后缀修改确认对话框 =====

    /// 当导出/剪切/重命名时用户修改了文件后缀，弹出确认对话框
    fn draw_ext_warning_dialog(&mut self, ctx: &egui::Context) {
        if !self.show_ext_warning {
            return;
        }
        egui::Window::new("修改文件后缀")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .fixed_size([420.0, 220.0])
            .show(ctx, |ui| {
                ui.vertical_centered(|ui| {
                    ui.add_space(16.0);
                    ui.label(
                        RichText::new("检测到文件后缀被修改")
                            .size(15.0)
                            .strong(),
                    );
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        ui.add_space(30.0);
                        ui.label(
                            RichText::new(format!("原名称: {}", self.ext_warning_old_name))
                                .size(13.0),
                        );
                    });
                    ui.horizontal(|ui| {
                        ui.add_space(30.0);
                        ui.label(
                            RichText::new(format!("新名称: {}", self.ext_warning_new_name))
                                .size(13.0),
                        );
                    });
                    ui.add_space(6.0);
                    ui.label(
                        RichText::new("⚠ 注意：修改文件后缀可能导致文件无法正常打开！")
                            .size(12.0)
                            .color(C_WARNING),
                    );
                    ui.add_space(16.0);
                    ui.horizontal(|ui| {
                        ui.add_space(40.0);
                        if ui
                            .add_sized(
                                [130.0, 32.0],
                                egui::Button::new(
                                    RichText::new("确认修改")
                                        .size(14.0)
                                        .color(Color32::WHITE),
                                )
                                .fill(C_WARNING),
                            )
                            .clicked()
                        {
                            // 执行待确认的操作
                            if let Some((bi, new_name)) = self.ext_warning_rename.take() {
                                self.execute_rename(ctx, bi, &new_name);
                                self.rename_target = None;
                                self.rename_new_name.clear();
                            } else if let Some((save_path, blind_index, is_cut)) =
                                self.ext_warning_export.take()
                            {
                                let vault = self.ext_warning_export_vault.take();
                                let result = self.ext_warning_export_result.take();
                                if let (Some(v), Some(r)) = (vault, result) {
                                    self.task_busy = true;
                                    self.task_busy_message = if is_cut {
                                        "正在剪切文件...".to_string()
                                    } else {
                                        "正在导出文件...".to_string()
                                    };
                                    use super::task::spawn_task;
                                    spawn_task(ctx, r, move || match v.lock() {
                                        Ok(v) => {
                                            v.export_file_to(&blind_index, &save_path)
                                                .map_err(|e| e.to_string())?;
                                            if is_cut {
                                                v.remove_file(&blind_index)
                                                    .map_err(|e| e.to_string())?;
                                                Ok(format!(
                                                    "文件已剪切到: {}",
                                                    save_path.display()
                                                ))
                                            } else {
                                                Ok(format!(
                                                    "文件已导出到: {}",
                                                    save_path.display()
                                                ))
                                            }
                                        }
                                        Err(e) => Err(format!("保险箱访问错误: {}", e)),
                                    });
                                }
                            }
                            self.show_ext_warning = false;
                            self.ext_warning_old_name.clear();
                            self.ext_warning_new_name.clear();
                        }
                        ui.add_space(20.0);
                        if ui
                            .add_sized(
                                [130.0, 32.0],
                                egui::Button::new(RichText::new("取消修改").size(14.0)),
                            )
                            .clicked()
                        {
                            // 清除待确认状态
                            if self.ext_warning_export.is_some() {
                                // 从导出流过来的，清除 busy 状态
                                self.task_busy = false;
                                self.task_busy_message.clear();
                            }
                            self.ext_warning_rename = None;
                            self.ext_warning_export = None;
                            self.ext_warning_export_vault = None;
                            self.ext_warning_export_result = None;
                            self.show_ext_warning = false;
                            self.ext_warning_old_name.clear();
                            self.ext_warning_new_name.clear();
                        }
                    });
                });
            });
    }

    // ===== 修改密码对话框 =====

    fn draw_change_password_dialog(&mut self, ctx: &egui::Context) {
        if !self.show_change_password {
            return;
        }
        egui::Window::new("修改密码")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .fixed_size([380.0, 260.0])
            .show(ctx, |ui| {
                ui.add_space(12.0);
                ui.vertical_centered(|ui| {
                    ui.label("修改保险箱密码");
                    ui.label(
                        RichText::new("修改后所有文件的 DEK 将用新密码重新加密")
                            .size(11.0)
                            .color(Color32::GRAY),
                    );
                });
                ui.add_space(8.0);

                ui.horizontal(|ui| {
                    ui.add_sized([70.0, 24.0], egui::Label::new("当前密码:"));
                    if ui
                        .add_sized(
                            [40.0, 20.0],
                            egui::Button::new(if self.change_password_visible {
                                "隐藏"
                            } else {
                                "显示"
                            })
                            .frame(false),
                        )
                        .clicked()
                    {
                        self.change_password_visible = !self.change_password_visible;
                    }
                    ui.add(
                        TextEdit::singleline(&mut self.change_old_password)
                            .password(!self.change_password_visible)
                            .hint_text("输入当前密码")
                            .desired_width(f32::INFINITY),
                    );
                });
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.add_sized([70.0, 24.0], egui::Label::new("新密码:"));
                    ui.add(
                        TextEdit::singleline(&mut self.change_new_password)
                            .password(!self.change_password_visible)
                            .hint_text("输入新密码")
                            .desired_width(f32::INFINITY),
                    );
                });
                if !self.change_new_password.is_empty() {
                    let pw = evaluate_password(&self.change_new_password);
                    let progress = strength_progress(&pw);
                    let c = strength_color_to_egui(strength_color(&pw));
                    ui.add_space(2.0);
                    ui.horizontal(|ui| {
                        let bar = egui::widgets::ProgressBar::new(progress)
                            .fill(c)
                            .desired_width(120.0);
                        ui.add(bar);
                        ui.label(
                            RichText::new(pw.level.as_str())
                                .color(c)
                                .size(11.0)
                                .strong(),
                        );
                    });
                }
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.add_sized([70.0, 24.0], egui::Label::new("确认密码:"));
                    ui.add(
                        TextEdit::singleline(&mut self.change_new_password_confirm)
                            .password(!self.change_password_visible)
                            .hint_text("再次输入新密码")
                            .desired_width(f32::INFINITY),
                    );
                });

                ui.add_space(8.0);
                ui.vertical_centered(|ui| {
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 0.0;
                        let total_w = 250.0;
                        ui.add_space((ui.available_width() - total_w).max(0.0) / 2.0);
                        if ui
                            .add_sized(
                                [140.0, 32.0],
                                egui::Button::new(
                                    RichText::new("确认修改").size(14.0).color(Color32::WHITE),
                                )
                                .fill(C_PRIMARY),
                            )
                            .clicked()
                        {
                            let mut old_pwd = self.change_old_password.trim().to_string();
                            let mut new_pwd = self.change_new_password.trim().to_string();
                            let mut confirm = self.change_new_password_confirm.trim().to_string();

                            if old_pwd.is_empty() || new_pwd.is_empty() {
                                old_pwd.zeroize();
                                new_pwd.zeroize();
                                confirm.zeroize();
                                set_pending(&self.pending_result, Err("密码不能为空".to_string()));
                            } else if new_pwd != confirm {
                                old_pwd.zeroize();
                                new_pwd.zeroize();
                                confirm.zeroize();
                                set_pending(
                                    &self.pending_result,
                                    Err("两次输入的新密码不一致".to_string()),
                                );
                            } else {
                                let pwd_for_task = new_pwd.clone();
                                run_task_mut(
                                    &self.vault.clone().unwrap(),
                                    &self.pending_result,
                                    &mut self.task_busy,
                                    &mut self.task_busy_message,
                                    ctx,
                                    "正在修改密码...",
                                    move |v| {
                                        v.change_password(&pwd_for_task)
                                            .map(|_| "密码已修改成功".to_string())
                                            .map_err(|e| e.to_string())
                                    },
                                );
                                old_pwd.zeroize();
                                new_pwd.zeroize();
                                confirm.zeroize();
                                self.change_password_pending = true;
                            }
                        }
                        ui.add_space(10.0);
                        if ui
                            .add_sized([100.0, 32.0], egui::Button::new("取消".to_string()))
                            .clicked()
                        {
                            zeroize_password_string(&mut self.change_old_password);
                            zeroize_password_string(&mut self.change_new_password);
                            zeroize_password_string(&mut self.change_new_password_confirm);
                            self.show_change_password = false;
                        }
                    });
                });
            });
    }

    // ===== 重命名文件对话框 =====

    fn draw_rename_dialog(&mut self, ctx: &egui::Context) {
        let blind_index = match self.rename_target {
            Some(bi) => bi,
            None => return,
        };
        let old_name = self.rename_old_name.clone();
        egui::Window::new("重命名文件")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .fixed_size([380.0, 160.0])
            .show(ctx, |ui| {
                ui.add_space(12.0);
                ui.vertical_centered(|ui| {
                    ui.label(
                        RichText::new(format!("当前名称: {}", old_name))
                            .size(13.0)
                            .color(Color32::GRAY),
                    );
                });
                ui.add_space(8.0);

                ui.horizontal(|ui| {
                    ui.add_sized([70.0, 24.0], egui::Label::new("新名称:"));
                    ui.add(
                        TextEdit::singleline(&mut self.rename_new_name)
                            .hint_text("输入新文件名")
                            .desired_width(f32::INFINITY),
                    );
                });

                ui.add_space(2.0);
                ui.horizontal(|ui| {
                    ui.add_space(70.0);
                    ui.label(
                        RichText::new("⚠ 请勿修改文件后缀名")
                            .size(11.0)
                            .color(C_WARNING),
                    );
                });
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 0.0;
                    let total_w = 250.0;
                    ui.add_space((ui.available_width() - total_w).max(0.0) / 2.0);
                    if ui
                        .add_sized(
                            [140.0, 32.0],
                            egui::Button::new(
                                RichText::new("确认重命名").size(14.0).color(Color32::WHITE),
                            )
                            .fill(C_PRIMARY),
                        )
                        .clicked()
                    {
                        let new_name = self.rename_new_name.clone();
                        // 检查后缀是否被修改
                        let old_ext = old_name.rsplit('.').next().unwrap_or("");
                        let new_ext = new_name.rsplit('.').next().unwrap_or("");
                        if !old_ext.is_empty()
                            && old_ext != new_ext
                            && old_ext.len() < new_name.len()
                        {
                            self.ext_warning_old_name = old_name.clone();
                            self.ext_warning_new_name = new_name.clone();
                            self.ext_warning_rename = Some((blind_index, new_name));
                            self.show_ext_warning = true;
                            // 不关闭重命名对话框，留待用户从警告对话框确认/取消
                        } else {
                            self.execute_rename(ctx, blind_index, &new_name);
                            self.rename_target = None;
                        }
                    }
                    ui.add_space(10.0);
                    if ui
                        .add_sized([100.0, 32.0], egui::Button::new("取消".to_string()))
                        .clicked()
                    {
                        self.rename_target = None;
                    }
                });
                if ctx.input(|i| i.key_pressed(egui::Key::Enter)) {
                    let new_name = self.rename_new_name.clone();
                    let old_ext = old_name.rsplit('.').next().unwrap_or("");
                    let new_ext = new_name.rsplit('.').next().unwrap_or("");
                    if !old_ext.is_empty()
                        && old_ext != new_ext
                        && old_ext.len() < new_name.len()
                    {
                        self.ext_warning_old_name = old_name.clone();
                        self.ext_warning_new_name = new_name.clone();
                        self.ext_warning_rename = Some((blind_index, new_name));
                        self.show_ext_warning = true;
                    } else {
                        self.execute_rename(ctx, blind_index, &new_name);
                        self.rename_target = None;
                    }
                }
            });
    }

    // ===== 目录重命名对话框 =====

    fn draw_rename_dir_dialog(&mut self, ctx: &egui::Context) {
        let rename_dir_path = match &self.rename_dir.clone() {
            Some(d) => d.clone(),
            None => return,
        };
        let display_name = rename_dir_path
            .rsplit('/')
            .next()
            .unwrap_or(&rename_dir_path)
            .to_string();
        egui::Window::new("重命名目录")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .fixed_size([380.0, 160.0])
            .show(ctx, |ui| {
                ui.add_space(12.0);
                ui.vertical_centered(|ui| {
                    ui.label(
                        RichText::new(format!("目录: {}", display_name))
                            .size(13.0)
                            .color(Color32::GRAY),
                    );
                });
                ui.add_space(8.0);

                ui.horizontal(|ui| {
                    ui.add_sized([70.0, 24.0], egui::Label::new("新名称:"));
                    ui.add(
                        TextEdit::singleline(&mut self.rename_dir_new_name)
                            .hint_text("输入新目录名")
                            .desired_width(f32::INFINITY),
                    );
                });

                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 0.0;
                    let total_w = 250.0;
                    ui.add_space((ui.available_width() - total_w).max(0.0) / 2.0);
                    if ui
                        .add_sized(
                            [140.0, 32.0],
                            egui::Button::new(
                                RichText::new("确认重命名").size(14.0).color(Color32::WHITE),
                            )
                            .fill(C_PRIMARY),
                        )
                        .clicked()
                    {
                        let new_name = self.rename_dir_new_name.trim().to_string();
                        if !new_name.is_empty() {
                            let new_dir = if let Some(parent_end) = rename_dir_path.rfind('/') {
                                format!("{}/{}", &rename_dir_path[..parent_end], new_name)
                            } else {
                                new_name.clone()
                            };
                            let old_dir = rename_dir_path.clone();
                            run_task_mut(
                                &self.vault.clone().unwrap(),
                                &self.pending_result,
                                &mut self.task_busy,
                                &mut self.task_busy_message,
                                ctx,
                                "正在重命名目录...",
                                move |guard| {
                                    guard
                                        .rename_directory(&old_dir, &new_dir)
                                        .map(|_| format!("目录重命名成功（{} 个文件）", new_name))
                                        .map_err(|e| e.to_string())
                                },
                            );
                        } else {
                            set_pending(&self.pending_result, Err("目录名不能为空".to_string()));
                        }
                        self.rename_dir = None;
                    }
                    ui.add_space(10.0);
                    if ui
                        .add_sized([100.0, 32.0], egui::Button::new("取消".to_string()))
                        .clicked()
                    {
                        self.rename_dir = None;
                    }
                });
            });
    }

    // ===== SM2 签名 =====

    fn draw_sm2_sign_dialog(&mut self, ctx: &egui::Context) {
        if !self.show_sm2_sign {
            return;
        }
        egui::Window::new("SM2 签名")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .fixed_size([360.0, 150.0])
            .show(ctx, |ui| {
                ui.add_space(16.0);
                ui.vertical_centered(|ui| {
                    ui.label("选择文件进行 SM2 数字签名");
                });
                ui.add_space(16.0);
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 0.0;
                    let total_w = 290.0;
                    ui.add_space((ui.available_width() - total_w).max(0.0) / 2.0);
                    let clicked = ui
                        .add_sized(
                            [180.0, 36.0],
                            egui::Button::new(
                                RichText::new("选择文件并签名")
                                    .size(14.0)
                                    .color(Color32::WHITE),
                            )
                            .fill(C_PRIMARY),
                        )
                        .clicked();
                    ui.add_space(10.0);
                    if ui
                        .add_sized([100.0, 36.0], egui::Button::new("取消".to_string()))
                        .clicked()
                    {
                        self.show_sm2_sign = false;
                    }
                    if clicked {
                        if let Some(file) = rfd::FileDialog::new()
                            .set_title("选择要签名的文件")
                            .pick_file()
                        {
                            let sig_path = file.with_extension("sig");
                            if let Some(save) = rfd::FileDialog::new()
                                .set_title("保存签名")
                                .set_file_name(sig_path.file_name().unwrap().to_str().unwrap())
                                .save_file()
                            {
                                if let Some(ref vault_arc) = self.vault
                                    && let Ok(v) = vault_arc.lock()
                                {
                                    let data = match std::fs::read(&file) {
                                        Ok(d) => d,
                                        Err(e) => {
                                            set_pending(
                                                &self.pending_result,
                                                Err(format!("读取文件失败: {}", e)),
                                            );
                                            self.show_sm2_sign = false;
                                            return;
                                        }
                                    };
                                    match v.sm2_sign(&data) {
                                        Ok(sig) => {
                                            let _ = std::fs::write(&save, sig);
                                            set_pending(
                                                &self.pending_result,
                                                Ok(format!("SM2 签名完成: {}", save.display())),
                                            );
                                        }
                                        Err(e) => {
                                            set_pending(
                                                &self.pending_result,
                                                Err(format!("签名失败: {}", e)),
                                            );
                                        }
                                    }
                                }
                            }
                            self.show_sm2_sign = false;
                        }
                    }
                });
            });
    }

    // ===== SM2 验签 =====

    fn draw_sm2_verify_dialog(&mut self, ctx: &egui::Context) {
        if !self.show_sm2_verify {
            return;
        }
        egui::Window::new("SM2 验签")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .fixed_size([360.0, 150.0])
            .show(ctx, |ui| {
                ui.add_space(16.0);
                ui.vertical_centered(|ui| {
                    ui.label("选择原始文件和签名文件进行 SM2 签名验证");
                });
                ui.add_space(16.0);
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 0.0;
                    let total_w = 290.0;
                    ui.add_space((ui.available_width() - total_w).max(0.0) / 2.0);
                    if ui
                        .add_sized(
                            [180.0, 36.0],
                            egui::Button::new(
                                RichText::new("选择文件并验证")
                                    .size(14.0)
                                    .color(Color32::WHITE),
                            )
                            .fill(C_PRIMARY),
                        )
                        .clicked()
                    {
                        let file = rfd::FileDialog::new().set_title("选择原始文件").pick_file();
                        let sig_file = rfd::FileDialog::new()
                            .set_title("选择签名文件（.sig）")
                            .pick_file();
                        if let (Some(f), Some(s)) = (file, sig_file) {
                            if let Some(ref vault_arc) = self.vault
                                && let Ok(v) = vault_arc.lock()
                            {
                                let data = match std::fs::read(&f) {
                                    Ok(d) => d,
                                    Err(e) => {
                                        set_pending(
                                            &self.pending_result,
                                            Err(format!("读取文件失败: {}", e)),
                                        );
                                        self.show_sm2_verify = false;
                                        return;
                                    }
                                };
                                let sig_bytes = match std::fs::read(&s) {
                                    Ok(d) if d.len() == 64 => {
                                        let mut arr = [0u8; 64];
                                        arr.copy_from_slice(&d);
                                        arr
                                    }
                                    _ => {
                                        set_pending(
                                            &self.pending_result,
                                            Err("签名文件无效（需 64 字节）".to_string()),
                                        );
                                        self.show_sm2_verify = false;
                                        return;
                                    }
                                };
                                match v.sm2_verify(&data, &sig_bytes) {
                                    Ok(true) => set_pending(
                                        &self.pending_result,
                                        Ok("SM2 签名验证通过 ✓".to_string()),
                                    ),
                                    Ok(false) => set_pending(
                                        &self.pending_result,
                                        Err("SM2 签名验证失败 ✗".to_string()),
                                    ),
                                    Err(e) => set_pending(
                                        &self.pending_result,
                                        Err(format!("验签错误: {}", e)),
                                    ),
                                }
                            }
                        }
                        self.show_sm2_verify = false;
                    }
                    ui.add_space(10.0);
                    if ui
                        .add_sized([100.0, 36.0], egui::Button::new("取消".to_string()))
                        .clicked()
                    {
                        self.show_sm2_verify = false;
                    }
                });
            });
    }

    // ===== KEK 分片 =====

    fn draw_kek_split_dialog(&mut self, ctx: &egui::Context) {
        if !self.show_kek_split {
            return;
        }
        egui::Window::new("KEK 分片（Shamir 秘密共享）")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .fixed_size([460.0, 320.0])
            .show(ctx, |ui| {
                ui.add_space(12.0);
                ui.vertical_centered(|ui| {
                    ui.label("将保险箱密钥拆分为多份，任意 t 份可恢复");
                });
                ui.add_space(8.0);

                ui.horizontal(|ui| {
                    ui.add_sized([70.0, 24.0], egui::Label::new("总份数 (n):"));
                    ui.add(
                        TextEdit::singleline(&mut self.kek_split_n).desired_width(f32::INFINITY),
                    );
                });
                ui.horizontal(|ui| {
                    ui.add_sized([70.0, 24.0], egui::Label::new("门限值 (t):"));
                    ui.add(
                        TextEdit::singleline(&mut self.kek_split_t).desired_width(f32::INFINITY),
                    );
                });

                ui.add_space(8.0);
                if self.kek_split_result.is_empty() {
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 0.0;
                        let total_w = 250.0;
                        ui.add_space((ui.available_width() - total_w).max(0.0) / 2.0);
                        if ui
                            .add_sized(
                                [140.0, 32.0],
                                egui::Button::new(
                                    RichText::new("生成分片").size(14.0).color(Color32::WHITE),
                                )
                                .fill(C_PRIMARY),
                            )
                            .clicked()
                        {
                            let n: u8 = self.kek_split_n.trim().parse().unwrap_or(0);
                            let t: u8 = self.kek_split_t.trim().parse().unwrap_or(0);
                            if t < 2 || n < t {
                                set_pending(
                                    &self.pending_result,
                                    Err("参数无效：t ≥ 2 且 n ≥ t".to_string()),
                                );
                            } else if let Some(ref vault_arc) = self.vault
                                && let Ok(v) = vault_arc.lock()
                            {
                                match v.split_kek(n, t) {
                                    Ok(shares) => {
                                        self.kek_split_result = shares;
                                    }
                                    Err(e) => {
                                        set_pending(
                                            &self.pending_result,
                                            Err(format!("分片失败: {}", e)),
                                        );
                                    }
                                }
                            }
                        }
                        ui.add_space(10.0);
                        if ui
                            .add_sized(
                                [100.0, 32.0],
                                egui::Button::new(RichText::new("取消").size(14.0)),
                            )
                            .clicked()
                        {
                            self.show_kek_split = false;
                        }
                    });
                } else {
                    ui.vertical_centered(|ui| {
                        ui.label(
                            RichText::new("请安全保管各份子秘密！")
                                .color(C_WARNING)
                                .strong(),
                        );
                        ui.add_space(4.0);
                        Frame::none()
                            .fill(C_TABLE_HEADER_BG)
                            .inner_margin(Margin::symmetric(6.0, 3.0))
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.spacing_mut().item_spacing.x = 0.0;
                                    ui.add_sized(
                                        [40.0, 18.0],
                                        egui::Label::new(RichText::new("序号").size(11.0).strong()),
                                    );
                                    ui.add_sized(
                                        [340.0, 18.0],
                                        egui::Label::new(
                                            RichText::new("子秘密（hex）").size(11.0).strong(),
                                        ),
                                    );
                                });
                            });
                        ScrollArea::vertical().max_height(140.0).show(ui, |ui| {
                            for (i, share) in self.kek_split_result.iter().enumerate() {
                                Frame::none()
                                    .fill(C_ROW_ALT_BG)
                                    .inner_margin(Margin::symmetric(6.0, 2.0))
                                    .show(ui, |ui| {
                                        ui.horizontal(|ui| {
                                            ui.spacing_mut().item_spacing.x = 0.0;
                                            ui.add_sized(
                                                [40.0, 18.0],
                                                egui::Label::new(
                                                    RichText::new(format!(
                                                        "{:02}/{:02}",
                                                        i + 1,
                                                        self.kek_split_result.len()
                                                    ))
                                                    .size(11.0),
                                                ),
                                            );
                                            ui.add_sized(
                                                [340.0, 18.0],
                                                egui::Label::new(
                                                    RichText::new(share)
                                                        .size(11.0)
                                                        .color(Color32::from_rgb(0x33, 0x33, 0x33)),
                                                ),
                                            );
                                        });
                                    });
                            }
                        });
                        ui.add_space(6.0);
                        if ui.button("关闭").clicked() {
                            self.show_kek_split = false;
                        }
                    });
                }
            });
    }

    // ===== KEK 恢复 =====

    pub(super) fn draw_kek_recover_dialog(&mut self, ctx: &egui::Context) {
        if !self.show_kek_recover {
            return;
        }
        egui::Window::new("KEK 恢复（Shamir 秘密共享）")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .fixed_size([480.0, 400.0])
            .show(ctx, |ui| {
                ui.add_space(12.0);
                ui.vertical_centered(|ui| {
                    ui.label("输入 t 份子秘密和新密码恢复保险箱访问");
                });
                ui.add_space(8.0);

                ui.horizontal(|ui| {
                    ui.add_sized([70.0, 24.0], egui::Label::new("门限 (t):"));
                    ui.add(
                        TextEdit::singleline(&mut self.kek_recover_t).desired_width(f32::INFINITY),
                    );
                });

                ui.add_space(4.0);
                ui.label("子秘密（每行一份 hex）:");
                let avail_h = ui.available_height().max(80.0);
                ScrollArea::vertical()
                    .max_height(avail_h - 80.0)
                    .show(ui, |ui| {
                        let mut remove_idx: Option<usize> = None;
                        for (i, share) in self.kek_recover_shares.iter_mut().enumerate() {
                            ui.horizontal(|ui| {
                                ui.add_sized(
                                    [24.0, 20.0],
                                    egui::Label::new(format!("#{}:", i + 1)),
                                );
                                ui.add(TextEdit::singleline(share).desired_width(f32::INFINITY));
                                if ui.button("✕").clicked() {
                                    remove_idx = Some(i);
                                }
                            });
                        }
                        if let Some(idx) = remove_idx {
                            self.kek_recover_shares.remove(idx);
                        }
                        ui.add_space(2.0);
                        if ui.button("+ 添加子秘密").clicked() {
                            self.kek_recover_shares.push(String::new());
                        }
                    });

                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.add_sized([70.0, 24.0], egui::Label::new("新密码:"));
                    ui.add(
                        TextEdit::singleline(&mut self.kek_recover_new_password)
                            .password(true)
                            .desired_width(f32::INFINITY),
                    );
                });
                ui.horizontal(|ui| {
                    ui.add_sized([70.0, 24.0], egui::Label::new("确认密码:"));
                    ui.add(
                        TextEdit::singleline(&mut self.kek_recover_confirm_password)
                            .password(true)
                            .desired_width(f32::INFINITY),
                    );
                });

                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 0.0;
                    let total_w = 250.0;
                    ui.add_space((ui.available_width() - total_w).max(0.0) / 2.0);
                    if ui
                        .add_sized(
                            [140.0, 32.0],
                            egui::Button::new(
                                RichText::new("恢复保险箱").size(14.0).color(Color32::WHITE),
                            )
                            .fill(C_PRIMARY),
                        )
                        .clicked()
                    {
                        let t: u8 = self.kek_recover_t.trim().parse().unwrap_or(0);
                        let valid_shares: Vec<String> = self
                            .kek_recover_shares
                            .iter()
                            .filter(|s| !s.trim().is_empty())
                            .cloned()
                            .collect();
                        if valid_shares.len() < t as usize {
                            set_pending(
                                &self.pending_result,
                                Err(format!("需要至少 {} 份有效子秘密", t)),
                            );
                        } else if self.kek_recover_new_password.is_empty() {
                            set_pending(&self.pending_result, Err("新密码不能为空".to_string()));
                        } else if self.kek_recover_new_password != self.kek_recover_confirm_password
                        {
                            set_pending(
                                &self.pending_result,
                                Err("两次输入的密码不一致".to_string()),
                            );
                        } else {
                            let new_pwd = self.kek_recover_new_password.clone();
                            let vault_dir = self.vault_dir.clone();
                            self.task_busy = true;
                            self.task_busy_message = "正在恢复 KEK...".to_string();
                            spawn_task(ctx, self.pending_result.clone(), move || {
                                crate::vault::Vault::recover_from_shares(
                                    &vault_dir,
                                    &valid_shares,
                                    t,
                                    &new_pwd,
                                )
                                .map(|_| "KEK 恢复成功，请重新登录".to_string())
                                .map_err(|e| e.to_string())
                            });
                            self.show_kek_recover = false;
                        }
                    }
                    ui.add_space(10.0);
                    if ui
                        .add_sized([100.0, 32.0], egui::Button::new("取消".to_string()))
                        .clicked()
                    {
                        self.show_kek_recover = false;
                    }
                });
            });
    }

    // ===== 导出/剪切通用辅助 =====

    /// 根据 `export_overwrite_choices` 过滤用户勾选的盲索引和文件名
    fn filter_export_overwrite_selection(
        &self,
        selected: &Option<Vec<[u8; 32]>>,
        files: &[String],
    ) -> (Vec<[u8; 32]>, Vec<String>) {
        let filtered: Vec<[u8; 32]> = selected
            .as_ref()
            .map(|sel| {
                sel.iter()
                    .enumerate()
                    .filter(|(i, _)| {
                        files
                            .get(*i)
                            .and_then(|n| self.export_overwrite_choices.get(n))
                            .copied()
                            .unwrap_or(false)
                    })
                    .map(|(_, bi)| *bi)
                    .collect()
            })
            .unwrap_or_default();

        let filtered_names: Vec<String> = files
            .iter()
            .enumerate()
            .filter(|(i, _)| {
                files
                    .get(*i)
                    .and_then(|n| self.export_overwrite_choices.get(n))
                    .copied()
                    .unwrap_or(false)
            })
            .map(|(_, n)| n.clone())
            .collect();

        (filtered, filtered_names)
    }
}

/// 格式化基准测试结果为纯文本（供复制到剪贴板）
fn format_bench_results(r: &BenchResults) -> String {
    let mut s = String::new();
    s.push_str("===== Sancove 基准测试结果 =====\n\n");
    s.push_str("SM4 加密吞吐量 (1MB 数据):\n");
    s.push_str(&format!(
        "  基线 (S-Box):     {:.1} MB/s\n",
        r.sm4_baseline_mbps
    ));
    s.push_str(&format!(
        "  优化 (T-Table):  {:.1} MB/s\n",
        r.sm4_t_table_mbps
    ));
    s.push_str(&format!("  常数时间 (CT):   {:.1} KB/s\n", r.sm4_ct_kbps));
    s.push_str(&format!("  加速比:           {:.2}x\n", r.speedup));
    s.push_str(&format!("\nSM4-CBC 密钥包裹 (1MB):\n"));
    s.push_str(&format!("  加密: {:.1} MB/s\n", r.sm4_cbc_encrypt_mbps));
    s.push_str(&format!("  解密: {:.1} MB/s\n", r.sm4_cbc_decrypt_mbps));
    s.push_str(&format!("\nHMAC-SM3 完整性校验:\n"));
    s.push_str(&format!("  吞吐量: {:.1} MB/s\n", r.hmac_sm3_mbps));
    s.push_str(&format!("\nPBKDF2-SM3 密钥派生:\n"));
    s.push_str(&format!("  100,000 次迭代:  {:.0} ms\n", r.pbkdf2_100k_ms));
    s.push_str(&format!("  600,000 次迭代:  {:.0} ms\n", r.pbkdf2_ms));
    s.push_str(&format!("\nSM2 公钥密码:\n"));
    s.push_str(&format!("  密钥生成: {:.1} ms\n", r.sm2_keygen_ms));
    s.push_str(&format!("  签名:     {:.1} ms\n", r.sm2_sign_ms));
    s.push_str(&format!("  验签:     {:.1} ms\n", r.sm2_verify_ms));
    s.push_str(&format!("\nShamir 秘密共享 (KEK 灾备):\n"));
    s.push_str(&format!("  5-of-3 分片: {:.1} μs\n", r.shamir_split_us));
    s.push_str(&format!("  3 份恢复:    {:.1} μs\n", r.shamir_recover_us));
    s.push_str(&format!("\n全链路文件操作:\n"));
    if let Some(v) = r.import_1kb_us {
        s.push_str(&format!("  1KB 导入:  {:.1} μs\n", v));
    }
    if let Some(v) = r.export_1kb_us {
        s.push_str(&format!("  1KB 导出:  {:.1} μs\n", v));
    }
    if let Some(v) = r.import_1mb_ms {
        s.push_str(&format!("  1MB 导入:  {:.1} ms\n", v));
    }
    if let Some(v) = r.export_1mb_ms {
        s.push_str(&format!("  1MB 导出:  {:.1} ms\n", v));
    }
    if let Some(v) = r.import_10mb_ms {
        s.push_str(&format!("  10MB 导入: {:.1} ms\n", v));
    }
    if let Some(v) = r.export_10mb_ms {
        s.push_str(&format!("  10MB 导出: {:.1} ms\n", v));
    }
    if let Some(v) = r.batch_import_10x1mb_ms {
        s.push_str(&format!("  批量导入 10×1MB: {:.1} ms\n", v));
    }
    s.push_str(&format!("\n保险箱操作:\n"));
    s.push_str(&format!("  打开（登录）: {:.0} ms\n", r.vault_open_ms));
    s.push_str("\n================================");
    s
}
