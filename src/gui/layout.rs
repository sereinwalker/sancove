//! GUI 主界面布局：工具栏、文件列表、面包屑导航

use eframe::egui;
use egui::{Color32, Frame, Margin, RichText, ScrollArea, TextEdit, Vec2};

use super::app::VaultApp;
use super::icons;
use super::task::{run_task_mut, set_pending, zeroize_password_string};
use super::types::{
    C_BG, C_ERROR, C_EXPORT_BTN, C_HEADER, C_PRIMARY, C_TOOLBAR_BG, C_TOOLBAR_TEXT,
};
use crate::audit_log::AuditEntryType;

/// 文件列表中除文件名外其他列（复选框+大小+时间+4个操作按钮）的总宽度
const NON_FILENAME_WIDTH: f32 = 364.0;

impl VaultApp {
    // ============================================================
    // 主界面
    // ============================================================

    pub(super) fn draw_main_screen(&mut self, ctx: &egui::Context) {
        // ===== 顶部工具栏 =====
        egui::TopBottomPanel::top("toolbar")
            .frame(Frame::none().fill(C_TOOLBAR_BG))
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.add_space(12.0);
                    ui.label(
                        RichText::new("保密文件库")
                            .size(16.0)
                            .color(C_PRIMARY)
                            .strong(),
                    );
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new(self.vault_dir.to_string_lossy().to_string())
                            .size(12.0)
                            .color(Color32::from_rgb(0x66, 0x77, 0x99)),
                    );

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.spacing_mut().item_spacing.x = 0.0;

                        // 登出
                        if ui
                            .add(
                                egui::Button::new(
                                    RichText::new("登出").size(13.0).color(Color32::WHITE),
                                )
                                .fill(Color32::from_rgb(0xcc, 0x33, 0x33))
                                .min_size(Vec2::new(60.0, 26.0)),
                            )
                            .clicked()
                        {
                            if self.task_busy {
                                set_pending(
                                    &self.pending_result,
                                    Err("请等待后台任务完成后再登出".to_string()),
                                );
                            } else {
                                self.logged_in = false;
                                self.vault = None;
                                self.files.clear();
                                zeroize_password_string(&mut self.password);
                                zeroize_password_string(&mut self.password_confirm);
                                zeroize_password_string(&mut self.change_old_password);
                                zeroize_password_string(&mut self.change_new_password);
                                zeroize_password_string(&mut self.change_new_password_confirm);
                            }
                            return;
                        }
                        ui.add_space(6.0);

                        // 管理 ▼
                        ui.menu_button(
                            RichText::new(format!("管理 {}", icons::ICON_MENU))
                                .size(13.0)
                                .color(C_TOOLBAR_TEXT)
                                .strong(),
                            |ui| {
                                ui.set_min_width(120.0);
                                if ui.button("修改密码").clicked() {
                                    self.show_change_password = true;
                                    zeroize_password_string(&mut self.change_old_password);
                                    zeroize_password_string(&mut self.change_new_password);
                                    zeroize_password_string(&mut self.change_new_password_confirm);
                                    ui.close_menu();
                                }
                                ui.separator();
                                if ui.button("备份").clicked() {
                                    if let Some(dir) = rfd::FileDialog::new()
                                        .set_title("选择备份目标目录")
                                        .pick_folder()
                                    {
                                        let dir2 = dir.clone();
                                        let dir_display = dir.display().to_string();
                                        run_task_mut(
                                            &self.vault.clone().unwrap(),
                                            &self.pending_result,
                                            &mut self.task_busy,
                                            &mut self.task_busy_message,
                                            ctx,
                                            "正在备份...",
                                            move |v| {
                                                v.backup_to(&dir2)
                                                    .map(|_| format!("备份完成: {}", dir_display))
                                                    .map_err(|e| e.to_string())
                                            },
                                        );
                                    }
                                    ui.close_menu();
                                }
                                ui.separator();
                                if ui.button("KEK 分片").clicked() {
                                    self.show_kek_split = true;
                                    self.kek_split_n.clear();
                                    self.kek_split_t.clear();
                                    self.kek_split_result.clear();
                                    ui.close_menu();
                                }
                            },
                        );
                        ui.add_space(4.0);

                        // 工具 ▼
                        ui.menu_button(
                            RichText::new(format!("工具 {}", icons::ICON_MENU))
                                .size(13.0)
                                .color(C_TOOLBAR_TEXT)
                                .strong(),
                            |ui| {
                                ui.set_min_width(120.0);
                                if ui.button("刷新").clicked() {
                                    self.refresh_files();
                                    self.gui_log(
                                        AuditEntryType::GuiAction,
                                        &format!("刷新文件列表 ({} 个文件)", self.files.len()),
                                    );
                                    set_pending(
                                        &self.pending_result,
                                        Ok(format!("已刷新，共 {} 个文件", self.files.len())),
                                    );
                                    ui.close_menu();
                                }
                                ui.separator();
                                if ui.button("公钥").clicked() {
                                    if let Some(ref vault_arc) = self.vault
                                        && let Ok(v) = vault_arc.lock()
                                        && let Some(pk) = v.get_sm2_pub_key().map(|k| {
                                            k.iter()
                                                .map(|b| format!("{:02x}", b))
                                                .collect::<String>()
                                        })
                                    {
                                        ui.ctx().output_mut(|o| o.copied_text = pk);
                                        self.gui_log(
                                            AuditEntryType::GuiAction,
                                            "复制 SM2 公钥到剪贴板",
                                        );
                                        set_pending(
                                            &self.pending_result,
                                            Ok("SM2 公钥已复制到剪贴板".to_string()),
                                        );
                                    }
                                    ui.close_menu();
                                }
                                ui.separator();
                                if ui.button("审计日志").clicked() {
                                    self.gui_log(AuditEntryType::GuiAction, "查看审计日志");
                                    if let Some(ref vault_arc) = self.vault
                                        && let Ok(v) = vault_arc.lock()
                                    {
                                        let entries =
                                            v.audit_log_get_recent(500).unwrap_or_default();
                                        self.audit_log_entries =
                                            super::types::audit_entries_to_display(&entries, false);
                                    }
                                    self.show_audit_log = true;
                                    ui.close_menu();
                                }
                                ui.separator();
                                if ui.button("基准测试").clicked() && !self.bench_running {
                                    self.gui_log(AuditEntryType::GuiAction, "运行基准测试");
                                    self.show_bench = !self.show_bench;
                                    if self.show_bench && self.bench_results.is_none() {
                                        self.spawn_bench_task(ctx);
                                    }
                                    ui.close_menu();
                                }
                                ui.separator();
                                if ui.button("SM2 签名").clicked() {
                                    self.show_sm2_sign = true;
                                    ui.close_menu();
                                }
                                if ui.button("SM2 验签").clicked() {
                                    self.show_sm2_verify = true;
                                    ui.close_menu();
                                }
                            },
                        );
                        ui.add_space(4.0);

                        // 导入 ▼
                        ui.menu_button(
                            RichText::new(format!("导入 {}", icons::ICON_MENU))
                                .size(13.0)
                                .color(C_TOOLBAR_TEXT)
                                .strong(),
                            |ui| {
                                ui.set_min_width(120.0);
                                if ui.button("导入文件").clicked() {
                                    self.start_batch_import();
                                    ui.close_menu();
                                }
                                ui.separator();
                                if ui.button("导入文件夹").clicked() {
                                    self.start_folder_import();
                                    ui.close_menu();
                                }
                            },
                        );
                        ui.add_space(6.0);

                        // 后台任务提示
                        if self.task_busy {
                            ui.add(egui::Spinner::new().color(C_TOOLBAR_TEXT).size(16.0));
                            ui.add_space(4.0);
                            ui.label(
                                RichText::new(&self.task_busy_message)
                                    .size(12.0)
                                    .color(C_TOOLBAR_TEXT),
                            );
                        }
                        ui.add_space(12.0);
                    });
                });
            });

        // ===== 文件列表区 =====
        egui::CentralPanel::default()
            .frame(Frame::none().fill(C_BG))
            .show(ctx, |ui| {
                ui.add_space(4.0);
                self.draw_file_list(ui);
                ui.add_space(2.0);
                Frame::none()
                    .fill(ui.style().visuals.window_fill())
                    .stroke(egui::Stroke::new(1.0, Color32::from_gray(0xcc)))
                    .inner_margin(Margin::symmetric(8.0, 4.0))
                    .show(ui, |ui| {
                        ui.label(
                            RichText::new(format!("文件: {}", self.files.len()))
                                .size(13.0)
                                .strong(),
                        );
                    });
            });
    }

    // -------- 文件列表方法 --------

    /// 刷新文件列表
    pub(super) fn refresh_files(&mut self) {
        let vault = match self.vault.clone() {
            Some(v) => v,
            None => return,
        };
        match vault.lock() {
            Ok(v) => match v.list_files() {
                Ok(files) => {
                    self.files = files.into_iter().map(|f| f.into()).collect();
                    self.files.sort_by_key(|b| std::cmp::Reverse(b.created_at));
                }
                Err(e) => {
                    set_pending(&self.pending_result, Err(format!("刷新列表失败: {}", e)));
                }
            },
            Err(e) => {
                set_pending(&self.pending_result, Err(format!("保险箱访问错误: {}", e)));
            }
        }
    }

    /// 获取当前目录下的可见条目
    pub(super) fn get_vault_listing(&self) -> Vec<super::types::VaultDirEntry> {
        let prefix = if self.current_vault_dir.is_empty() {
            String::new()
        } else {
            format!("{}/", self.current_vault_dir)
        };

        let mut dirs: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        let mut file_entries: Vec<super::types::VaultDirEntry> = Vec::new();

        for f in &self.files {
            let path = &f.filename;
            if !self.current_vault_dir.is_empty() && !path.starts_with(&prefix) {
                continue;
            }
            let relative = if self.current_vault_dir.is_empty() {
                path.as_str()
            } else {
                &path[prefix.len()..]
            };
            if relative.is_empty() {
                continue;
            }

            if let Some(slash_pos) = relative.find('/') {
                let dir_name = &relative[..slash_pos];
                if !dir_name.is_empty() {
                    dirs.insert(dir_name.to_string());
                }
            } else {
                file_entries.push(super::types::VaultDirEntry {
                    name: relative.to_string(),
                    is_dir: false,
                    blind_index: Some(f.blind_index),
                    size_display: f.size_display.clone(),
                    time_display: f.created_at_display.clone(),
                });
            }
        }

        let mut result: Vec<super::types::VaultDirEntry> = dirs
            .into_iter()
            .map(|d| super::types::VaultDirEntry {
                name: d,
                is_dir: true,
                blind_index: None,
                size_display: String::new(),
                time_display: String::new(),
            })
            .collect();
        result.extend(file_entries);
        result
    }

    /// 绘制面包屑导航
    pub(super) fn draw_breadcrumb(&mut self, ui: &mut egui::Ui) {
        if self.current_vault_dir.is_empty() {
            if !self.files.is_empty() {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 2.0;
                    ui.label(RichText::new("根目录").size(13.0).color(Color32::GRAY));
                    ui.label(RichText::new("›").size(14.0).color(Color32::GRAY));
                    ui.label(
                        RichText::new("所有文件")
                            .size(12.0)
                            .color(Color32::from_rgb(0x88, 0x88, 0x88)),
                    );
                });
                ui.add_space(4.0);
            }
            return;
        }

        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 2.0;
            {
                let resp = ui.add(egui::Button::new(
                    RichText::new("根目录")
                        .size(13.0)
                        .color(C_PRIMARY)
                        .underline(),
                ));
                if resp.clicked() {
                    self.current_vault_dir.clear();
                    return;
                }
            }

            let parts: Vec<&str> = self.current_vault_dir.split('/').collect();
            let mut accumulated = String::new();
            for (i, part) in parts.iter().enumerate() {
                ui.label(RichText::new("›").size(14.0).color(Color32::GRAY));
                if i == parts.len() - 1 {
                    ui.label(RichText::new(*part).size(13.0).strong());
                } else {
                    accumulated.push_str(part);
                    let target = accumulated.clone();
                    {
                        let resp = ui.add(egui::Button::new(
                            RichText::new(*part).size(13.0).color(C_PRIMARY).underline(),
                        ));
                        if resp.clicked() {
                            self.current_vault_dir = target;
                            return;
                        }
                    }
                    accumulated.push('/');
                }
            }
        });
        ui.add_space(6.0);
    }

    /// 绘制文件行
    pub(super) fn draw_file_row(
        &mut self,
        ui: &mut egui::Ui,
        blind_idx: [u8; 32],
        file_name: &str,
        size_str: &str,
        time_str: &str,
        bg: Color32,
    ) {
        let row_frame = Frame::none()
            .fill(bg)
            .inner_margin(Margin::symmetric(8.0, 4.0));
        let _row_resp = row_frame.show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 0.0;
                ui.set_height(22.0);

                let mut checked = self.selected_indices.contains(&blind_idx);
                if ui
                    .add_sized([24.0, 20.0], egui::Checkbox::new(&mut checked, ""))
                    .changed()
                {
                    if checked {
                        self.selected_indices.insert(blind_idx);
                    } else {
                        self.selected_indices.remove(&blind_idx);
                    }
                }

                let fname_w = (ui.available_width() - NON_FILENAME_WIDTH).max(80.0);
                ui.add_sized(
                    [fname_w, 20.0],
                    egui::Label::new(RichText::new(file_name).size(13.0)),
                );
                ui.add_sized(
                    [80.0, 20.0],
                    egui::Label::new(
                        RichText::new(size_str)
                            .size(13.0)
                            .color(Color32::from_rgb(0x66, 0x66, 0x66)),
                    ),
                );
                ui.add_sized(
                    [100.0, 20.0],
                    egui::Label::new(RichText::new(time_str).size(12.0).color(Color32::GRAY)),
                );

                if ui
                    .add_sized(
                        [40.0, 20.0],
                        egui::Button::new(RichText::new("导出").size(12.0)).frame(false),
                    )
                    .clicked()
                {
                    let ctx = ui.ctx().clone();
                    self.start_export_by_index(&ctx, blind_idx);
                }
                if ui
                    .add_sized(
                        [40.0, 20.0],
                        egui::Button::new(RichText::new("导出并移除").size(12.0)).frame(false),
                    )
                    .clicked()
                {
                    let ctx = ui.ctx().clone();
                    self.start_cut_by_index(&ctx, blind_idx);
                }
                if ui
                    .add_sized(
                        [40.0, 20.0],
                        egui::Button::new(RichText::new("改名").size(12.0)).frame(false),
                    )
                    .clicked()
                {
                    self.rename_target = Some(blind_idx);
                    self.rename_old_name = file_name.to_string();
                    self.rename_new_name = file_name.to_string();
                }
                if ui
                    .add_sized(
                        [40.0, 20.0],
                        egui::Button::new(RichText::new("删除").size(12.0)).frame(false),
                    )
                    .clicked()
                {
                    self.confirm_remove = Some(blind_idx);
                    self.confirm_remove_filename = file_name.to_string();
                }
            });
        });
        ui.separator();
    }

    /// 绘制文件列表（含搜索、目录结构）
    pub(super) fn draw_file_list(&mut self, ui: &mut egui::Ui) {
        // 标题行 + 搜索框
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(format!("文件列表 ({} 个文件)", self.files.len()))
                    .size(15.0)
                    .strong(),
            );
            if !self.current_vault_dir.is_empty() {
                ui.add_space(8.0);
                if ui
                    .add_sized(
                        [110.0, 24.0],
                        egui::Button::new(
                            RichText::new(icons::fmt_export("导出目录"))
                                .size(12.0)
                                .color(Color32::WHITE),
                        )
                        .fill(C_EXPORT_BTN),
                    )
                    .clicked()
                {
                    let ctx = ui.ctx().clone();
                    let dir = self.current_vault_dir.clone();
                    self.start_directory_export(&ctx, &dir);
                }
            }
            if self.files.is_empty() {
                ui.label(
                    RichText::new("保险箱为空 — 点击工具栏「导入」或拖放文件到窗口添加文件")
                        .size(14.0)
                        .color(Color32::from_rgb(0x99, 0x99, 0x99)),
                );
            }
            if !self.files.is_empty() {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let sq = &mut self.search_query;
                    let search_resp = ui.add_sized(
                        [180.0, 22.0],
                        TextEdit::singleline(sq)
                            .hint_text("搜索文件名...")
                            .desired_width(f32::INFINITY),
                    );
                    if search_resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                        sq.clear();
                    }
                    if !sq.is_empty() {
                        ui.add_space(-2.0);
                        if ui
                            .add_sized(
                                [16.0, 22.0],
                                egui::Button::new(RichText::new(icons::ICON_CLEAR).size(14.0))
                                    .frame(false),
                            )
                            .clicked()
                        {
                            sq.clear();
                        }
                    }
                });
            }
        });
        ui.add_space(6.0);

        self.draw_breadcrumb(ui);

        // 搜索审计日志
        if !self.search_query.is_empty() && self.search_query != self.last_logged_search {
            self.gui_log(
                AuditEntryType::GuiAction,
                &format!("搜索: {}", self.search_query),
            );
            self.last_logged_search = self.search_query.clone();
        } else if self.search_query.is_empty() && !self.last_logged_search.is_empty() {
            self.last_logged_search.clear();
        }

        if self.files.is_empty() {
            return;
        }

        let is_empty_filter = self.search_query.trim().is_empty();
        let query = self.search_query.to_lowercase();
        let filtered_indices: Vec<usize> = if is_empty_filter {
            (0..self.files.len()).collect()
        } else {
            self.files
                .iter()
                .enumerate()
                .filter(|(_, f)| f.filename.to_lowercase().contains(&query))
                .map(|(i, _)| i)
                .collect()
        };

        if !is_empty_filter {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(format!("找到 {} 个匹配文件", filtered_indices.len()))
                        .size(12.0)
                        .color(Color32::from_rgb(0x66, 0x66, 0x99)),
                );
                if ui
                    .add_sized([40.0, 16.0], egui::Button::new("清除").frame(false))
                    .clicked()
                {
                    self.search_query.clear();
                }
            });
            ui.add_space(4.0);
        }

        // 文件列表（可滚动）
        ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                let is_searching = !is_empty_filter;

                // 表头
                let visible_bis: Vec<[u8; 32]> = if is_searching {
                    filtered_indices
                        .iter()
                        .filter(|&&i| i < self.files.len()) // 防越界（后台更新 files 后索引可能过期）
                        .map(|&i| self.files[i].blind_index)
                        .collect()
                } else {
                    self.get_vault_listing()
                        .iter()
                        .filter(|e| !e.is_dir)
                        .filter_map(|e| e.blind_index)
                        .collect()
                };
                let header_frame = Frame::none()
                    .fill(C_HEADER)
                    .inner_margin(Margin::symmetric(8.0, 4.0));
                header_frame.show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 0.0;
                        ui.set_height(24.0);
                        let all_selected = !visible_bis.is_empty()
                            && visible_bis
                                .iter()
                                .all(|bi| self.selected_indices.contains(bi));
                        let mut checked = all_selected;
                        if ui
                            .add_sized([24.0, 20.0], egui::Checkbox::new(&mut checked, ""))
                            .changed()
                        {
                            for bi in &visible_bis {
                                if all_selected {
                                    self.selected_indices.remove(bi);
                                } else {
                                    self.selected_indices.insert(*bi);
                                }
                            }
                        }
                        let fname_w = (ui.available_width() - NON_FILENAME_WIDTH).max(80.0);
                        ui.add_sized(
                            [fname_w, 20.0],
                            egui::Label::new(RichText::new("文件名").strong().size(13.0)),
                        );
                        ui.add_sized(
                            [80.0, 20.0],
                            egui::Label::new(RichText::new("大小").strong().size(13.0)),
                        );
                        ui.add_sized(
                            [100.0, 20.0],
                            egui::Label::new(RichText::new("导入时间").strong().size(13.0)),
                        );
                        ui.allocate_ui_with_layout(
                            egui::vec2(160.0, 20.0),
                            egui::Layout::centered_and_justified(egui::Direction::LeftToRight),
                            |ui| {
                                ui.label(RichText::new("操作").strong().size(13.0));
                            },
                        );
                    });
                });

                // 批量操作栏
                let sel_count = self.selected_indices.len();
                if sel_count > 0 {
                    ui.add_space(2.0);
                    let action_frame = Frame::none()
                        .fill(Color32::from_rgb(0xf0, 0xf5, 0xff))
                        .inner_margin(Margin::symmetric(8.0, 4.0));
                    action_frame.show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.horizontal(|ui| {
                            ui.spacing_mut().item_spacing.x = 0.0;
                            ui.label(
                                RichText::new(format!("已选 {} 项", sel_count))
                                    .size(13.0)
                                    .strong()
                                    .color(C_PRIMARY),
                            );
                            ui.add_space(12.0);
                            if ui
                                .add_sized(
                                    [90.0, 24.0],
                                    egui::Button::new(
                                        RichText::new("批量导出").size(13.0).color(Color32::WHITE),
                                    )
                                    .fill(C_EXPORT_BTN),
                                )
                                .clicked()
                            {
                                self.start_batch_export();
                            }
                            ui.add_space(6.0);
                            if ui
                                .add_sized(
                                    [90.0, 24.0],
                                    egui::Button::new(
                                        RichText::new("批量导出并移除").size(13.0).color(Color32::WHITE),
                                    )
                                    .fill(C_PRIMARY),
                                )
                                .clicked()
                            {
                                self.start_batch_cut();
                            }
                            ui.add_space(6.0);
                            if ui
                                .add_sized(
                                    [90.0, 24.0],
                                    egui::Button::new(
                                        RichText::new("批量删除").size(13.0).color(Color32::WHITE),
                                    )
                                    .fill(C_ERROR),
                                )
                                .clicked()
                            {
                                self.batch_remove_filenames = self
                                    .files
                                    .iter()
                                    .filter(|f| self.selected_indices.contains(&f.blind_index))
                                    .map(|f| f.filename.clone())
                                    .collect();
                                self.show_batch_remove_confirm = true;
                            }
                        });
                    });
                    ui.add_space(2.0);
                }

                // 搜索模式
                if is_searching {
                    if filtered_indices.is_empty() {
                        ui.add_space(20.0);
                        ui.vertical_centered(|ui| {
                            ui.label(
                                RichText::new("未找到匹配的文件")
                                    .size(14.0)
                                    .color(Color32::GRAY),
                            );
                        });
                        return;
                    }
                    for (row_pos, &i) in filtered_indices.iter().enumerate() {
                        if i >= self.files.len() {
                            continue;
                        } // 防越界
                        let f = self.files[i].clone();
                        let bg = if row_pos.is_multiple_of(2) {
                            Color32::WHITE
                        } else {
                            Color32::from_rgb(0xf3, 0xf5, 0xf9)
                        };
                        self.draw_file_row(
                            ui,
                            f.blind_index,
                            &f.filename,
                            &f.size_display,
                            &f.created_at_display,
                            bg,
                        );
                    }
                } else {
                    // 浏览模式
                    let listing = self.get_vault_listing();
                    if listing.is_empty() {
                        ui.add_space(20.0);
                        ui.vertical_centered(|ui| {
                            ui.label(
                                RichText::new(if self.current_vault_dir.is_empty() {
                                    "保险箱为空 — 点击工具栏「导入」或拖放文件到窗口添加文件"
                                } else {
                                    "此目录为空"
                                })
                                .size(14.0)
                                .color(Color32::GRAY),
                            );
                        });
                        return;
                    }

                    let mut row_pos = 0usize;

                    // 返回上级
                    if !self.current_vault_dir.is_empty() {
                        let parent_bg = Color32::from_rgb(0xf0, 0xf0, 0xf8);
                        let row_frame = Frame::none()
                            .fill(parent_bg)
                            .inner_margin(Margin::symmetric(8.0, 4.0));
                        let _ = row_frame.show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.horizontal(|ui| {
                                ui.spacing_mut().item_spacing.x = 0.0;
                                ui.set_height(22.0);
                                ui.add_sized([24.0, 20.0], egui::Label::new(""));
                                let fname_w = (ui.available_width() - NON_FILENAME_WIDTH).max(80.0);
                                {
                                    let resp = ui.add_sized(
                                        [fname_w, 20.0],
                                        egui::Button::new(
                                            RichText::new(icons::fmt_back())
                                                .size(13.0)
                                                .color(C_PRIMARY),
                                        ),
                                    );
                                    if resp.clicked() {
                                        if let Some(pos) = self.current_vault_dir.rfind('/') {
                                            self.current_vault_dir =
                                                self.current_vault_dir[..pos].to_string();
                                        } else {
                                            self.current_vault_dir.clear();
                                        }
                                    }
                                }
                                ui.add_sized([80.0, 20.0], egui::Label::new(""));
                                ui.add_sized([100.0, 20.0], egui::Label::new(""));
                                ui.add_sized([40.0, 20.0], egui::Label::new(""));
                                ui.add_sized([40.0, 20.0], egui::Label::new(""));
                                ui.add_sized([40.0, 20.0], egui::Label::new(""));
                                ui.add_sized([40.0, 20.0], egui::Label::new(""));
                            });
                        });
                        row_pos += 1;
                    }

                    // 目录行
                    for entry in &listing {
                        if !entry.is_dir {
                            continue;
                        }
                        let bg = if row_pos.is_multiple_of(2) {
                            Color32::WHITE
                        } else {
                            Color32::from_rgb(0xf3, 0xf5, 0xf9)
                        };
                        let dir_name = entry.name.clone();
                        let full_dir = if self.current_vault_dir.is_empty() {
                            dir_name.clone()
                        } else {
                            format!("{}/{}", self.current_vault_dir, dir_name)
                        };
                        let row_frame = Frame::none()
                            .fill(bg)
                            .inner_margin(Margin::symmetric(8.0, 4.0));
                        let _ = row_frame.show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.horizontal(|ui| {
                                ui.spacing_mut().item_spacing.x = 0.0;
                                ui.set_height(22.0);
                                ui.add_sized([24.0, 20.0], egui::Label::new(""));
                                let fname_w = (ui.available_width() - NON_FILENAME_WIDTH).max(80.0);
                                {
                                    let resp = ui.add_sized(
                                        [fname_w, 20.0],
                                        egui::Button::new(
                                            RichText::new(icons::fmt_dir(&dir_name))
                                                .size(13.0)
                                                .color(C_PRIMARY),
                                        ),
                                    );
                                    if resp.clicked() {
                                        if self.current_vault_dir.is_empty() {
                                            self.current_vault_dir = dir_name.clone();
                                        } else {
                                            self.current_vault_dir.push('/');
                                            self.current_vault_dir.push_str(&dir_name);
                                        }
                                    }
                                }
                                ui.add_sized(
                                    [80.0, 20.0],
                                    egui::Label::new(
                                        RichText::new("目录")
                                            .size(12.0)
                                            .color(Color32::from_rgb(0x88, 0x88, 0xcc)),
                                    ),
                                );
                                ui.add_sized([100.0, 20.0], egui::Label::new(""));
                                let dir_for_export = full_dir.clone();
                                if ui
                                    .add_sized(
                                        [40.0, 20.0],
                                        egui::Button::new(RichText::new("导出").size(12.0))
                                            .frame(false),
                                    )
                                    .clicked()
                                {
                                    let ctx = ui.ctx().clone();
                                    self.start_directory_export(&ctx, &dir_for_export);
                                }
                                let dir_for_cut = full_dir.clone();
                                if ui
                                    .add_sized(
                                        [40.0, 20.0],
                                        egui::Button::new(RichText::new("导出并移除").size(12.0))
                                            .frame(false),
                                    )
                                    .clicked()
                                {
                                    let ctx = ui.ctx().clone();
                                    self.start_directory_cut(&ctx, &dir_for_cut);
                                }
                                let dir_for_rename = full_dir.clone();
                                if ui
                                    .add_sized(
                                        [40.0, 20.0],
                                        egui::Button::new(RichText::new("改名").size(12.0))
                                            .frame(false),
                                    )
                                    .clicked()
                                {
                                    self.rename_dir = Some(dir_for_rename);
                                    self.rename_dir_new_name = dir_name.clone();
                                }
                                let dir_for_delete = full_dir.clone();
                                if ui
                                    .add_sized(
                                        [40.0, 20.0],
                                        egui::Button::new(RichText::new("删除").size(12.0))
                                            .frame(false),
                                    )
                                    .clicked()
                                {
                                    self.confirm_remove_dir = Some(dir_for_delete);
                                    self.confirm_remove_dir_name = dir_name;
                                }
                            });
                        });
                        ui.separator();
                        row_pos += 1;
                    }

                    // 文件行
                    for entry in &listing {
                        if entry.is_dir {
                            continue;
                        }
                        let bg = if row_pos.is_multiple_of(2) {
                            Color32::WHITE
                        } else {
                            Color32::from_rgb(0xf3, 0xf5, 0xf9)
                        };
                        self.draw_file_row(
                            ui,
                            entry.blind_index.unwrap_or_default(),
                            &entry.name,
                            &entry.size_display,
                            &entry.time_display,
                            bg,
                        );
                        row_pos += 1;
                    }
                }
            });
    }
}
