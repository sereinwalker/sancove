//! GUI 登录界面

use std::path::PathBuf;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;

use super::app::VaultApp;
use super::task::spawn_task;
use super::types::{C_ERROR, C_PRIMARY, C_WARNING, strength_color_to_egui};
use crate::crypto::password_strength::{evaluate_password, strength_color, strength_progress};
use crate::vault::Vault;
use eframe::egui;
use egui::{Color32, Frame, RichText, TextEdit};

impl VaultApp {
    // ============================================================
    // 登录界面
    // ============================================================

    pub(super) fn draw_login_screen(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default()
            .frame(egui::Frame::none().fill(ctx.style().visuals.window_fill()))
            .show(ctx, |ui| {
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .max_height(f32::INFINITY)
                    .show(ui, |ui| {
                        ui.vertical_centered(|ui| {
                            // 垂直居中：内容区约 500px，剩余空间均匀分配到上下
                            let extra = (ui.available_height() - 500.0).max(0.0) / 2.0;
                            ui.add_space(extra);
                            ui.heading(RichText::new("保密文件库").size(28.0).color(C_PRIMARY));
                            ui.add_space(4.0);
                            ui.label(
                                RichText::new("基于国密算法 SM4/SM3")
                                    .size(14.0)
                                    .color(Color32::GRAY),
                            );
                            ui.add_space(32.0);

                            let form_width = 380.0;
                            let frame = Frame::group(ui.style())
                                .fill(Color32::from_rgb(0xfa, 0xfa, 0xfa))
                                .stroke(egui::Stroke::new(1.0, Color32::from_gray(0xcc)))
                                .inner_margin(egui::Margin::symmetric(24.0, 20.0));

                            frame.show(ui, |ui| {
                                ui.set_min_width(form_width);
                                ui.vertical_centered(|ui| {
                                    let row_w = 300.0;
                                    let text_w = 256.0;
                                    let btn_w = 40.0;
                                    let gap = 4.0;

                                    // 保险箱路径
                                    ui.label(RichText::new("保险箱路径").strong().size(14.0));
                                    ui.add_space(4.0);
                                    ui.add_sized([row_w, 28.0], |ui: &mut egui::Ui| {
                                        ui.horizontal(|ui| {
                                            ui.spacing_mut().item_spacing.x = 0.0;
                                            ui.add_sized(
                                                [text_w, 28.0],
                                                TextEdit::singleline(&mut self.vault_path)
                                                    .hint_text("例如: D:\\MyVault")
                                                    .desired_width(f32::INFINITY),
                                            );
                                            ui.add_sized([gap, 28.0], egui::Label::new(""));
                                            if ui
                                                .add_sized([btn_w, 28.0], egui::Button::new("浏览"))
                                                .clicked()
                                                && let Some(dir) = rfd::FileDialog::new()
                                                    .set_title("选择保险箱存储目录")
                                                    .pick_folder()
                                            {
                                                self.vault_path = dir.to_string_lossy().to_string();
                                            }
                                        })
                                        .response
                                    });

                                    ui.add_space(12.0);

                                    // 密码
                                    ui.label(RichText::new("密码").strong().size(14.0));
                                    ui.add_space(4.0);
                                    ui.add_sized([row_w, 28.0], |ui: &mut egui::Ui| {
                                        ui.horizontal(|ui| {
                                            ui.spacing_mut().item_spacing.x = 0.0;
                                            ui.add_sized(
                                                [text_w, 28.0],
                                                TextEdit::singleline(&mut self.password)
                                                    .password(!self.password_visible)
                                                    .hint_text("输入密码")
                                                    .desired_width(f32::INFINITY),
                                            );
                                            ui.add_sized([gap, 28.0], egui::Label::new(""));
                                            if ui
                                                .add_sized(
                                                    [btn_w, 28.0],
                                                    egui::Button::new(if self.password_visible {
                                                        "隐藏"
                                                    } else {
                                                        "显示"
                                                    }),
                                                )
                                                .clicked()
                                            {
                                                self.password_visible = !self.password_visible;
                                            }
                                        })
                                        .response
                                    });

                                    // 密码强度
                                    if !self.password.is_empty() {
                                        self.password_strength =
                                            Some(evaluate_password(&self.password));
                                    } else {
                                        self.password_strength = None;
                                    }
                                    self.draw_password_strength(ui, row_w, text_w);

                                    ui.add_space(8.0);

                                    // 确认密码
                                    ui.label(RichText::new("确认密码").strong().size(14.0));
                                    ui.add_space(4.0);
                                    ui.add_sized([row_w, 28.0], |ui: &mut egui::Ui| {
                                        ui.horizontal(|ui| {
                                            ui.spacing_mut().item_spacing.x = 0.0;
                                            ui.add_sized(
                                                [text_w, 28.0],
                                                TextEdit::singleline(&mut self.password_confirm)
                                                    .password(!self.password_visible)
                                                    .hint_text("再次输入密码确认")
                                                    .desired_width(f32::INFINITY),
                                            );
                                            ui.add_sized([gap, 28.0], egui::Label::new(""));
                                            if ui
                                                .add_sized(
                                                    [btn_w, 28.0],
                                                    egui::Button::new(if self.password_visible {
                                                        "隐藏"
                                                    } else {
                                                        "显示"
                                                    }),
                                                )
                                                .clicked()
                                            {
                                                self.password_visible = !self.password_visible;
                                            }
                                        })
                                        .response
                                    });

                                    ui.add_space(20.0);

                                    // 按钮
                                    let button_width = 140.0;
                                    let btn_row_w = button_width * 2.0 + 32.0;
                                    ui.allocate_ui_with_layout(
                                        egui::vec2(btn_row_w, 36.0),
                                        egui::Layout::left_to_right(egui::Align::Center),
                                        |ui| {
                                            let busy = self.login_busy;
                                            if ui
                                                .add_sized(
                                                    [button_width, 36.0],
                                                    egui::Button::new(if busy {
                                                        RichText::new("处理中...").size(15.0)
                                                    } else {
                                                        RichText::new("打开").size(15.0)
                                                    })
                                                    .fill(C_PRIMARY),
                                                )
                                                .clicked()
                                                && !busy
                                            {
                                                self.try_open_vault(ctx);
                                            }

                                            ui.add_space(16.0);

                                            if ui
                                                .add_sized(
                                                    [button_width, 36.0],
                                                    egui::Button::new(if busy {
                                                        RichText::new("处理中...").size(15.0)
                                                    } else {
                                                        RichText::new("创建").size(15.0)
                                                    })
                                                    .fill(Color32::from_rgb(0x34, 0xa8, 0x53)),
                                                )
                                                .clicked()
                                                && !busy
                                            {
                                                self.try_create_vault(ctx);
                                            }
                                        },
                                    );

                                    if !self.login_error.is_empty() {
                                        ui.add_space(12.0);
                                        ui.label(
                                            RichText::new(format!("! {}", self.login_error))
                                                .color(C_ERROR)
                                                .size(13.0),
                                        );
                                    }

                                    // 无法登录时的恢复选项
                                    ui.add_space(16.0);
                                    ui.separator();
                                    ui.add_space(8.0);
                                    if ui
                                        .add_sized(
                                            [row_w, 32.0],
                                            egui::Button::new(
                                                RichText::new("🔑 KEK 分片恢复（忘记密码）")
                                                    .size(13.0)
                                                    .color(Color32::WHITE),
                                            )
                                            .fill(C_WARNING),
                                        )
                                        .clicked()
                                        && !self.login_busy
                                    {
                                        self.vault_dir =
                                            std::path::PathBuf::from(self.vault_path.trim());
                                        self.show_kek_recover = true;
                                        self.kek_recover_t.clear();
                                        self.kek_recover_shares.clear();
                                        self.kek_recover_new_password.clear();
                                        self.kek_recover_confirm_password.clear();
                                    }
                                    ui.add_space(4.0);
                                    if ui
                                        .add_sized(
                                            [row_w, 32.0],
                                            egui::Button::new(
                                                RichText::new("📂 从备份恢复保险箱")
                                                    .size(13.0)
                                                    .color(Color32::WHITE),
                                            )
                                            .fill(C_PRIMARY),
                                        )
                                        .clicked()
                                        && !self.login_busy
                                    {
                                        let path = self.vault_path.trim().to_string();
                                        let target_dir = if path.is_empty() {
                                            rfd::FileDialog::new()
                                                .set_title("选择要恢复到哪个目录")
                                                .pick_folder()
                                        } else {
                                            Some(std::path::PathBuf::from(&path))
                                        };
                                        if let Some(target) = target_dir {
                                            if let Some(dir) = rfd::FileDialog::new()
                                                .set_title("选择备份目录")
                                                .pick_folder()
                                            {
                                                if !dir.join("vault.db").exists() {
                                                    self.login_error =
                                                        "所选目录不是有效的保险箱备份".to_string();
                                                } else {
                                                    self.vault_path =
                                                        target.to_string_lossy().to_string();
                                                    let vault_dir = target;
                                                    let backup_dir = dir.clone();
                                                    self.login_busy = true;
                                                    spawn_task(ctx, self.pending_result.clone(), move || {
                                                        crate::vault::Vault::restore_from(&backup_dir, &vault_dir)
                                                            .map(|_| "备份恢复完成，请打开保险箱".to_string())
                                                            .map_err(|e| format!("恢复失败: {}", e))
                                                    });
                                                }
                                            }
                                        }
                                    }

                                    if !self.login_busy
                                        && ctx.input(|i| i.key_pressed(egui::Key::Enter))
                                    {
                                        self.try_open_vault(ctx);
                                    }
                                });

                                ui.add_space(40.0);
                                ui.label(
                                    RichText::new(
                                        "SM3 / SM4 国密算法 · KEK/DEK 双层密钥 · Encrypt-then-MAC",
                                    )
                                    .size(12.0)
                                    .color(Color32::GRAY),
                                );
                            });
                        });
                    });
            });
    }

    /// 绘制密码强度指示器
    fn draw_password_strength(&mut self, ui: &mut egui::Ui, row_w: f32, text_w: f32) {
        if let Some(ref s) = self.password_strength {
            let progress = strength_progress(s);
            let c = strength_color_to_egui(strength_color(s));
            ui.add_space(4.0);
            ui.add_sized([row_w, 20.0], |ui: &mut egui::Ui| {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 0.0;
                    let bar = egui::widgets::ProgressBar::new(progress)
                        .fill(c)
                        .desired_width(text_w);
                    ui.add_sized([text_w, 8.0], bar);
                    ui.add_sized([8.0, 8.0], egui::Label::new(""));
                    ui.label(RichText::new(s.level.as_str()).color(c).size(12.0).strong());
                })
                .response
            });
            ui.add_space(1.0);
            ui.add_sized([row_w, 16.0], |ui: &mut egui::Ui| {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 0.0;
                    ui.label(
                        RichText::new(format!(
                            "长度 {} 位{}",
                            s.length,
                            if s.length >= 16 {
                                " · 推荐"
                            } else if s.length >= 12 {
                                " · 良好"
                            } else {
                                ""
                            },
                        ))
                        .size(10.0)
                        .color(Color32::GRAY),
                    );
                })
                .response
            });
            for issue in &s.issues {
                ui.add_space(2.0);
                ui.add_sized([row_w, 16.0], |ui: &mut egui::Ui| {
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 0.0;
                        ui.label(
                            RichText::new(issue)
                                .size(11.0)
                                .color(C_WARNING),
                        );
                    })
                    .response
                });
            }
        }
    }

    // ============================================================
    // 登录操作
    // ============================================================

    fn try_open_vault(&mut self, ctx: &egui::Context) {
        let path = self.vault_path.trim().to_string();
        let password = self.password.trim().to_string();

        if path.is_empty() {
            self.login_error = "请输入保险箱路径".to_string();
            return;
        }
        if password.is_empty() {
            self.login_error = "请输入密码".to_string();
            return;
        }

        let vault_path = PathBuf::from(&path);
        if !vault_path.join("vault.db").exists() {
            self.login_error = "该目录下没有保险箱数据库，请先创建或检查路径".to_string();
            return;
        }

        let (tx, rx) = mpsc::channel();
        self.login_channel = Some(rx);
        self.login_busy = true;
        self.login_error.clear();
        let ctx_clone = ctx.clone();
        thread::spawn(move || {
            let result = Vault::open(&vault_path, &password)
                .map(|v| Arc::new(Mutex::new(v)))
                .map_err(|e| format!("打开失败: {}", e));
            let _ = tx.send(result);
            ctx_clone.request_repaint();
        });
    }

    fn try_create_vault(&mut self, ctx: &egui::Context) {
        let path = self.vault_path.trim().to_string();
        let password = self.password.trim().to_string();
        let password_confirm = self.password_confirm.trim().to_string();

        if path.is_empty() {
            self.login_error = "请输入保险箱路径".to_string();
            return;
        }
        if password.is_empty() {
            self.login_error = "请输入密码".to_string();
            return;
        }
        if password != password_confirm {
            self.login_error = "两次输入的密码不一致".to_string();
            return;
        }

        let vault_path = PathBuf::from(&path);
        if vault_path.join("vault.db").exists() {
            self.login_error = "该目录已存在保险箱，请使用「打开」或选择其他目录".to_string();
            return;
        }

        let (tx, rx) = mpsc::channel();
        self.login_channel = Some(rx);
        self.login_busy = true;
        self.login_error.clear();
        let ctx_clone = ctx.clone();
        thread::spawn(move || {
            let result = Vault::create(&vault_path, &password)
                .map(|v| Arc::new(Mutex::new(v)))
                .map_err(|e| format!("创建失败: {}", e));
            let _ = tx.send(result);
            ctx_clone.request_repaint();
        });
    }
}
