//! GUI 主更新循环 — eframe::App::update

use std::path::PathBuf;
use std::sync::atomic::Ordering;

use eframe::egui;
use egui::{Color32, Frame, Margin, RichText, Rounding};
use zeroize::Zeroize;

use super::app::VaultApp;
use super::task::set_pending;
use super::types::{C_ERROR, C_SUCCESS, ImportFileItem, scan_folder_for_items};

impl eframe::App for VaultApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // 自动消失状态消息（5 秒后清除）
        if self.status_message.is_some()
            && let Some(set_at) = self.status_set_at
            && set_at.elapsed().as_secs() > 5
        {
            self.status_message = None;
            self.status_set_at = None;
            ctx.request_repaint();
        }

        // 检查后台登录任务结果
        if let Some(ref rx) = self.login_channel
            && self.login_busy
            && let Ok(result) = rx.try_recv()
        {
            self.login_channel = None;
            self.login_busy = false;
            match result {
                Ok(vault_arc) => {
                    self.vault = Some(vault_arc);
                    self.vault_dir = PathBuf::from(self.vault_path.trim());
                    self.logged_in = true;
                    self.login_error.clear();
                    // 零化密码（Zeroize 确保内存缓冲区被清除）
                    self.password.zeroize();
                    self.password_confirm.zeroize();
                    self.refresh_files();
                }
                Err(e) => {
                    self.login_error = e;
                    self.status_message = Some((false, self.login_error.clone()));
                    self.status_set_at = Some(std::time::Instant::now());
                }
            }
        }

        // 检查后台任务结果
        self.check_pending_result();

        // 更新批量导入进度
        if self.task_busy {
            if let Some(ref progress) = self.batch_import_progress {
                let done = progress.load(Ordering::Relaxed);
                if done > 0 {
                    self.task_busy_message =
                        format!("正在批量导入... ({}/{})", done, self.batch_import_total);
                }
            }
        } else {
            self.batch_import_progress = None;
            self.batch_import_total = 0;
        }

        // 检查基准测试结果
        if self.bench_running
            && let Ok(mut guard) = self.bench_pending.lock()
            && let Some(r) = guard.take()
        {
            self.bench_results = Some(r);
            self.bench_running = false;
            set_pending(&self.pending_result, Ok("基准测试完成".to_string()));
        }

        // 拖放文件/文件夹导入
        if self.logged_in && !self.task_busy {
            let dropped: Vec<PathBuf> = ctx.input(|i| {
                i.raw
                    .dropped_files
                    .iter()
                    .filter_map(|f| f.path.clone())
                    .collect()
            });
            if !dropped.is_empty() {
                let mut items = Vec::new();
                for p in &dropped {
                    if p.is_dir() {
                        scan_folder_for_items(p, &mut items);
                    } else if p.is_file()
                        && let Some(name) = p.file_name().and_then(|n| n.to_str())
                    {
                        items.push(ImportFileItem {
                            source: p.clone(),
                            vault_path: name.to_string(),
                        });
                    }
                }
                if items.is_empty() {
                    return;
                }
                self.batch_import_files = items;
                self.init_batch_import_ui();
            }
        }

        if self.logged_in {
            self.draw_main_screen(ctx);
            // 在主界面之上渲染所有对话框
            self.draw_dialogs(ctx);
        } else {
            self.draw_login_screen(ctx);
            // 登录页也需要渲染 KEK 恢复对话框
            self.draw_kek_recover_dialog(ctx);
            if self.login_busy {
                egui::Area::new("login_spinner".into())
                    .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                    .show(ctx, |ui| {
                        Frame::none()
                            .fill(Color32::from_rgba_premultiplied(0, 0, 0, 180))
                            .inner_margin(Margin::symmetric(24.0, 16.0))
                            .show(ui, |ui| {
                                ui.label(
                                    RichText::new("正在处理...（密钥派生中，请稍候）")
                                        .size(16.0)
                                        .color(Color32::WHITE)
                                        .strong(),
                                );
                            });
                    });
            }
        }

        // Toast 浮动通知
        if let Some((is_ok, ref msg)) = self.status_message {
            let screen_size = ctx.screen_rect().size();
            let toast_color = if is_ok { C_SUCCESS } else { C_ERROR };
            egui::Area::new("toast".into())
                .anchor(egui::Align2::CENTER_BOTTOM, [0.0, -40.0])
                .show(ctx, |ui| {
                    let max_w = screen_size.x.min(500.0);
                    Frame::none()
                        .fill(toast_color)
                        .rounding(Rounding::same(6.0))
                        .stroke(egui::Stroke::new(
                            1.0,
                            Color32::from_rgba_premultiplied(0, 0, 0, 50),
                        ))
                        .inner_margin(Margin::symmetric(16.0, 10.0))
                        .show(ui, |ui| {
                            ui.set_max_width(max_w);
                            ui.label(
                                RichText::new(msg.as_str())
                                    .size(13.0)
                                    .color(Color32::WHITE)
                                    .strong(),
                            );
                        });
                });
        }
    }
}
