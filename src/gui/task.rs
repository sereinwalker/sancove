//! 后台任务基础设施

use std::sync::{Arc, Mutex};
use std::thread;

use eframe::egui;
use zeroize::Zeroize;

use crate::vault::Vault;

/// 后台任务共享结果通道
pub type TaskResult = Arc<Mutex<Option<Result<String, String>>>>;

/// 安全设置 pending_result
pub fn set_pending(target: &TaskResult, value: Result<String, String>) {
    match target.lock() {
        Ok(mut guard) => {
            *guard = Some(value);
        }
        Err(poisoned) => {
            let mut guard = poisoned.into_inner();
            *guard = Some(value);
        }
    }
}

/// 安全取出 pending_result
pub fn take_pending(target: &TaskResult) -> Option<Result<String, String>> {
    match target.lock() {
        Ok(mut guard) => guard.take(),
        Err(poisoned) => {
            // Mutex 被毒化时直接恢复内部值，不覆盖原有结果
            let mut guard = poisoned.into_inner();
            guard.take()
        }
    }
}

/// 静默清空 pending_result
pub fn reset_pending(target: &TaskResult) {
    if let Ok(mut guard) = target.lock() {
        *guard = None;
    }
}

/// 完全零化 String
pub fn zeroize_password_string(s: &mut String) {
    let mut bytes = std::mem::take(s).into_bytes();
    bytes.zeroize();
}

/// 启动后台线程
pub fn spawn_task<F>(ctx: &egui::Context, result: TaskResult, f: F)
where
    F: FnOnce() -> Result<String, String> + Send + 'static,
{
    let ctx_clone = ctx.clone();
    thread::spawn(move || {
        let outcome = f();
        set_pending(&result, outcome);
        ctx_clone.request_repaint();
    });
}

/// 后台任务启动器（&mut Vault 版本）
pub fn run_task_mut<F>(
    vault: &Arc<Mutex<Vault>>,
    pending_result: &TaskResult,
    task_busy: &mut bool,
    task_busy_message: &mut String,
    ctx: &egui::Context,
    message: &str,
    f: F,
) where
    F: FnOnce(&mut Vault) -> Result<String, String> + Send + 'static,
{
    let v = vault.clone();
    let result = Arc::clone(pending_result);
    reset_pending(&result);

    *task_busy = true;
    *task_busy_message = message.to_string();

    spawn_task(ctx, result, move || match v.lock() {
        Ok(mut guard) => f(&mut guard),
        Err(e) => Err(format!("保险箱访问错误: {}", e)),
    });
}
