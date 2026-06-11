//! 基于国密算法的保密文件库 - egui 图形界面
//!
//! 提供直观的图形化界面操作保密文件库：
//! - 登录界面：创建 / 打开保险箱
//! - 主界面：文件列表展示及导入 / 导出 / 移除操作
//!
//! # 模块划分
//!
//! - `app` — VaultApp 结构体定义、状态管理、启动入口
//! - `types` — 颜色常量、展示类型、文件夹扫描
//! - `task` — 后台任务基础设施（结果通道、spawn 助手）
//! - `login` — 登录界面绘制及操作
//! - `layout` — 主界面布局（工具栏、文件列表、面包屑）
//! - `dialogs` — 确认对话框及覆盖窗口（删除、导入、导出、改名等）
//! - `ops` — 后台操作执行（导入/导出/删除/重命名后台线程）
//! - `update` — eframe::App::update 主循环

mod app;
mod dialogs;
pub mod icons;
mod layout;
mod login;
mod ops;
mod task;
mod types;
mod update;

pub use self::app::VaultApp;
