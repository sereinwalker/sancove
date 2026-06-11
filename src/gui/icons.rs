//! 跨平台图标系统
//!
//! # 设计原则
//!
//! 真实工程实践中，GUI 图标方案的选择需权衡美观、兼容性和维护成本：
//!
//! | 方案 | 兼容性 | 美观度 | 维护成本 | 适用场景 |
//! |------|--------|--------|----------|----------|
//! | SVG 内嵌 | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | 生产级应用，egui 推荐 |
//! | 图标字体 | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | 大型项目，需要丰富图标库 |
//! | Unicode 符号 | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | 轻量级工具，本方案 |
//! | Emoji | ⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | 不推荐（跨平台不一致） |
//!
//! 本项目当前选用 **Unicode 符号** 方案，原因：
//! - 零外部依赖，编译时确定，无加载失败风险
//! - 选用的 Geometric Shapes (U+2500–25FF) 和 Arrows (U+2190–21FF)
//!   在 Windows Microsoft YaHei / SimHei、macOS PingFang、Linux Noto Sans CJK
//!   中均有覆盖
//! - 避免使用 Emoji (U+1F300+)，因 CJK 字体不含 Emoji 字形
//! - 所有图标通过常量引用，后续迁移到 SVG 方案时只需改此文件
//!
//! # 迁移路径
//!
//! 如需迁移到 SVG 图标，将常量改为返回 `egui::Image` 并配合
//! `egui::include_image!()` 宏：
//!
//! ```rust,ignore
//! // 后续迁移示例：
//! pub fn icon_folder(ui: &mut egui::Ui, max_height: f32) -> egui::Image {
//!     egui::Image::new(egui::include_image!("../../assets/icons/folder.svg"))
//!         .max_height(max_height)
//! }
//! ```

// ── 导航与目录 ──

/// 文件夹指示器 — ▶ (U+25B6, Black Right-Pointing Triangle)
/// 用于目录名前缀，表示可展开
pub const ICON_FOLDER: &str = "▶";

/// 返回上级 — ◀ (U+25C0, Black Left-Pointing Triangle)
pub const ICON_BACK: &str = "◀";

// ── 操作按钮 ──

/// 刷新 — ↻ (U+21BB, Clockwise Open Circle Arrow)
pub const ICON_REFRESH: &str = "↻";

/// 关闭 — ✕ (U+2715, Multiplication X)
pub const ICON_CLOSE: &str = "✕";

/// 搜索清除 — × (U+00D7, Multiplication Sign, Latin-1)
/// 与 ICON_CLOSE 视觉近似但使用 Latin-1 字符，通用性最好
pub const ICON_CLEAR: &str = "×";

/// 菜单指示器 — ▼ (U+25BC, Black Down-Pointing Triangle)
pub const ICON_MENU: &str = "▼";

/// 导出 — ⬇ (U+2B07, Downwards Black Arrow)
pub const ICON_EXPORT: &str = "⬇";

// ── 功能标签（无图标的纯文本场景，用统一的格式化风格）──

/// 为目录名添加前缀图标
pub fn fmt_dir(name: &str) -> String {
    format!("{}  {}", ICON_FOLDER, name)
}

/// 为返回上级添加前缀图标
pub fn fmt_back() -> String {
    format!("{} 返回上级", ICON_BACK)
}

/// 为导出按钮添加前缀图标
pub fn fmt_export(label: &str) -> String {
    format!("{} {}", ICON_EXPORT, label)
}
