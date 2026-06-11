//! GUI 常用类型、颜色、工具函数

use std::path::{Path, PathBuf};

use eframe::egui;
use egui::Color32;

use crate::vault::FileInfo;

// ============================================================
// 颜色方案
// ============================================================

pub const C_PRIMARY: Color32 = Color32::from_rgb(0x1a, 0x73, 0xe8);
pub const C_SUCCESS: Color32 = Color32::from_rgb(0x0f, 0x9d, 0x58);
pub const C_ERROR: Color32 = Color32::from_rgb(0xdb, 0x44, 0x37);
pub const C_BG: Color32 = Color32::from_rgb(0xf5, 0xf5, 0xf5);
pub const C_HEADER: Color32 = Color32::from_rgb(0xcc, 0xcc, 0xcc);
pub const C_TOOLBAR_BG: Color32 = Color32::from_rgb(0xe6, 0xe8, 0xed);
pub const C_TOOLBAR_TEXT: Color32 = Color32::from_rgb(0x33, 0x33, 0x33);

// ============================================================
// 对话框颜色常量
// ============================================================

/// 对话框表头背景色 (#dddddd)
pub const C_TABLE_HEADER_BG: Color32 = Color32::from_rgb(0xdd, 0xdd, 0xdd);

/// 对话框交替行背景色 (#f8f8f8)
pub const C_ROW_ALT_BG: Color32 = Color32::from_rgb(0xf8, 0xf8, 0xf8);

/// 导出/剪切按钮绿色 (#2d8c6b)
pub const C_EXPORT_BTN: Color32 = Color32::from_rgb(0x2d, 0x8c, 0x6b);

/// 警告/覆盖文字颜色 (#cc8800)
pub const C_WARNING: Color32 = Color32::from_rgb(0xcc, 0x88, 0x00);

// ============================================================
// 展示用文件条目
// ============================================================

#[derive(Clone)]
pub struct FileEntry {
    pub blind_index: [u8; 32],
    pub filename: String,
    pub size_display: String,
    pub created_at: i64,
    pub created_at_display: String,
}

impl From<FileInfo> for FileEntry {
    fn from(f: FileInfo) -> Self {
        let size_str = if f.original_size >= 1_000_000 {
            format!("{:.2} MB", f.original_size as f64 / 1_000_000.0)
        } else if f.original_size >= 1_000 {
            format!("{:.1} KB", f.original_size as f64 / 1_000.0)
        } else {
            format!("{} B", f.original_size)
        };

        let time_str = if f.created_at > 0 {
            let secs = f.created_at as u64;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let age = now.saturating_sub(secs);
            if age < 60 {
                "刚刚".to_string()
            } else if age < 3600 {
                format!("{}分钟前", age / 60)
            } else if age < 86400 {
                format!("{}小时前", age / 3600)
            } else {
                format!("{}天前", age / 86400)
            }
        } else {
            "—".to_string()
        };

        Self {
            blind_index: f.blind_index,
            filename: f.filename,
            size_display: size_str,
            created_at: f.created_at,
            created_at_display: time_str,
        }
    }
}

// ============================================================
// 辅助展示类型
// ============================================================

#[derive(Clone)]
pub struct AuditLogEntryDisplay {
    pub idx: String,
    pub time_str: String,
    pub type_name: String,
    pub payload: String,
}

#[derive(Clone)]
pub struct VaultDirEntry {
    pub name: String,
    pub is_dir: bool,
    pub blind_index: Option<[u8; 32]>,
    pub size_display: String,
    pub time_display: String,
}

/// 批量导入项
#[derive(Clone)]
pub struct ImportFileItem {
    pub source: PathBuf,
    pub vault_path: String,
}

// ============================================================
// 文件夹扫描
// ============================================================

pub fn scan_folder_for_items(dir: &Path, result: &mut Vec<ImportFileItem>) {
    let canonical = match dir.canonicalize() {
        Ok(c) => c,
        Err(_) => return,
    };
    if !canonical.is_dir() {
        return;
    }
    let folder_name = canonical
        .file_name()
        .and_then(|n| n.to_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "imported".to_string());
    scan_items_recursive(&canonical, &canonical, result);
    // 以文件夹名为顶层目录前缀，实现整体导入
    for item in result.iter_mut() {
        item.vault_path = format!("{}/{}", folder_name, item.vault_path);
    }
}

fn scan_items_recursive(base: &Path, current: &Path, result: &mut Vec<ImportFileItem>) {
    let mut entries: Vec<_> = match std::fs::read_dir(current) {
        Ok(e) => e.filter_map(|e| e.ok()).collect(),
        Err(_) => return,
    };
    entries.sort_by_key(|e| e.file_name());
    for entry in &entries {
        let path = entry.path();
        if path.is_dir() {
            scan_items_recursive(base, &path, result);
        } else if path.is_file()
            && let Ok(relative) = path.strip_prefix(base)
        {
            let vault_path = relative.to_string_lossy().replace('\\', "/");
            if !vault_path.is_empty() {
                result.push(ImportFileItem {
                    source: path,
                    vault_path,
                });
            }
        }
    }
}

// ============================================================
// 密码强度辅助
// ============================================================

/// 将 `password_strength::strength_color()` 返回的 u32 转为 egui Color32
pub fn strength_color_to_egui(color: u32) -> Color32 {
    Color32::from_rgb(
        ((color >> 16) & 0xFF) as u8,
        ((color >> 8) & 0xFF) as u8,
        (color & 0xFF) as u8,
    )
}

/// 将审计日志原始条目转换为展示格式（供 layout/dialogs 共用）
pub fn audit_entries_to_display(
    entries: &[(crate::audit_log::AuditEntry, [u8; 32])],
    truncate: bool,
) -> Vec<AuditLogEntryDisplay> {
    entries
        .iter()
        .map(|(entry, _hmac)| {
            let ts = crate::audit_log::chrono_from_timestamp(entry.timestamp);
            let type_name = crate::audit_log::AuditEntryType::from_u8(entry.entry_type)
                .map(|t| t.display_name().to_string())
                .unwrap_or_else(|| format!("未知({})", entry.entry_type));
            let payload_full = String::from_utf8_lossy(&entry.payload).to_string();
            let payload = if truncate && payload_full.len() > 100 {
                format!("{}...（完整内容见数据库）", &payload_full[..100])
            } else {
                payload_full
            };
            AuditLogEntryDisplay {
                idx: format!("#{}", entry.idx),
                time_str: ts,
                type_name,
                payload,
            }
        })
        .collect()
}

/// 配置支持中文显示的字体
pub fn configure_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();

    const FONT_CANDIDATES: &[&str] = &[
        "C:\\Windows\\Fonts\\msyh.ttc",
        "C:\\Windows\\Fonts\\msyhbd.ttc",
        "C:\\Windows\\Fonts\\simhei.ttf",
        "C:\\Windows\\Fonts\\simsun.ttc",
        "C:\\Windows\\Fonts\\seguiemj.ttf",
    ];

    let mut loaded = false;
    for path in FONT_CANDIDATES {
        if let Ok(data) = std::fs::read(path) {
            let stem = path.rsplit('\\').next().unwrap_or("font");
            let font_name = format!("system_chinese_{}", stem);
            fonts
                .font_data
                .insert(font_name.clone(), egui::FontData::from_owned(data));
            for family in fonts.families.values_mut() {
                if !family.contains(&font_name) {
                    family.push(font_name.clone());
                }
            }
            loaded = true;
            break;
        }
    }

    if !loaded {
        const UNIX_CANDIDATES: &[&str] = &[
            "/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttc",
            "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
            "/System/Library/Fonts/PingFang.ttc",
            "/System/Library/Fonts/STHeiti Light.ttc",
        ];
        for path in UNIX_CANDIDATES {
            if let Ok(data) = std::fs::read(path) {
                let font_name = format!(
                    "system_chinese_{}",
                    path.rsplit('/').next().unwrap_or("font")
                );
                fonts
                    .font_data
                    .insert(font_name.clone(), egui::FontData::from_owned(data));
                for family in fonts.families.values_mut() {
                    if !family.contains(&font_name) {
                        family.push(font_name.clone());
                    }
                }
                break;
            }
        }
    }

    ctx.set_fonts(fonts);
}
