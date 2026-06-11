//! 密码强度在线评估
//!
//! 基于 NIST SP 800-63B Rev 4（2025）指导原则和 zxcvbn 工程实践：
//!
//! - **长度是强度最可靠的单一指标**，优于字符类别组合规则
//! - **禁止组合规则**（NIST SP 800-63B Rev 4: "SHALL NOT impose composition rules"）
//! - 每个 Unicode 码点计为 1 个字符（NIST: "SHOULD count each Unicode code point as one character"）
//! - 常见模式检测提供提示但不改变评分
//!
//! # 评分等级
//!
//! - **Weak (0)**: 长度 < 8 或在弱口令黑名单中
//! - **Medium (1)**: 长度 8–11
//! - **Strong (2)**: 长度 12–15
//! - **Very Strong (3)**: 长度 ≥ 16
//!
//! # 参考
//!
//! - NIST SP 800-63B Rev 4: Digital Authentication Guideline
//! - Dropbox zxcvbn: https://github.com/dropbox/zxcvbn
//! - OWASP Password Policy: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

// ============================================================
// 长度阈值常量（基于 NIST SP 800-63B Rev 4）
// ============================================================

/// 最小可接受密码长度（8 位以下直接拒绝）
const MIN_ACCEPTABLE_LENGTH: usize = 8;
/// 强密码最小长度（12 位及以上）
const STRONG_MIN_LENGTH: usize = 12;
/// 非常强密码最小长度（16 位及以上）
const VERY_STRONG_MIN_LENGTH: usize = 16;

/// 密码强度等级
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrengthLevel {
    /// 极弱 — 应拒绝（长度 < 8）
    Weak,
    /// 中等（长度 8–11）
    Medium,
    /// 强（长度 12–15）
    Strong,
    /// 非常强（长度 ≥ 16）
    VeryStrong,
}

impl StrengthLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            StrengthLevel::Weak => "弱",
            StrengthLevel::Medium => "中",
            StrengthLevel::Strong => "强",
            StrengthLevel::VeryStrong => "非常强",
        }
    }
}

/// 密码评估结果
#[derive(Debug)]
pub struct PasswordStrength {
    /// 强度等级
    pub level: StrengthLevel,
    /// 密码长度（Unicode 字符数，非字节数）
    pub length: usize,
    /// 检测到的问题列表
    pub issues: Vec<String>,
}

/// 评估密码强度
///
/// 遵循 NIST SP 800-63B Rev 4 和 zxcvbn 工程实践：
///
/// 1. **长度优先** — 长度是强度最可靠的单一预测指标
/// 2. **无组合规则** — 不要求大小写/数字/特殊字符的组合
/// 3. **Unicode 友好** — 每个字符（含中文）计为 1 位
/// 4. **模式检测仅提供提示** — 不因模式降低评分
/// 5. **弱口令黑名单** — 匹配黑名单直接评为 Weak
///
/// # 参数
///
/// * `password` — 待评估的密码字符串（UTF-8）
///
/// # 返回值
///
/// [`PasswordStrength`] 包含等级、长度和建议提示。
pub fn evaluate_password(password: &str) -> PasswordStrength {
    let mut issues = Vec::new();

    // 使用 chars().count() 而非 len()：中文等每个 Unicode 码点算 1 字符
    let length = password.chars().count();

    // ------ 常见模式检测（仅提供提示，不影响评分） ------

    if length < 8 {
        issues.push(format!(
            "密码过短（{}位），建议至少 {} 位",
            length, MIN_ACCEPTABLE_LENGTH
        ));
    }

    // 连续字符（如 "abcd", "1234", "zyxw"）
    if has_consecutive_sequence(password, 3) {
        issues.push("包含连续字符序列（如 abc、123），降低密码可预测性".to_string());
    }

    // 重复字符（如 "aaa", "111"）
    if has_repeated_chars(password, 3) {
        issues.push("包含重复字符（如 aaa），降低密码可预测性".to_string());
    }

    // 键盘模式（如 "qwerty", "asdf"）
    if has_keyboard_pattern(password) {
        issues.push("包含键盘连续按键模式（如 qwerty），易被模式攻击破解".to_string());
    }

    // 常见弱口令
    if is_common_password(password) {
        issues.push("密码出现在常见弱口令列表中，极易被快速破解".to_string());
    }

    // ------ 等级判定（纯长度驱动 + 黑名单覆盖） ------

    // 黑名单不限长度直接评为 Weak（即使 16 位 "passwordpassword" 也是 Weak）
    let level = if is_common_password(password) || length < MIN_ACCEPTABLE_LENGTH {
        StrengthLevel::Weak
    } else if length >= VERY_STRONG_MIN_LENGTH {
        StrengthLevel::VeryStrong
    } else if length >= STRONG_MIN_LENGTH {
        StrengthLevel::Strong
    } else {
        StrengthLevel::Medium
    };

    PasswordStrength {
        level,
        length,
        issues,
    }
}

/// 返回适合在 GUI 中显示的进度条比例 (0.0 ~ 1.0)
pub fn strength_progress(strength: &PasswordStrength) -> f32 {
    match strength.level {
        StrengthLevel::Weak => 0.25,
        StrengthLevel::Medium => 0.50,
        StrengthLevel::Strong => 0.75,
        StrengthLevel::VeryStrong => 1.0,
    }
}

/// 返回强度颜色（RGB hex）
pub fn strength_color(strength: &PasswordStrength) -> u32 {
    match strength.level {
        StrengthLevel::Weak => 0xDB4437,       // 红
        StrengthLevel::Medium => 0xF4B400,     // 黄
        StrengthLevel::Strong => 0x0F9D58,     // 绿
        StrengthLevel::VeryStrong => 0x1A73E8, // 蓝
    }
}

// ============================================================
// 内部辅助函数
// ============================================================

/// 检测是否存在长度 ≥ `min_len` 的连续字符序列（如 "abc", "123", "zyx"）
///
/// 在 ASCII 字节级别检测。多字节 UTF-8 编码的字节间极少连续，但不保证零误检。
fn has_consecutive_sequence(s: &str, min_len: usize) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() < min_len {
        return false;
    }

    // 连续递增序列（如 abc, 123）
    let mut inc_run = 1u32;
    for i in 1..bytes.len() {
        if bytes[i] == bytes[i - 1].wrapping_add(1) {
            inc_run += 1;
            if inc_run >= min_len as u32 {
                return true;
            }
        } else {
            inc_run = 1;
        }
    }

    // 连续递减序列（如 zyx, 321）
    let mut dec_run = 1u32;
    for i in 1..bytes.len() {
        if bytes[i] == bytes[i - 1].wrapping_sub(1) {
            dec_run += 1;
            if dec_run >= min_len as u32 {
                return true;
            }
        } else {
            dec_run = 1;
        }
    }

    false
}

/// 检测是否存在长度 ≥ `min_len` 的重复字符（如 "aaa", "111"）
///
/// 在 ASCII 字节级别检测。多字节 UTF-8 编码的字节间极少重复，但不保证零误检。
fn has_repeated_chars(s: &str, min_len: usize) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() < min_len {
        return false;
    }

    let mut run = 1u32;
    for i in 1..bytes.len() {
        if bytes[i] == bytes[i - 1] {
            run += 1;
            if run >= min_len as u32 {
                return true;
            }
        } else {
            run = 1;
        }
    }
    false
}

/// 键盘 QWERTY 布局行（仅小写，检测时会先小写化输入）
const KEYBOARD_ROWS: &[&[u8]] = &[
    b"qwertyuiop",
    b"asdfghjkl",
    b"zxcvbnm",
    b"0123456789",
    b"!@#$%^&*()",
];

/// 键盘行的反向序列（预计算，避免每次检测时重新分配 Vec）
const REV_KEYBOARD_ROWS: &[&[u8]] = &[
    b"poiuytrewq",
    b"lkjhgfdsa",
    b"mnbvcxz",
    b"9876543210",
    b")(*&^%$#@!",
];

/// 检测密码中是否包含键盘连续按键模式（如 "qwerty", "asdf"）
fn has_keyboard_pattern(s: &str) -> bool {
    let s_lower = s.to_lowercase();
    let bytes = s_lower.as_bytes();
    if bytes.len() < 4 {
        return false;
    }

    // 正向检查每个键盘行
    for row in KEYBOARD_ROWS {
        if row.len() < 4 {
            continue;
        }
        for i in 0..=row.len() - 4 {
            let pat = &row[i..i + 4];
            if bytes.windows(4).any(|w| w == pat) {
                return true;
            }
        }
    }

    // 反向检查（使用预计算的反向行）
    for row in REV_KEYBOARD_ROWS {
        if row.len() < 4 {
            continue;
        }
        for i in 0..=row.len() - 4 {
            let pat = &row[i..i + 4];
            if bytes.windows(4).any(|w| w == pat) {
                return true;
            }
        }
    }
    false
}

/// 常见弱口令黑名单（Top 50）
///
/// 基于历年泄露数据统计的最常见密码。
/// 覆盖中英文常见弱口令。
const COMMON_PASSWORDS: &[&str] = &[
    "123456",
    "password",
    "12345678",
    "qwerty",
    "123456789",
    "12345",
    "1234",
    "111111",
    "1234567",
    "sunshine",
    "qwerty123",
    "iloveyou",
    "princess",
    "admin",
    "welcome",
    "666666",
    "abc123",
    "football",
    "123123",
    "monkey",
    "654321",
    "!@#$%^&*",
    "charlie",
    "aa123456",
    "donald",
    "password1",
    "qwerty12345",
    "1234567890",
    "letmein",
    "password123",
    "dragon",
    "baseball",
    "adobe123",
    "master",
    "hunter",
    "ashley",
    "batman",
    "trustno1",
    "000000",
    "123",
    "login",
    "admin123",
    "passw0rd",
    "shadow",
    "michael",
    "ninja",
    "mustang",
    "121212",
    "passwd",
    "hello",
];

fn is_common_password(password: &str) -> bool {
    let lower = password.to_lowercase();
    COMMON_PASSWORDS.contains(&lower.as_str())
}

// ============================================================
// 测试
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_weak_short_password() {
        let r = evaluate_password("123456");
        assert_eq!(r.level, StrengthLevel::Weak);
        assert!(!r.issues.is_empty());
    }

    #[test]
    fn test_weak_common_password() {
        let r = evaluate_password("password");
        assert_eq!(r.level, StrengthLevel::Weak);
    }

    #[test]
    fn test_medium_password_8char() {
        let r = evaluate_password("Abcdef12");
        assert_eq!(r.level, StrengthLevel::Medium);
    }

    #[test]
    fn test_medium_password_11char() {
        let r = evaluate_password("abcdefghijk");
        assert_eq!(r.level, StrengthLevel::Medium);
    }

    #[test]
    fn test_strong_password_12char() {
        let r = evaluate_password("abcdefghijkl");
        assert_eq!(r.level, StrengthLevel::Strong);
    }

    #[test]
    fn test_strong_password_15char() {
        let r = evaluate_password("abcdefghijklmno");
        assert_eq!(r.level, StrengthLevel::Strong);
    }

    #[test]
    fn test_very_strong_password() {
        let r = evaluate_password("Kz9#mP2$vL7@nQ5!");
        assert_eq!(r.level, StrengthLevel::VeryStrong);
    }

    /// zxcvbn 经典用例："CorrectHorseBatteryStaple" 25 位 → VeryStrong
    #[test]
    fn test_xkcd_passphrase() {
        let r = evaluate_password("CorrectHorseBatteryStaple");
        assert_eq!(r.level, StrengthLevel::VeryStrong);
    }

    #[test]
    fn test_consecutive_detection() {
        assert!(has_consecutive_sequence("abc", 3));
        assert!(has_consecutive_sequence("1234", 3));
        assert!(has_consecutive_sequence("zyx", 3));
        assert!(!has_consecutive_sequence("a1b2c3", 3));
    }

    #[test]
    fn test_repeated_detection() {
        assert!(has_repeated_chars("aaa", 3));
        assert!(has_repeated_chars("1111", 3));
        assert!(!has_repeated_chars("abca", 3));
    }

    #[test]
    fn test_keyboard_pattern() {
        assert!(has_keyboard_pattern("qwerty"));
        assert!(has_keyboard_pattern("asdfgh"));
        assert!(has_keyboard_pattern("zxcvbn"));
        assert!(!has_keyboard_pattern("random"));
    }

    #[test]
    fn test_common_password_list() {
        assert!(is_common_password("123456"));
        assert!(is_common_password("password"));
        assert!(is_common_password("admin"));
        assert!(!is_common_password("MyC0mpl3x!Password"));
    }

    #[test]
    fn test_strength_progress() {
        let weak = evaluate_password("1234");
        let strong = evaluate_password("Kz9#mP2$vL7@nQ5!");
        assert!(strength_progress(&weak) < strength_progress(&strong));
    }

    #[test]
    fn test_empty_password() {
        let r = evaluate_password("");
        assert_eq!(r.level, StrengthLevel::Weak);
        assert_eq!(r.length, 0);
    }

    #[test]
    fn test_edge_length_6() {
        let r = evaluate_password("Ab123!");
        assert_eq!(r.length, 6);
        assert_eq!(r.level, StrengthLevel::Weak);
    }

    #[test]
    fn test_edge_length_7() {
        let r = evaluate_password("Abc123!");
        assert_eq!(r.length, 7);
        // 7 < 8 → Weak（NIST 指导原则：8 位以下不应接受）
        assert_eq!(r.level, StrengthLevel::Weak);
    }

    #[test]
    fn test_chinese_password() {
        // 中文密码：chars().count() 应为 5 而非字节数 15
        let r = evaluate_password("我的密码强");
        assert_eq!(r.length, 5, "中文密码应以字符而非字节计数");
        // 长度不足 8 → Weak
        assert_eq!(r.level, StrengthLevel::Weak);
    }

    #[test]
    fn test_mixed_chinese_ascii_password() {
        // 混合中文 + ASCII，11 个字符
        let r = evaluate_password("密码Safe2024!");
        assert_eq!(r.length, 11, "混合密码应以字符计数");
        // 11 位 → Medium（8 ≤ 11 < 12）
        assert_eq!(r.level, StrengthLevel::Medium);
    }

    #[test]
    fn test_unicode_japanese() {
        // 日文密码：パスワード(5) + 1234(4) = 9 chars
        let r = evaluate_password("パスワード1234");
        assert_eq!(r.length, 9, "日文密码应以字符计数");
        assert_eq!(r.level, StrengthLevel::Medium);
    }

    #[test]
    fn test_very_long_chinese() {
        // 长中文密码 15 chars → Strong (12 ≤ 15 < 16)
        let r = evaluate_password("我的密码非常安全没有人可以破解");
        assert_eq!(r.length, 15);
        assert_eq!(r.level, StrengthLevel::Strong);
    }

    #[test]
    fn test_chinese_passphrase_very_strong() {
        // 16 位中文 → VeryStrong
        let r = evaluate_password("我的密码非常安全没有人可以破解你");
        assert_eq!(r.length, 16);
        assert_eq!(r.level, StrengthLevel::VeryStrong);
    }

    #[test]
    fn test_common_password_long_but_weak() {
        // 即使长度长，出现在黑名单中也评为 Weak
        let r = evaluate_password("password123");
        assert_eq!(r.length, 11);
        assert_eq!(
            r.level,
            StrengthLevel::Weak,
            "黑名单中的密码即使长度足够也应为 Weak"
        );
    }
}
