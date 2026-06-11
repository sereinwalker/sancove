//! 审计日志 JSON 导出及时间格式化

use std::fmt::Write as FmtWrite;

use crate::audit_log::AuditEntry;
use crate::audit_log::AuditEntryType;
use crate::audit_log::AuditLog;
use crate::audit_log::error::AuditLogError;

/// 将字节切片编码为十六进制字符串
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(s, "{:02x}", b).unwrap();
    }
    s
}

/// JSON 字符串转义（处理 Unicode 和特殊字符）
fn json_escape(s: &str) -> String {
    let mut escaped = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                write!(escaped, "\\u{:04x}", c as u32).unwrap();
            }
            c => escaped.push(c),
        }
    }
    escaped
}

/// 将 Unix 时间戳转为可读日期时间字符串（YYYY-MM-DD HH:MM:SS UTC 格式）
pub fn chrono_from_timestamp(ts: i64) -> String {
    let seconds_per_day: i64 = 86400;
    let days_from_epoch = if ts >= 0 {
        ts / seconds_per_day
    } else {
        (ts - seconds_per_day + 1) / seconds_per_day
    };
    let remaining_seconds = ts - days_from_epoch * seconds_per_day;

    let (year, month, day) = days_to_civil_date(days_from_epoch);
    let hour = (remaining_seconds / 3600) % 24;
    let minute = (remaining_seconds / 60) % 60;
    let second = remaining_seconds % 60;

    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        year, month, day, hour, minute, second
    )
}

/// 将 Unix 纪元起算的天数转换为公历（年、月、日）
///
/// 使用 Fliegel-Van Flandern 算法将"Unix 纪元天数（1970-01-01 起算）"
/// 先转为儒略日数（JD），再转为公历日期。
fn days_to_civil_date(days: i64) -> (i64, u32, u32) {
    // 转 JD: Unix 纪元 1970-01-01 对应 JD 2440588
    let jd = days + 2440588;
    // Fliegel-Van Flandern 公式：JD → 公历 y/m/d
    let l = jd + 68569;
    let n = (4 * l) / 146097;
    let l = l - (146097 * n + 3) / 4;
    let i = (4000 * (l + 1)) / 1461001;
    let l = l - (1461 * i) / 4 + 31;
    let j = (80 * l) / 2447;
    let day = l - (2447 * j) / 80;
    let l = j / 11;
    let month = j + 2 - 12 * l;
    let year = 100 * (n - 49) + i + l;
    (year, month as u32, day as u32)
}

impl AuditLog {
    /// 将全部审计日志导出为 JSON 字符串
    ///
    /// 输出格式为 JSON 数组，每个元素包含条目的完整信息。
    /// 二进制字段（哈希值、HMAC 标签）以十六进制字符串表示。
    pub fn export_as_json(&self) -> Result<String, AuditLogError> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT idx, entry_blob, hmac_tag FROM audit_log ORDER BY idx ASC")
            .map_err(AuditLogError::Db)?;

        let rows = stmt
            .query_map([], |row| {
                let idx: i64 = row.get(0)?;
                let entry_blob: Vec<u8> = row.get(1)?;
                let hmac_tag: Vec<u8> = row.get(2)?;
                Ok((idx, entry_blob, hmac_tag))
            })
            .map_err(AuditLogError::Db)?;

        let mut json = String::from("[\n");
        let mut first = true;

        for row in rows {
            let (_idx, entry_blob, hmac_tag) = row.map_err(AuditLogError::Db)?;
            let entry: AuditEntry =
                bincode::deserialize(&entry_blob).map_err(AuditLogError::Serialize)?;

            if !first {
                json.push_str(",\n");
            }
            first = false;

            let entry_type_enum = AuditEntryType::from_u8(entry.entry_type)
                .map(|t| t.type_name())
                .unwrap_or("Unknown");

            let payload_str = if let Ok(s) = std::str::from_utf8(&entry.payload) {
                format!("\"{}\"", json_escape(s))
            } else {
                format!("\"<hex: {}>\"", hex_encode(&entry.payload))
            };

            let datetime = chrono_from_timestamp(entry.timestamp);

            json.push_str("  {\n");
            json.push_str(&format!("    \"idx\": {},\n", entry.idx));
            json.push_str(&format!("    \"timestamp\": {},\n", entry.timestamp));
            json.push_str(&format!("    \"datetime\": \"{}\",\n", datetime));
            json.push_str(&format!("    \"entry_type\": \"{}\",\n", entry_type_enum));
            json.push_str(&format!("    \"entry_type_code\": {},\n", entry.entry_type));
            json.push_str(&format!(
                "    \"prev_hash\": \"{}\",\n",
                hex_encode(&entry.prev_hash)
            ));
            json.push_str(&format!("    \"hash\": \"{}\",\n", hex_encode(&entry.hash)));
            json.push_str(&format!("    \"payload\": {},\n", payload_str));
            json.push_str(&format!(
                "    \"hmac_tag\": \"{}\"\n",
                hex_encode(&hmac_tag)
            ));
            json.push_str("  }");
        }

        if first {
            json.push_str("]\n");
        } else {
            json.push_str("\n]\n");
        }
        Ok(json)
    }
}
