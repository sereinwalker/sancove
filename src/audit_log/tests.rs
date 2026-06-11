use crate::audit_log::{AuditEntryType, AuditLog, AuditLogError};
use rusqlite::{Connection, params};

fn setup_audit_log() -> (tempfile::TempDir, AuditLog) {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test_audit.db");
    let log = AuditLog::open(&db_path).unwrap();
    (dir, log)
}

#[test]
fn test_open_empty() {
    let (_dir, log) = setup_audit_log();
    assert_eq!(log.count().unwrap(), 0);
}

#[test]
fn test_append_single() {
    let (_dir, log) = setup_audit_log();
    let kek = [0x01u8; 16];

    let entry = log.append(AuditEntryType::VaultCreate, &kek, b"").unwrap();
    assert_eq!(entry.idx, 0);
    assert_eq!(entry.entry_type, AuditEntryType::VaultCreate as u8);
    assert_eq!(entry.prev_hash, [0u8; 32]);
    assert_eq!(log.count().unwrap(), 1);
}

#[test]
fn test_append_multiple() {
    let (_dir, log) = setup_audit_log();
    let kek = [0xABu8; 16];

    let e1 = log.append(AuditEntryType::VaultCreate, &kek, b"").unwrap();
    assert_eq!(e1.idx, 0);

    let e2 = log
        .append(AuditEntryType::FileImport, &kek, b"test.txt")
        .unwrap();
    assert_eq!(e2.idx, 1);
    assert_eq!(
        e2.prev_hash, e1.hash,
        "第二条的 prev_hash 应等于第一条的 hash"
    );

    let e3 = log
        .append(AuditEntryType::FileExport, &kek, b"test.txt")
        .unwrap();
    assert_eq!(e3.idx, 2);
    assert_eq!(
        e3.prev_hash, e2.hash,
        "第三条的 prev_hash 应等于第二条的 hash"
    );

    assert_eq!(log.count().unwrap(), 3);
}

#[test]
fn test_get_recent_order() {
    let (_dir, log) = setup_audit_log();
    let kek = [0xCDu8; 16];

    log.append(AuditEntryType::VaultCreate, &kek, b"").unwrap();
    log.append(AuditEntryType::FileImport, &kek, b"a.txt")
        .unwrap();
    log.append(AuditEntryType::FileImport, &kek, b"b.txt")
        .unwrap();
    log.append(AuditEntryType::FileImport, &kek, b"c.txt")
        .unwrap();

    let recent = log.get_recent(3).unwrap();
    assert_eq!(recent.len(), 3);
    assert_eq!(recent[0].0.idx, 3);
    assert_eq!(recent[1].0.idx, 2);
    assert_eq!(recent[2].0.idx, 1);
}

#[test]
fn test_get_recent_limit() {
    let (_dir, log) = setup_audit_log();
    let kek = [0xEFu8; 16];

    log.append(AuditEntryType::VaultCreate, &kek, b"").unwrap();
    log.append(AuditEntryType::FileImport, &kek, b"x.txt")
        .unwrap();
    log.append(AuditEntryType::FileImport, &kek, b"y.txt")
        .unwrap();

    let recent = log.get_recent(1).unwrap();
    assert_eq!(recent.len(), 1);
    assert_eq!(recent[0].0.idx, 2);
}

#[test]
fn test_verify_chain_empty() {
    let (_dir, log) = setup_audit_log();
    let kek = [0x01u8; 16];
    assert!(log.verify_chain(&kek).unwrap());
}

#[test]
fn test_verify_chain_valid() {
    let (_dir, log) = setup_audit_log();
    let kek = [0x42u8; 16];

    log.append(AuditEntryType::VaultCreate, &kek, b"").unwrap();
    log.append(AuditEntryType::FileImport, &kek, b"secret.pdf")
        .unwrap();
    log.append(AuditEntryType::FileExport, &kek, b"secret.pdf")
        .unwrap();
    log.append(AuditEntryType::PasswordChange, &kek, b"")
        .unwrap();

    assert!(log.verify_chain(&kek).unwrap(), "完整链应通过验证");
}

#[test]
fn test_verify_chain_wrong_kek() {
    let (_dir, log) = setup_audit_log();
    let kek = [0x42u8; 16];

    log.append(AuditEntryType::VaultCreate, &kek, b"").unwrap();

    let wrong_kek = [0xFFu8; 16];
    let result = log.verify_chain(&wrong_kek);
    assert!(
        matches!(result, Err(AuditLogError::ChainBroken(_))),
        "错误 KEK 应导致 HMAC 验证失败"
    );
}

#[test]
fn test_detect_tampered_entry_blob() {
    let (dir, log) = setup_audit_log();
    let kek = [0x55u8; 16];

    log.append(AuditEntryType::VaultCreate, &kek, b"").unwrap();
    log.append(AuditEntryType::FileImport, &kek, b"important.docx")
        .unwrap();

    // 直接篡改 SQLite 中的 entry_blob
    let db_path = dir.path().join("test_audit.db");
    let conn = Connection::open(&db_path).unwrap();
    let original: Vec<u8> = conn
        .query_row(
            "SELECT entry_blob FROM audit_log WHERE idx = 0",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let mut tampered = original.clone();
    if !tampered.is_empty() {
        tampered[0] ^= 0xFF;
    }
    conn.execute(
        "UPDATE audit_log SET entry_blob = ?1 WHERE idx = 0",
        params![tampered],
    )
    .unwrap();
    drop(conn);

    let log = AuditLog::open(&db_path).unwrap();
    let result = log.verify_chain(&kek);
    assert!(
        matches!(result, Err(AuditLogError::ChainBroken(_))),
        "篡改 entry_blob 后验证应失败"
    );
}

#[test]
fn test_export_as_json() {
    let (_dir, log) = setup_audit_log();
    let kek = [0x77u8; 16];

    log.append(AuditEntryType::VaultCreate, &kek, b"").unwrap();
    log.append(AuditEntryType::FileImport, &kek, b"doc.pdf")
        .unwrap();

    let json = log.export_as_json().unwrap();
    assert!(json.contains("\"idx\": 0"));
    assert!(json.contains("\"idx\": 1"));
    assert!(json.contains("VaultCreate"));
    assert!(json.contains("FileImport"));
    assert!(json.starts_with('['));
    assert!(json.ends_with("]\n"));
}

#[test]
fn test_export_as_json_empty() {
    let (_dir, log) = setup_audit_log();
    let json = log.export_as_json().unwrap();
    assert_eq!(json, "[\n]\n");
}

#[test]
fn test_all_entry_types() {
    let (_dir, log) = setup_audit_log();
    let kek = [0x33u8; 16];

    let types = [
        AuditEntryType::FileImport,
        AuditEntryType::FileExport,
        AuditEntryType::FileDelete,
        AuditEntryType::PasswordChange,
        AuditEntryType::VaultCreate,
        AuditEntryType::VaultBackup,
        AuditEntryType::VaultRestore,
        AuditEntryType::FileRename,
        AuditEntryType::VaultOpen,
        AuditEntryType::VaultClose,
        AuditEntryType::GuiAction,
    ];

    for (i, &t) in types.iter().enumerate() {
        let payload = format!("event_{}", i);
        let entry = log.append(t, &kek, payload.as_bytes()).unwrap();
        assert_eq!(entry.idx, i as u64);
        assert_eq!(entry.entry_type, t as u8);
    }

    assert_eq!(log.count().unwrap(), 11);
    assert!(log.verify_chain(&kek).unwrap());
}

#[test]
fn test_large_payload() {
    let (_dir, log) = setup_audit_log();
    let kek = [0x99u8; 16];

    let large_payload = vec![0xABu8; 10240];
    let entry = log
        .append(AuditEntryType::FileImport, &kek, &large_payload)
        .unwrap();
    assert_eq!(entry.idx, 0);
    assert_eq!(entry.payload.len(), 10240);
    assert!(log.verify_chain(&kek).unwrap());
}

#[test]
fn test_consecutive_empty_payload() {
    let (_dir, log) = setup_audit_log();
    let kek = [0xBBu8; 16];

    let e1 = log.append(AuditEntryType::VaultCreate, &kek, b"").unwrap();
    let e2 = log
        .append(AuditEntryType::PasswordChange, &kek, b"")
        .unwrap();

    assert_ne!(e1.hash, e2.hash, "不同 idx 的条目哈希应不相同");
}

#[test]
fn test_get_recent_less_than_limit() {
    let (_dir, log) = setup_audit_log();
    let kek = [0xCCu8; 16];

    log.append(AuditEntryType::VaultCreate, &kek, b"").unwrap();

    let recent = log.get_recent(10).unwrap();
    assert_eq!(recent.len(), 1);
}
