//! Vault 模块测试

use super::*;

fn setup_test_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::create(dir.path(), "test_password").unwrap();
    (dir, vault)
}

#[test]
fn test_create_and_open() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::create(dir.path(), "mypassword").unwrap();
    assert_eq!(vault.file_count().unwrap(), 0);
    drop(vault);

    let vault2 = Vault::open(dir.path(), "mypassword").unwrap();
    assert_eq!(vault2.file_count().unwrap(), 0);
}

#[test]
fn test_wrong_password_fails_gracefully() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::create(dir.path(), "correct_password").unwrap();
    drop(vault);

    let result = Vault::open(dir.path(), "wrong_password");
    assert!(result.is_err(), "错误密码应返回错误");

    let vault2 = Vault::open(dir.path(), "correct_password").unwrap();
    assert_eq!(vault2.file_count().unwrap(), 0);
}

#[test]
fn test_import_and_export_roundtrip() {
    let (_dir, vault) = setup_test_vault();

    let src_dir = tempfile::tempdir().unwrap();
    let src_file = src_dir.path().join("hello.txt");
    let content = b"Hello, SM4+CBC+Vault!";
    std::fs::write(&src_file, content).unwrap();

    vault.import_file(&src_file).unwrap();
    assert_eq!(vault.file_count().unwrap(), 1);

    let files = vault.list_files().unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].filename, "hello.txt");
    assert_eq!(files[0].original_size, content.len() as u64);

    let out_dir = tempfile::tempdir().unwrap();
    vault
        .export_file(&files[0].blind_index, out_dir.path())
        .unwrap();

    let exported = std::fs::read(out_dir.path().join("hello.txt")).unwrap();
    assert_eq!(exported, content);
}

#[test]
fn test_import_large_file() {
    let (_dir, vault) = setup_test_vault();

    let src_dir = tempfile::tempdir().unwrap();
    let src_file = src_dir.path().join("large.bin");
    let content = vec![0xABu8; 1024 * 1024]; // 1MB
    std::fs::write(&src_file, &content).unwrap();

    vault.import_file(&src_file).unwrap();
    assert_eq!(vault.file_count().unwrap(), 1);

    let files = vault.list_files().unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].original_size, 1024 * 1024);

    let out_dir = tempfile::tempdir().unwrap();
    vault
        .export_file(&files[0].blind_index, out_dir.path())
        .unwrap();
    let exported = std::fs::read(out_dir.path().join("large.bin")).unwrap();
    assert_eq!(exported.len(), 1024 * 1024);
    assert_eq!(exported, content);
}

#[test]
fn test_import_multiple_files() {
    let (_dir, vault) = setup_test_vault();

    let src_dir = tempfile::tempdir().unwrap();
    for i in 0..5 {
        let f = src_dir.path().join(format!("file_{}.txt", i));
        std::fs::write(&f, format!("content_{}", i)).unwrap();
        vault.import_file(&f).unwrap();
    }

    assert_eq!(vault.file_count().unwrap(), 5);
    let files = vault.list_files().unwrap();
    assert_eq!(files.len(), 5);

    let mut filenames: Vec<String> = files.iter().map(|f| f.filename.clone()).collect();
    filenames.sort();
    for i in 0..5 {
        assert_eq!(filenames[i], format!("file_{}.txt", i));
    }
}

#[test]
fn test_remove_file() {
    let (_dir, vault) = setup_test_vault();

    let src_dir = tempfile::tempdir().unwrap();
    let src_file = src_dir.path().join("delete_me.txt");
    std::fs::write(&src_file, b"to be deleted").unwrap();

    vault.import_file(&src_file).unwrap();
    assert_eq!(vault.file_count().unwrap(), 1);

    let files = vault.list_files().unwrap();
    vault.remove_file(&files[0].blind_index).unwrap();
    assert_eq!(vault.file_count().unwrap(), 0);
}

#[test]
fn test_import_duplicate_filename() {
    let (_dir, vault) = setup_test_vault();

    let src_dir = tempfile::tempdir().unwrap();
    let f = src_dir.path().join("dup.txt");
    std::fs::write(&f, b"first").unwrap();
    vault.import_file(&f).unwrap();

    std::fs::write(&f, b"second").unwrap();
    vault.import_file(&f).unwrap();

    assert_eq!(vault.file_count().unwrap(), 2);
}

// ============================================================
// sanitize_filename 测试
// ============================================================

#[test]
fn test_sanitize_normal_filename() {
    assert_eq!(Vault::sanitize_filename("hello.txt"), "hello.txt");
    assert_eq!(
        Vault::sanitize_filename("my_document-v2.pdf"),
        "my_document-v2.pdf"
    );
}

#[test]
fn test_sanitize_path_traversal() {
    assert_eq!(
        Vault::sanitize_filename("../../../etc/passwd"),
        "etc passwd"
    );
    assert_eq!(Vault::sanitize_filename("..\\..\\secret.txt"), "secret.txt");
}

#[test]
fn test_sanitize_all_invalid() {
    assert_eq!(
        Vault::sanitize_filename("\0/\\:*?"),
        super::DEFAULT_FILE_NAME
    );
}

#[test]
fn test_sanitize_unicode_preserved() {
    let name = "中文文件名称_测试.pdf";
    assert_eq!(Vault::sanitize_filename(name), name);
}

#[test]
fn test_sanitize_control_chars() {
    let result = Vault::sanitize_filename("test\x00file\x1f.txt");
    assert_eq!(result, "test file .txt");
}

#[test]
fn test_sanitize_trim_spaces() {
    assert_eq!(Vault::sanitize_filename("  my file.txt "), "my file.txt");
}

// ============================================================
// change_password 测试
// ============================================================

#[test]
fn test_change_password_multiple_files() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::create(dir.path(), "old_pass").unwrap();

    let src_dir = tempfile::tempdir().unwrap();
    for i in 0..3 {
        let f = src_dir.path().join(format!("doc_{}.txt", i));
        std::fs::write(&f, format!("content_{}", i)).unwrap();
        vault.import_file(&f).unwrap();
    }
    assert_eq!(vault.file_count().unwrap(), 3);
    drop(vault);

    let mut vault = Vault::open(dir.path(), "old_pass").unwrap();
    vault.change_password("new_strong_pass").unwrap();
    drop(vault);

    assert!(Vault::open(dir.path(), "old_pass").is_err());

    let vault = Vault::open(dir.path(), "new_strong_pass").unwrap();
    assert_eq!(vault.file_count().unwrap(), 3);

    let files = vault.list_files().unwrap();
    assert_eq!(files.len(), 3);

    let out_dir = tempfile::tempdir().unwrap();
    for f in &files {
        vault.export_file(&f.blind_index, out_dir.path()).unwrap();
        let exported = std::fs::read(out_dir.path().join(&f.filename)).unwrap();
        assert!(!exported.is_empty());
    }
}

#[test]
fn test_change_password_empty_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::create(dir.path(), "correct").unwrap();
    drop(vault);

    let mut vault = Vault::open(dir.path(), "correct").unwrap();
    assert!(vault.change_password("").is_err());
}

// ============================================================
// HMAC 篡改拒绝测试
// ============================================================

#[test]
fn test_export_rejects_tampered_hmac() {
    let (dir, vault) = setup_test_vault();

    let src_dir = tempfile::tempdir().unwrap();
    let src_file = src_dir.path().join("secret.txt");
    std::fs::write(&src_file, b"classified content").unwrap();
    vault.import_file(&src_file).unwrap();

    let files = vault.list_files().unwrap();
    assert_eq!(files.len(), 1);

    let temp_db_path = dir.path().join("vault.db.tmp");
    vault
        .db
        .checkpoint()
        .map_err(|e| format!("checkpoint: {}", e))
        .unwrap();
    let conn = rusqlite::Connection::open(&temp_db_path).unwrap();
    conn.execute(
        "UPDATE secure_vault SET hmac_tag = X'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF' WHERE blind_index = ?1",
        rusqlite::params![files[0].blind_index.to_vec()],
    ).unwrap();
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .unwrap();
    drop(conn);

    drop(vault);

    let vault = Vault::open(dir.path(), "test_password").unwrap();
    let out_dir = tempfile::tempdir().unwrap();
    let result = vault.export_file(&files[0].blind_index, out_dir.path());
    assert!(result.is_err(), "篡改 HMAC 后导出应被拒绝");
    assert!(
        matches!(result.unwrap_err(), VaultError::Integrity(_)),
        "错误类型应为 Integrity"
    );
}

// ============================================================
// SAVEPOINT 嵌套事务测试
// ============================================================

#[test]
fn test_with_transaction_commit() {
    let (_dir, vault) = setup_test_vault();

    let src_dir = tempfile::tempdir().unwrap();
    let f = src_dir.path().join("tx_test.txt");
    std::fs::write(&f, b"transaction test").unwrap();

    vault
        .with_transaction(|s| {
            let src_dir2 = tempfile::tempdir().unwrap();
            let f2 = src_dir2.path().join("inner.txt");
            std::fs::write(&f2, b"inner").unwrap();
            s.import_file(&f)
        })
        .unwrap();
    assert_eq!(vault.file_count().unwrap(), 1);
}

#[test]
fn test_with_transaction_rollback() {
    let (_dir, vault) = setup_test_vault();

    let src_dir = tempfile::tempdir().unwrap();
    let f = src_dir.path().join("rollback_test.txt");
    std::fs::write(&f, b"will be rolled back").unwrap();

    let result = vault.with_transaction(|s| {
        s.import_file(&f)?;
        // 返回错误触发 SAVEPOINT 回滚
        Err(VaultError::InvalidInput("模拟错误".to_string()))
    });
    assert!(result.is_err(), "事务回滚应返回错误");
    assert_eq!(vault.file_count().unwrap(), 0, "回滚后导入的文件应被撤销");
}

// ============================================================
// SM2 文件共享 E2E 测试
// ============================================================

#[test]
fn test_share_export_import_roundtrip() {
    let dir_a = tempfile::tempdir().unwrap();
    let vault_a = Vault::create(dir_a.path(), "password_a").unwrap();

    let dir_b = tempfile::tempdir().unwrap();
    let vault_b = Vault::create(dir_b.path(), "password_b").unwrap();

    let src_dir = tempfile::tempdir().unwrap();
    let src_file = src_dir.path().join("shared_doc.txt");
    let content = b"SM2 encrypted shared content";
    std::fs::write(&src_file, content).unwrap();
    vault_a.import_file(&src_file).unwrap();

    let files_a = vault_a.list_files().unwrap();
    assert_eq!(files_a.len(), 1);
    let b_pubkey = vault_b.get_sm2_pub_key().expect("B 应有 SM2 公钥");

    let pkg = vault_a
        .share_export_file(&files_a[0].blind_index, b_pubkey)
        .unwrap();

    vault_b.share_import_file(&pkg).unwrap();

    assert_eq!(vault_b.file_count().unwrap(), 1);
    let files_b = vault_b.list_files().unwrap();
    assert_eq!(files_b[0].filename, "shared_doc.txt");
    assert_eq!(files_b[0].original_size, content.len() as u64);
}

// ============================================================
// Shamir KEK 分片/恢复 E2E 测试
// ============================================================

#[test]
fn test_split_kek_recover_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::create(dir.path(), "original_password").unwrap();
    let src_dir = tempfile::tempdir().unwrap();

    let f = src_dir.path().join("test.txt");
    std::fs::write(&f, b"content before recovery").unwrap();
    vault.import_file(&f).unwrap();
    assert_eq!(vault.file_count().unwrap(), 1);
    drop(vault);

    let vault = Vault::open(dir.path(), "original_password").unwrap();
    let n: u8 = 5;
    let t: u8 = 3;
    let shares = vault.split_kek(n, t).unwrap();
    assert_eq!(shares.len(), n as usize);
    drop(vault);

    let recovery_shares: Vec<String> = shares[..t as usize].to_vec();
    let recovered_vault =
        Vault::recover_from_shares(dir.path(), &recovery_shares, t, "recovered_password").unwrap();

    assert_eq!(recovered_vault.file_count().unwrap(), 1);
    let files = recovered_vault.list_files().unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].filename, "test.txt");

    assert!(
        Vault::open(dir.path(), "original_password").is_err(),
        "恢复后旧密码应失效"
    );
    let _vault_new = Vault::open(dir.path(), "recovered_password").unwrap();
}

// ============================================================
// 文件夹导入测试
// ============================================================

#[test]
fn test_import_folder_preserves_structure() {
    let (_dir, vault) = setup_test_vault();

    let src_dir = tempfile::tempdir().unwrap();
    // 创建目录结构：folder/a.txt, folder/sub/b.txt
    let sub_dir = src_dir.path().join("sub");
    std::fs::create_dir_all(&sub_dir).unwrap();
    std::fs::write(src_dir.path().join("a.txt"), b"root file").unwrap();
    std::fs::write(sub_dir.join("b.txt"), b"subdir file").unwrap();

    vault.import_folder(src_dir.path()).unwrap();
    assert_eq!(vault.file_count().unwrap(), 2);

    let files = vault.list_files().unwrap();
    let mut paths: Vec<&str> = files.iter().map(|f| f.filename.as_str()).collect();
    paths.sort();
    assert_eq!(paths, vec!["a.txt", "sub/b.txt"]);
}

// ============================================================
// 文件重命名测试
// ============================================================

#[test]
fn test_rename_file_and_verify() {
    let (_dir, vault) = setup_test_vault();

    let src_dir = tempfile::tempdir().unwrap();
    let src = src_dir.path().join("old_name.txt");
    std::fs::write(&src, b"rename test content").unwrap();
    vault.import_file(&src).unwrap();

    let files = vault.list_files().unwrap();
    assert_eq!(files[0].filename, "old_name.txt");

    vault
        .rename_file(&files[0].blind_index, "new_name.txt")
        .unwrap();

    let files2 = vault.list_files().unwrap();
    assert_eq!(files2.len(), 1);
    assert_eq!(files2[0].filename, "new_name.txt");

    // 导出验证内容完整
    let out_dir = tempfile::tempdir().unwrap();
    vault
        .export_file(&files2[0].blind_index, out_dir.path())
        .unwrap();
    let exported = std::fs::read(out_dir.path().join("new_name.txt")).unwrap();
    assert_eq!(exported, b"rename test content");
}

// ============================================================
// 备份/恢复测试
// ============================================================

#[test]
fn test_backup_and_restore() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::create(dir.path(), "backup_pass").unwrap();

    let src_dir = tempfile::tempdir().unwrap();
    let src = src_dir.path().join("important.doc");
    std::fs::write(&src, b"backup me!").unwrap();
    vault.import_file(&src).unwrap();
    drop(vault);

    // 备份
    let backup_dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), "backup_pass").unwrap();
    vault.backup_to(backup_dir.path()).unwrap();
    drop(vault);

    // 从备份恢复到新目录
    let restore_dir = tempfile::tempdir().unwrap();
    Vault::restore_from(backup_dir.path(), restore_dir.path()).unwrap();

    // 打开并验证
    let restored = Vault::open(restore_dir.path(), "backup_pass").unwrap();
    assert_eq!(restored.file_count().unwrap(), 1);
    let files = restored.list_files().unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].filename, "important.doc");

    let out_dir = tempfile::tempdir().unwrap();
    restored
        .export_file(&files[0].blind_index, out_dir.path())
        .unwrap();
    let exported = std::fs::read(out_dir.path().join("important.doc")).unwrap();
    assert_eq!(exported, b"backup me!");
}

// ============================================================
// 审计日志写入验证
// ============================================================

#[test]
fn test_audit_log_records_operations() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::create(dir.path(), "audit_pass").unwrap();
    drop(vault);
    // 重新打开以初始化审计日志（create 初始化后 drop，返回 None）
    let vault = Vault::open(dir.path(), "audit_pass").unwrap();

    // 导入文件应产生 FileImport 日志
    let src_dir = tempfile::tempdir().unwrap();
    let src = src_dir.path().join("logged.txt");
    std::fs::write(&src, b"audit this").unwrap();
    vault.import_file(&src).unwrap();

    let recent = vault.audit_log_get_recent(10).unwrap();
    assert!(!recent.is_empty(), "操作后审计日志不应为空");

    let has_import = recent
        .iter()
        .any(|(e, _)| e.entry_type == crate::audit_log::AuditEntryType::FileImport as u8);
    assert!(has_import, "导入操作应生成 FileImport 审计日志条目");

    // 删除文件应产生 FileDelete 日志
    let files = vault.list_files().unwrap();
    vault.remove_file(&files[0].blind_index).unwrap();

    let recent2 = vault.audit_log_get_recent(10).unwrap();
    let has_delete = recent2
        .iter()
        .any(|(e, _)| e.entry_type == crate::audit_log::AuditEntryType::FileDelete as u8);
    assert!(has_delete, "删除操作应生成 FileDelete 审计日志条目");
}

// ============================================================
// export_file_to, export_directory_to, remove_directory,
// rename_directory, import_file_and_remove, sanitize_vault_path
// ============================================================

#[test]
fn test_export_file_to_custom_path() {
    let (_dir, vault) = setup_test_vault();

    let src_dir = tempfile::tempdir().unwrap();
    let src_file = src_dir.path().join("custom.txt");
    std::fs::write(&src_file, b"custom path export").unwrap();
    vault.import_file(&src_file).unwrap();

    let files = vault.list_files().unwrap();
    let out_dir = tempfile::tempdir().unwrap();
    let custom_path = out_dir.path().join("renamed_output.txt");
    vault
        .export_file_to(&files[0].blind_index, &custom_path)
        .unwrap();
    let exported = std::fs::read(&custom_path).unwrap();
    assert_eq!(exported, b"custom path export");
}

#[test]
fn test_remove_directory() {
    let (_dir, vault) = setup_test_vault();

    let src_dir = tempfile::tempdir().unwrap();
    let sub_dir = src_dir.path().join("mydir");
    std::fs::create_dir_all(&sub_dir).unwrap();
    std::fs::write(sub_dir.join("f1.txt"), b"file1").unwrap();
    std::fs::write(sub_dir.join("f2.txt"), b"file2").unwrap();

    vault.import_folder(src_dir.path()).unwrap();
    assert_eq!(vault.file_count().unwrap(), 2);

    vault.remove_directory("mydir").unwrap();
    assert_eq!(vault.file_count().unwrap(), 0);
}

#[test]
fn test_export_directory_to() {
    let (_dir, vault) = setup_test_vault();

    let src_dir = tempfile::tempdir().unwrap();
    let sub = src_dir.path().join("docs");
    std::fs::create_dir_all(&sub).unwrap();
    std::fs::write(sub.join("a.txt"), b"aaa").unwrap();
    std::fs::write(sub.join("b.txt"), b"bbb").unwrap();

    vault.import_folder(src_dir.path()).unwrap();
    assert_eq!(vault.file_count().unwrap(), 2);

    let out_dir = tempfile::tempdir().unwrap();
    let count = vault.export_directory_to("docs", out_dir.path()).unwrap();
    assert_eq!(count, 2);
    assert!(out_dir.path().join("a.txt").exists());
    assert!(out_dir.path().join("b.txt").exists());
}

#[test]
fn test_rename_directory() {
    let (_dir, vault) = setup_test_vault();

    let src_dir = tempfile::tempdir().unwrap();
    let sub = src_dir.path().join("olddir");
    std::fs::create_dir_all(&sub).unwrap();
    std::fs::write(sub.join("note.txt"), b"rename dir test").unwrap();

    vault.import_folder(src_dir.path()).unwrap();
    vault.rename_directory("olddir", "newdir").unwrap();

    let files = vault.list_files().unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].filename, "newdir/note.txt");
}

#[test]
fn test_import_file_and_remove() {
    let (_dir, vault) = setup_test_vault();

    let src_dir = tempfile::tempdir().unwrap();
    let src_file = src_dir.path().join("to_remove.txt");
    std::fs::write(&src_file, b"will be removed after import").unwrap();

    vault.import_file_and_remove(&src_file).unwrap();
    assert_eq!(vault.file_count().unwrap(), 1);
    assert!(!src_file.exists(), "源文件应被删除");
}

#[test]
fn test_sanitize_vault_path() {
    assert_eq!(
        Vault::sanitize_vault_path("normal/path/file.txt"),
        "normal/path/file.txt"
    );
    assert_eq!(
        Vault::sanitize_vault_path("..\\..\\secret.txt"),
        "secret.txt"
    );
    assert_eq!(Vault::sanitize_vault_path(""), super::DEFAULT_FILE_NAME);
    assert_eq!(
        Vault::sanitize_vault_path("/absolute/path"),
        "absolute/path"
    );
    assert_eq!(Vault::sanitize_vault_path("a/b:c/d"), "a/b c/d");
}
