//! 内建基准测试
//!
//! 覆盖整个产品性能：
//! - SM4 三种实现对比（S-Box / T-Table / CT bitslice）
//! - SM4-CBC 加解密（KEK 包裹/解包路径）
//! - HMAC-SM3 完整性校验
//! - PBKDF2-SM3 密钥派生（100k / 600k）
//! - SM2 密钥生成 + 签名 + 验签
//! - Shamir 秘密共享（分片 + 恢复）
//! - 全链路文件操作（1KB / 1MB / 10MB 三级）
//! - 保险箱打开（登录）
//! - 批量导入 10 个 1MB 文件
//!
//! 结果在 GUI 面板和 CLI 中展示，无需外部工具。

use std::time::Instant;

use crate::crypto::sm3::pbkdf2_sm3;
use crate::crypto::sm4_ctr::sm4_ctr_crypt;

/// 基准数据块大小（1 MB）
const ONE_MB: usize = 1024 * 1024;
/// 1 KB
const ONE_KB: usize = 1024;
/// 10 MB
const TEN_MB: usize = 10 * 1024 * 1024;
/// CT SM4 基准数据块大小（4 KB — CT 实现慢，用更小数据量）
const CT_BENCH_SIZE: usize = 4096;

/// 基准测试结果集合
#[derive(Debug, Clone)]
pub struct BenchResults {
    // ── SM4 加密 ──
    /// SM4 基线吞吐量 (MB/s)
    pub sm4_baseline_mbps: f64,
    /// SM4 T-Table 吞吐量 (MB/s)
    pub sm4_t_table_mbps: f64,
    /// SM4 CT (常数时间) 吞吐量 (KB/s，4KB 数据)
    pub sm4_ct_kbps: f64,
    /// 加速比 (T-Table / Baseline)
    pub speedup: f64,

    // ── SM4-CBC（KEK 包裹/解包路径）──
    /// SM4-CBC 加密吞吐量 (MB/s)
    pub sm4_cbc_encrypt_mbps: f64,
    /// SM4-CBC 解密吞吐量 (MB/s)
    pub sm4_cbc_decrypt_mbps: f64,

    // ── 完整性校验 ──
    /// HMAC-SM3 吞吐量 (MB/s)
    pub hmac_sm3_mbps: f64,

    // ── 密钥派生 ──
    /// PBKDF2-SM3 600k 迭代耗时 (ms)
    pub pbkdf2_ms: f64,
    /// PBKDF2-SM3 100k 迭代耗时 (ms)
    pub pbkdf2_100k_ms: f64,

    // ── SM2 公钥密码 ──
    /// SM2 密钥生成耗时 (ms)
    pub sm2_keygen_ms: f64,
    /// SM2 签名耗时 (ms)
    pub sm2_sign_ms: f64,
    /// SM2 验证耗时 (ms)
    pub sm2_verify_ms: f64,

    // ── Shamir 秘密共享（KEK 灾备）──
    /// Shamir 5-of-3 分片耗时 (μs)
    pub shamir_split_us: f64,
    /// Shamir 3 份恢复耗时 (μs)
    pub shamir_recover_us: f64,

    // ── 全链路文件操作 ──
    /// 1KB 文件导入耗时 (μs)
    pub import_1kb_us: Option<f64>,
    /// 1KB 文件导出耗时 (μs)
    pub export_1kb_us: Option<f64>,
    /// 1MB 文件导入耗时 (ms)
    pub import_1mb_ms: Option<f64>,
    /// 1MB 文件导出耗时 (ms)
    pub export_1mb_ms: Option<f64>,
    /// 10MB 文件导入耗时 (ms)
    pub import_10mb_ms: Option<f64>,
    /// 10MB 文件导出耗时 (ms)
    pub export_10mb_ms: Option<f64>,

    // ── 保险箱操作 ──
    /// 保险箱打开（登录）耗时 (ms)
    pub vault_open_ms: f64,

    // ── 批量操作 ──
    /// 批量导入 10 个 1MB 文件耗时 (ms)
    pub batch_import_10x1mb_ms: Option<f64>,
}

impl Default for BenchResults {
    fn default() -> Self {
        Self {
            sm4_baseline_mbps: 0.0,
            sm4_t_table_mbps: 0.0,
            sm4_ct_kbps: 0.0,
            speedup: 0.0,
            sm4_cbc_encrypt_mbps: 0.0,
            sm4_cbc_decrypt_mbps: 0.0,
            hmac_sm3_mbps: 0.0,
            pbkdf2_ms: 0.0,
            pbkdf2_100k_ms: 0.0,
            sm2_keygen_ms: 0.0,
            sm2_sign_ms: 0.0,
            sm2_verify_ms: 0.0,
            shamir_split_us: 0.0,
            shamir_recover_us: 0.0,
            import_1kb_us: None,
            export_1kb_us: None,
            import_1mb_ms: None,
            export_1mb_ms: None,
            import_10mb_ms: None,
            export_10mb_ms: None,
            vault_open_ms: 0.0,
            batch_import_10x1mb_ms: None,
        }
    }
}

/// 运行纯计算基准测试（约 5 秒，不需要保险箱）
pub fn run_all_benches() -> BenchResults {
    let mut results = BenchResults::default();

    // =========================================================
    // 1. SM4 吞吐量（1MB 数据）
    // =========================================================
    let key = [0xABu8; 16];
    let nonce = [0xCDu8; 12];
    let data_size = ONE_MB;
    let data = vec![0x42u8; data_size];

    // 基线 (S-Box)
    let start = Instant::now();
    let _ = sm4_ctr_crypt(&key, &nonce, &data);
    results.sm4_baseline_mbps = (data_size as f64 / 1_000_000.0) / start.elapsed().as_secs_f64();

    // T-Table
    let start = Instant::now();
    let _ = crate::crypto::sm4_ctr::sm4_ctr_crypt_t_table(&key, &nonce, &data);
    let dur = start.elapsed();
    results.sm4_t_table_mbps = (data_size as f64 / 1_000_000.0) / dur.as_secs_f64();
    results.speedup = results.sm4_t_table_mbps / results.sm4_baseline_mbps;

    // CT SM4（4KB — 比 T-Table 慢约 20000x）
    let ct_data = vec![0x42u8; CT_BENCH_SIZE];
    let ct_iv = [0xCDu8; 16];
    let start = Instant::now();
    let _ = crate::crypto::sm4_bitslice::sm4_ct_cbc_encrypt(&key, &ct_iv, &ct_data);
    results.sm4_ct_kbps = (CT_BENCH_SIZE as f64 / 1000.0) / start.elapsed().as_secs_f64();

    // =========================================================
    // 2. SM4-CBC 加解密（KEK 包裹/解包路径，1MB）
    // =========================================================
    let sm4_key = crate::crypto::sm4_ctr::Sm4Key::new(&key);
    let cbc_iv = [0xDEu8; 16];
    let cbc_data = vec![0x42u8; ONE_MB];

    // CBC 加密
    let start = Instant::now();
    let cbc_ct = crate::crypto::sm4_ctr::sm4_cbc_encrypt(&sm4_key, &cbc_iv, &cbc_data);
    results.sm4_cbc_encrypt_mbps =
        (ONE_MB as f64 / 1_000_000.0) / start.elapsed().as_secs_f64();

    // CBC 解密
    let start = Instant::now();
    let _ = crate::crypto::sm4_ctr::sm4_cbc_decrypt_with_key(&sm4_key, &cbc_iv, &cbc_ct)
        .expect("CBC 解密失败");
    results.sm4_cbc_decrypt_mbps =
        (ONE_MB as f64 / 1_000_000.0) / start.elapsed().as_secs_f64();

    // =========================================================
    // 3. HMAC-SM3 吞吐量（1MB — 文件完整性校验关键路径）
    // =========================================================
    let hmac_data = vec![0x42u8; ONE_MB];
    let hmac_key = b"bench_hmac_key_16B";
    let start = Instant::now();
    let _ = crate::crypto::sm3::hmac_sm3(hmac_key, &hmac_data);
    results.hmac_sm3_mbps = (ONE_MB as f64 / 1_000_000.0) / start.elapsed().as_secs_f64();

    // =========================================================
    // 4. PBKDF2-SM3 密钥派生
    // =========================================================
    let password = b"bench_test_password";
    let salt = b"bench_salt_123";

    let start = Instant::now();
    let _ = pbkdf2_sm3(password, salt, 100_000, 16);
    results.pbkdf2_100k_ms = start.elapsed().as_secs_f64() * 1000.0;

    let start = Instant::now();
    let _ = pbkdf2_sm3(password, salt, 600_000, 16);
    results.pbkdf2_ms = start.elapsed().as_secs_f64() * 1000.0;

    // =========================================================
    // 5. SM2 密钥生成 + 签名 + 验签
    // =========================================================
    let start = Instant::now();
    let (sm2_priv, sm2_pub) = crate::crypto::sm2::generate_key_pair();
    results.sm2_keygen_ms = start.elapsed().as_secs_f64() * 1000.0;

    let msg = b"SM2 bench test message";

    let start = Instant::now();
    let sig = crate::crypto::sm2::sign(&sm2_priv, &sm2_pub, msg);
    results.sm2_sign_ms = start.elapsed().as_secs_f64() * 1000.0;

    let start = Instant::now();
    let _ = crate::crypto::sm2::verify(&sm2_pub, msg, &sig);
    results.sm2_verify_ms = start.elapsed().as_secs_f64() * 1000.0;

    // =========================================================
    // 6. Shamir 秘密共享（分片 + 恢复）
    // =========================================================
    let kek_secret = vec![0xAAu8; 16];

    // Shamir 操作极快，用 μs 测量
    let start = Instant::now();
    let shares = crate::crypto::shamir::split_secret(&kek_secret, 5, 3);
    results.shamir_split_us = start.elapsed().as_secs_f64() * 1_000_000.0;

    let start = Instant::now();
    let _ = crate::crypto::shamir::recover_secret(&shares[..3], 3);
    results.shamir_recover_us = start.elapsed().as_secs_f64() * 1_000_000.0;

    results
}

/// 运行全链路文件 I/O 基准测试（需要临时保险箱）
///
/// 覆盖：不同大小文件导入/导出、保险箱打开、批量导入。
///
/// **注意：** 返回的 `BenchResults` 中仅文件 I/O 相关字段有效，
/// 计算类字段值为 `0.0`，调用方应配合 `run_all_benches()` 合并使用。
pub fn run_io_benches() -> BenchResults {
    let mut results = BenchResults::default();

    // =========================================================
    // 阶段 1：创建保险箱 + 测速打开（登录）
    // =========================================================
    let dir = tempfile::tempdir().expect("无法创建临时目录");
    let vault =
        crate::vault::Vault::create(dir.path(), "bench_password").expect("无法创建测试保险箱");

    // 关闭后重新打开，测量登录速度（PBKDF2 + KEK 派生 + 配置校验）
    drop(vault);
    let start = Instant::now();
    let vault = crate::vault::Vault::open(dir.path(), "bench_password").expect("无法打开测试保险箱");
    results.vault_open_ms = start.elapsed().as_secs_f64() * 1000.0;

    let src_dir = tempfile::tempdir().expect("无法创建临时目录");

    // =========================================================
    // 阶段 2：1KB 极小文件（测量系统开销）
    // =========================================================
    let src_1kb = src_dir.path().join("bench_1kb.bin");
    let content_1kb = vec![0xABu8; ONE_KB];
    std::fs::write(&src_1kb, &content_1kb).expect("无法写 1KB 测试文件");

    let start = Instant::now();
    vault.import_file(&src_1kb).expect("1KB 导入失败");
    results.import_1kb_us = Some(start.elapsed().as_secs_f64() * 1_000_000.0);

    // 查找 1KB 文件的 blind_index
    let find_1kb = |files: &[crate::vault::FileInfo]| -> Option<[u8; 32]> {
        files.iter().find(|f| f.filename == "bench_1kb.bin").map(|f| f.blind_index)
    };
    let files = vault.list_files().expect("列表失败");
    let idx_1kb = find_1kb(&files).expect("未找到 1KB 文件");

    let out_dir_1kb = tempfile::tempdir().expect("无法创建临时目录");
    let start = Instant::now();
    vault.export_file(&idx_1kb, out_dir_1kb.path()).expect("1KB 导出失败");
    results.export_1kb_us = Some(start.elapsed().as_secs_f64() * 1_000_000.0);

    // =========================================================
    // 阶段 3：1MB 标准文件（现有兼容）
    // =========================================================
    let src_1mb = src_dir.path().join("bench_1mb.bin");
    let content_1mb = vec![0xABu8; ONE_MB];
    std::fs::write(&src_1mb, &content_1mb).expect("无法写 1MB 测试文件");

    let start = Instant::now();
    vault.import_file(&src_1mb).expect("1MB 导入失败");
    results.import_1mb_ms = Some(start.elapsed().as_secs_f64() * 1000.0);

    let files = vault.list_files().expect("列表失败");
    let idx_1mb = files.iter()
        .find(|f| f.filename == "bench_1mb.bin")
        .map(|f| f.blind_index)
        .expect("未找到 1MB 文件");

    let out_dir_1mb = tempfile::tempdir().expect("无法创建临时目录");
    let start = Instant::now();
    vault.export_file(&idx_1mb, out_dir_1mb.path()).expect("1MB 导出失败");
    results.export_1mb_ms = Some(start.elapsed().as_secs_f64() * 1000.0);

    // =========================================================
    // 阶段 4：10MB 大文件（I/O 瓶颈）
    // =========================================================
    let src_10mb = src_dir.path().join("bench_10mb.bin");
    let content_10mb = vec![0xABu8; TEN_MB];
    std::fs::write(&src_10mb, &content_10mb).expect("无法写 10MB 测试文件");

    let start = Instant::now();
    vault.import_file(&src_10mb).expect("10MB 导入失败");
    results.import_10mb_ms = Some(start.elapsed().as_secs_f64() * 1000.0);

    let files = vault.list_files().expect("列表失败");
    let idx_10mb = files.iter()
        .find(|f| f.filename == "bench_10mb.bin")
        .map(|f| f.blind_index)
        .expect("未找到 10MB 文件");

    let out_dir_10mb = tempfile::tempdir().expect("无法创建临时目录");
    let start = Instant::now();
    vault.export_file(&idx_10mb, out_dir_10mb.path()).expect("10MB 导出失败");
    results.export_10mb_ms = Some(start.elapsed().as_secs_f64() * 1000.0);

    // =========================================================
    // 阶段 5：批量导入 10 个 1MB 文件
    // =========================================================
    let batch_dir = tempfile::tempdir().expect("无法创建临时目录");
    let batch_vault =
        crate::vault::Vault::create(batch_dir.path(), "bench_batch").expect("无法创建批量测试保险箱");
    let batch_src = tempfile::tempdir().expect("无法创建临时目录");
    for i in 0..10 {
        let path = batch_src.path().join(format!("batch_{}.bin", i));
        std::fs::write(&path, vec![0xCDu8; ONE_MB]).expect("无法写批量测试文件");
    }
    let start = Instant::now();
    for i in 0..10 {
        let path = batch_src.path().join(format!("batch_{}.bin", i));
        batch_vault.import_file(&path).expect("批量导入失败");
    }
    results.batch_import_10x1mb_ms = Some(start.elapsed().as_secs_f64() * 1000.0);

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 验证 SM4 吞吐量和 PBKDF2 基准测试返回值非负
    #[test]
    fn test_bench_sm4_throughput() {
        let r = run_all_benches();
        assert!(r.sm4_baseline_mbps > 0.0, "基线吞吐量应 > 0");
        assert!(r.sm4_t_table_mbps > 0.0, "T-Table 吞吐量应 > 0");
        assert!(r.sm4_cbc_encrypt_mbps > 0.0, "CBC 加密吞吐量应 > 0");
        assert!(r.sm4_cbc_decrypt_mbps > 0.0, "CBC 解密吞吐量应 > 0");
        assert!(r.hmac_sm3_mbps > 0.0, "HMAC-SM3 吞吐量应 > 0");
        assert!(r.pbkdf2_ms > 0.0, "PBKDF2 耗时应 > 0");
        assert!(r.speedup >= 0.5, "加速比应 >= 0.5");
        assert!(r.sm2_keygen_ms > 0.0, "SM2 密钥生成耗时应 > 0");
        assert!(r.sm2_sign_ms > 0.0, "SM2 签名耗时应 > 0");
        assert!(r.sm2_verify_ms > 0.0, "SM2 验签耗时应 > 0");
        assert!(r.shamir_split_us > 0.0, "Shamir 分片耗时应 > 0");
        assert!(r.shamir_recover_us > 0.0, "Shamir 恢复耗时应 > 0");
        eprintln!(
            "SM4 基线: {:.1} MB/s | T-Table: {:.1} MB/s | 加速比: {:.2}x",
            r.sm4_baseline_mbps, r.sm4_t_table_mbps, r.speedup
        );
        eprintln!(
            "SM4-CBC 加密: {:.1} MB/s | 解密: {:.1} MB/s",
            r.sm4_cbc_encrypt_mbps, r.sm4_cbc_decrypt_mbps
        );
        eprintln!(
            "PBKDF2 100k: {:.1} ms | 600k: {:.1} ms",
            r.pbkdf2_100k_ms, r.pbkdf2_ms
        );
        eprintln!(
            "SM2 密钥生成: {:.1} ms | 签名: {:.1} ms | 验签: {:.1} ms",
            r.sm2_keygen_ms, r.sm2_sign_ms, r.sm2_verify_ms
        );
        eprintln!(
            "Shamir 分片: {:.1} μs | 恢复: {:.1} μs",
            r.shamir_split_us, r.shamir_recover_us
        );
    }

    /// 验证全链路文件 I/O 基准测试返回值非负
    #[test]
    fn test_bench_io() {
        let r = run_io_benches();
        assert!(r.vault_open_ms > 0.0, "保险箱打开耗时应 > 0");
        if let Some(v) = r.import_1kb_us {
            assert!(v > 0.0);
        }
        if let Some(v) = r.export_1kb_us {
            assert!(v > 0.0);
        }
        assert!(r.import_1mb_ms.unwrap() > 0.0);
        assert!(r.export_1mb_ms.unwrap() > 0.0);
        if let Some(v) = r.import_10mb_ms {
            assert!(v > 0.0);
        }
        if let Some(v) = r.export_10mb_ms {
            assert!(v > 0.0);
        }
        if let Some(v) = r.batch_import_10x1mb_ms {
            assert!(v > 0.0);
        }
        eprintln!(
            "保险箱打开: {:.1} ms", r.vault_open_ms
        );
        eprintln!(
            "1KB 导入: {:.1} μs | 导出: {:.1} μs",
            r.import_1kb_us.unwrap_or(0.0),
            r.export_1kb_us.unwrap_or(0.0)
        );
        eprintln!(
            "1MB 导入: {:.1} ms | 导出: {:.1} ms",
            r.import_1mb_ms.unwrap(),
            r.export_1mb_ms.unwrap()
        );
        if let (Some(imp), Some(exp)) = (r.import_10mb_ms, r.export_10mb_ms) {
            eprintln!("10MB 导入: {:.1} ms | 导出: {:.1} ms", imp, exp);
        }
        if let Some(batch) = r.batch_import_10x1mb_ms {
            eprintln!("批量导入 10×1MB: {:.1} ms", batch);
        }
    }
}
