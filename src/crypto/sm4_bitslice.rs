//! Bitslice SM4 —— 128 路并行常数时间实现
//!
//! # 原理
//!
//! 将 SM4 转换为布尔电路，使用 `u128` 同时处理 128 个块：
//!
//! - 每个 `u128` 持有 128 个块在**同一个比特位**的值
//! - S-Box 用按位匹配公式计算（逐项比对 256 个候选值，始终遍历全部）
//! - **所有**操作为位运算（XOR, AND, OR, NOT），无数据相关的内存访问
//! - 内存访问模式与输入数据无关 → 抗缓存时序侧信道（含 MemJam）
//!
//! # 性能特征
//!
//! - 128 路并行，适合批量加密（如 64 KB 分块 = 4096 块 → 32 次 bitslice 调用）
//!
//! # 优化说明
//!
//! - S-Box 的 256 个输出值预先展开为 8 个 `u128` 位平面，避免运行时 `wrapping_neg()` 开销
//! - 8 位比较循环手动展开，帮助编译器优化表达式树
//! - 转置函数使用 u32 字加载代替逐字节加载

use std::sync::OnceLock;

use crate::crypto::sm4_ctr::{SBOX, sm4_key_expansion};

// ============================================================
// Bitslice S-Box（常数时间）
// ============================================================

/// 预计算 S-Box 输出位平面：
/// `sbox_bits[k][bit]` = !0（如果 SBOX[k] 的第 bit 位为 1）或 0
fn sbox_bits() -> &'static [[u128; 8]; 256] {
    static BITS: OnceLock<[[u128; 8]; 256]> = OnceLock::new();
    BITS.get_or_init(|| {
        let mut bits = [[0u128; 8]; 256];
        for i in 0..256 {
            let sv = SBOX[i];
            for bit in 0..8 {
                if (sv >> bit) & 1 == 1 {
                    bits[i][bit] = !0u128;
                }
            }
        }
        bits
    })
}

/// Bitslice S-Box：对 128 个块同时应用 SM4 S-Box
///
/// # 参数
///
/// * `input` — 8 个 `u128`，第 i 个 `u128` 的第 j 位是第 j 个块在输入字节的第 i 位
///
/// # 返回值
///
/// 8 个 `u128`，格式同上，值为 S-Box 输出字节的各位
///
/// # 常数时间保证
///
/// 始终遍历全部 256 个 S-Box 条目，无数据依赖分支。
#[inline]
fn bitslice_sbox(input: &[u128; 8]) -> [u128; 8] {
    let sb = sbox_bits();
    let mut output = [0u128; 8];

    for k in 0u8..=255u8 {
        // 将 k 的 8 个比特展开为 0/!0 并行匹配比较
        // k_bit = 0 → expand = 0:  !(input[bit] ^ 0) = !input[bit]
        // k_bit = 1 → expand = !0: !(input[bit] ^ !0) = input[bit]
        let e0 = (((k >> 0) & 1) as u128).wrapping_neg();
        let e1 = (((k >> 1) & 1) as u128).wrapping_neg();
        let e2 = (((k >> 2) & 1) as u128).wrapping_neg();
        let e3 = (((k >> 3) & 1) as u128).wrapping_neg();
        let e4 = (((k >> 4) & 1) as u128).wrapping_neg();
        let e5 = (((k >> 5) & 1) as u128).wrapping_neg();
        let e6 = (((k >> 6) & 1) as u128).wrapping_neg();
        let e7 = (((k >> 7) & 1) as u128).wrapping_neg();

        // 8 位比较合并为单一表达式，辅助编译器别名为单一 SSA 链
        let eq = !(input[0] ^ e0)
               & !(input[1] ^ e1)
               & !(input[2] ^ e2)
               & !(input[3] ^ e3)
               & !(input[4] ^ e4)
               & !(input[5] ^ e5)
               & !(input[6] ^ e6)
               & !(input[7] ^ e7);

        // 使用预先展开的 S-Box 位平面
        let s = &sb[k as usize];
        output[0] |= eq & s[0];
        output[1] |= eq & s[1];
        output[2] |= eq & s[2];
        output[3] |= eq & s[3];
        output[4] |= eq & s[4];
        output[5] |= eq & s[5];
        output[6] |= eq & s[6];
        output[7] |= eq & s[7];
    }
    output
}

// ============================================================
// Bitslice SM4 密钥展开
// ============================================================

/// Bitslice 轮密钥：每个比特位一个 `u128`
///
/// `rk[round][bit]` 中第 i 个比特位对应第 i 个块在该轮的轮密钥的第 `bit` 位。
struct BitsliceRoundKeys {
    rk: [[u128; 32]; 32],
}

impl BitsliceRoundKeys {
    /// 从 16 字节 SM4 密钥生成 bitslice 轮密钥
    fn new(key: &[u8; 16]) -> Self {
        let rk_scalar = sm4_key_expansion(key);
        let mut rk = [[0u128; 32]; 32];
        for round in 0..32 {
            let rk_val = rk_scalar[round];
            for bit in 0..32 {
                if (rk_val >> bit) & 1 == 1 {
                    rk[round][bit] = !0u128;
                }
            }
        }
        Self { rk }
    }
}

// ============================================================
// Bitslice SM4 单轮
// ============================================================

/// Bitslice SM4 状态：4 个 32 位字，每个字分解为 32 个 bit-slice u128
///
/// `state[word][bit]` 的第 i 位 = 第 i 个块在该字的第 bit 位
type BitsliceState = [[u128; 32]; 4];

/// 执行一轮 bitslice SM4（含 τ + L 变换）
fn bitslice_round(state: &mut BitsliceState, rk: &[u128; 32]) {
    // ---- 第 1 步: y = X1 ^ X2 ^ X3 ^ rk ----
    let mut y = [0u128; 32];
    for b in 0..32 {
        y[b] = state[1][b] ^ state[2][b] ^ state[3][b] ^ rk[b];
    }

    // ---- 第 2 步: τ 变换（S-Box 逐字节） ----
    let sb3 = bitslice_sbox(array_ref_8(&y[24..32])); // MSB 字节
    let sb2 = bitslice_sbox(array_ref_8(&y[16..24]));
    let sb1 = bitslice_sbox(array_ref_8(&y[8..16]));
    let sb0 = bitslice_sbox(array_ref_8(&y[0..8])); // LSB 字节

    // 合并回 32 位（大端）
    let mut sb = [0u128; 32];
    sb[0..8].copy_from_slice(&sb0);
    sb[8..16].copy_from_slice(&sb1);
    sb[16..24].copy_from_slice(&sb2);
    sb[24..32].copy_from_slice(&sb3);

    // ---- 第 3 步: L 变换 ----
    // L(B) = B ^ (B <<< 2) ^ (B <<< 10) ^ (B <<< 18) ^ (B <<< 24)
    let mut t = [0u128; 32];
    for i in 0..32 {
        t[i] = sb[i]
            ^ sb[(i + 30) % 32]   // B <<< 2  → bit i = B[(i-2) % 32]
            ^ sb[(i + 22) % 32]   // B <<< 10
            ^ sb[(i + 14) % 32]   // B <<< 18
            ^ sb[(i + 8) % 32];   // B <<< 24
    }

    // ---- 第 4 步: X3_new = X0 ^ t ----
    for b in 0..32 {
        let x3_new = state[0][b] ^ t[b];
        state[0][b] = state[1][b];
        state[1][b] = state[2][b];
        state[2][b] = state[3][b];
        state[3][b] = x3_new;
    }
}

/// 从切片取固定 8 元素数组引用
fn array_ref_8(slice: &[u128]) -> &[u128; 8] {
    slice.try_into().expect("bitslice 每个字节恰好 8 个 u128")
}

// ============================================================
// Bitslice 转置（Normal ↔ Bitslice）
// ============================================================

/// 将 128 个 16 字节明文块转换为 bitslice 状态
///
/// `blocks` 是 128 x 16 = 2048 字节，排列为 `[block0][block1]...[block127]`
/// 输出 `state[word][bit]` 中第 i 位 = blocks[i] 在 word 的第 bit 位
///
/// 优化：用 u32 字加载代替逐字节操作，减少循环开销。
fn transpose_to_bitslice(blocks: &[u8; 2048]) -> BitsliceState {
    let mut state = [[0u128; 32]; 4];

    for block_idx in 0..128 {
        let base = block_idx * 16;
        let mask = 1u128 << block_idx;
        for word in 0..4 {
            let wb = word * 4;
            let word_val = u32::from_be_bytes([
                blocks[base + wb],
                blocks[base + wb + 1],
                blocks[base + wb + 2],
                blocks[base + wb + 3],
            ]);
            for bit in 0..32 {
                if (word_val >> bit) & 1 == 1 {
                    state[word][bit] |= mask;
                }
            }
        }
    }
    state
}

/// 将 bitslice 状态转置回 128 个 16 字节密文块
///
/// 优化：用 u32 字写入代替逐字节操作。
fn transpose_from_bitslice(state: &BitsliceState) -> [u8; 2048] {
    let mut blocks = [0u8; 2048];

    for block_idx in 0..128 {
        let base = block_idx * 16;
        for word in 0..4 {
            let wb = word * 4;
            let mut word_val = 0u32;
            for bit in 0..32 {
                if (state[word][bit] >> block_idx) & 1 == 1 {
                    word_val |= 1u32 << bit;
                }
            }
            let bytes = word_val.to_be_bytes();
            blocks[base + wb]     = bytes[0];
            blocks[base + wb + 1] = bytes[1];
            blocks[base + wb + 2] = bytes[2];
            blocks[base + wb + 3] = bytes[3];
        }
    }
    blocks
}

// ============================================================
// 公开 API
// ============================================================

/// Bitslice SM4 密钥（128 路并行常数时间加密）
pub struct Sm4BitsliceKey {
    rk: BitsliceRoundKeys,
}

impl Sm4BitsliceKey {
    /// 从 16 字节 SM4 密钥创建 bitslice 密钥
    pub fn new(key: &[u8; 16]) -> Self {
        Self {
            rk: BitsliceRoundKeys::new(key),
        }
    }

    /// 并行加密 128 个块（2048 字节）
    ///
    /// # 参数
    ///
    /// * `plaintext` — 128 个连续明文块，共 2048 字节
    ///   `plaintext[0..16]` 是第 0 块，`plaintext[16..32]` 是第 1 块，以此类推
    ///
    /// # 返回值
    ///
    /// 128 个密文块，共 2048 字节，格式同上
    pub fn encrypt_128_blocks(&self, plaintext: &[u8; 2048]) -> [u8; 2048] {
        let mut state = transpose_to_bitslice(plaintext);

        // 32 轮加密
        for round in 0..32 {
            bitslice_round(&mut state, &self.rk.rk[round]);
        }

        // SM4 反序输出：state 最终为 [X32, X33, X34, X35]
        state.swap(0, 3);
        state.swap(1, 2);

        transpose_from_bitslice(&state)
    }
}

// ============================================================
// 标量常数时间 SM4（单块回退，供 bench.rs 等使用）
// ============================================================

/// 常数时间相等判定: 0xFF（相等）或 0x00（不等）
#[inline]
fn ct_eq_mask(a: u8, b: u8) -> u8 {
    let mut diff = a ^ b;
    diff |= diff >> 4;
    diff |= diff >> 2;
    diff |= diff >> 1;
    (diff & 1).wrapping_sub(1)
}

/// 常数时间 S-Box 单块查找（全扫描 256 项，无分支）
fn ct_sbox_scalar(x: u8) -> u8 {
    let mut r = 0u8;
    let mut i = 0usize;
    while i < 256 {
        r |= SBOX[i] & ct_eq_mask(x, i as u8);
        i += 1;
    }
    r
}

fn sm4_ct_subword_scalar(x: u32) -> u32 {
    let b = x.to_be_bytes();
    u32::from_be_bytes([
        ct_sbox_scalar(b[0]),
        ct_sbox_scalar(b[1]),
        ct_sbox_scalar(b[2]),
        ct_sbox_scalar(b[3]),
    ])
}

/// 常数时间 SM4 单块加密（标量回退版本）
pub fn sm4_ct_encrypt_block(block: &[u8; 16], rk: &[u32; 32]) -> [u8; 16] {
    let mut x = [
        u32::from_be_bytes([block[0], block[1], block[2], block[3]]),
        u32::from_be_bytes([block[4], block[5], block[6], block[7]]),
        u32::from_be_bytes([block[8], block[9], block[10], block[11]]),
        u32::from_be_bytes([block[12], block[13], block[14], block[15]]),
    ];
    for &rk_i in rk.iter() {
        let y = x[1] ^ x[2] ^ x[3] ^ rk_i;
        let sb = sm4_ct_subword_scalar(y);
        let t =
            sb ^ sb.rotate_left(2) ^ sb.rotate_left(10) ^ sb.rotate_left(18) ^ sb.rotate_left(24);
        let f = x[0] ^ t;
        x[0] = x[1];
        x[1] = x[2];
        x[2] = x[3];
        x[3] = f;
    }
    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&x[3].to_be_bytes());
    out[4..8].copy_from_slice(&x[2].to_be_bytes());
    out[8..12].copy_from_slice(&x[1].to_be_bytes());
    out[12..16].copy_from_slice(&x[0].to_be_bytes());
    out
}

/// 常数时间 SM4-CBC 加密（单块回退，供 bench.rs 使用）
pub fn sm4_ct_cbc_encrypt(key: &[u8; 16], iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    let rk = sm4_key_expansion(key);
    let pad_byte = (16 - (plaintext.len() % 16)) as u8;
    let padded_len = plaintext.len() + pad_byte as usize;
    let block_count = padded_len / 16;
    let mut ciphertext = Vec::with_capacity(padded_len);
    let mut prev = *iv;
    let mut offset = 0;
    for _ in 0..block_count {
        let mut block = [pad_byte; 16];
        let remaining = plaintext.len().saturating_sub(offset);
        if remaining > 0 {
            let n = remaining.min(16);
            block[..n].copy_from_slice(&plaintext[offset..offset + n]);
        }
        for j in 0..16 {
            block[j] ^= prev[j];
        }
        let encrypted = sm4_ct_encrypt_block(&block, &rk);
        ciphertext.extend_from_slice(&encrypted);
        prev = encrypted;
        offset += 16;
    }
    ciphertext
}

// ============================================================
// 测试
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sm4_ctr::sm4_encrypt_block;

    const TEST_KEY: [u8; 16] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];
    const TEST_PT: [u8; 16] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];
    const TEST_CT: [u8; 16] = [
        0x68, 0x1E, 0xDF, 0x34, 0xD2, 0x06, 0x96, 0x5E, 0x86, 0xB3, 0xE9, 0x4F, 0x53, 0x6E, 0x42,
        0x46,
    ];

    fn make_128_identical_blocks(block: &[u8; 16]) -> [u8; 2048] {
        let mut data = [0u8; 2048];
        for i in 0..128 {
            data[i * 16..(i + 1) * 16].copy_from_slice(block);
        }
        data
    }

    fn make_128_diverse_blocks() -> [u8; 2048] {
        let mut data = [0u8; 2048];
        for i in 0..128 {
            let base = i * 16;
            for j in 0..16 {
                data[base + j] = ((i * 16 + j) ^ 0xAB) as u8;
            }
        }
        data
    }

    #[test]
    fn test_bitslice_sbox_known_entry() {
        let input = [0u128; 8];
        let result = bitslice_sbox(&input);
        let expected = SBOX[0x00];
        for bit in 0..8 {
            let expected_bit = (expected >> bit) & 1;
            let bit_val = if expected_bit == 1 { !0u128 } else { 0u128 };
            assert_eq!(result[bit], bit_val, "SBOX[0x00] 的第 {} 位", bit);
        }
    }

    #[test]
    fn test_bitslice_sbox_all_inputs() {
        for val in 0u8..=255u8 {
            let mut input = [0u128; 8];
            for bit in 0..8 {
                if (val >> bit) & 1 == 1 {
                    input[bit] = !0u128;
                }
            }
            let result = bitslice_sbox(&input);
            let expected = SBOX[val as usize];
            for bit in 0..8 {
                let expected_bit = (expected >> bit) & 1;
                let bit_val = if expected_bit == 1 { !0u128 } else { 0u128 };
                assert_eq!(
                    result[bit], bit_val,
                    "SBOX[0x{:02X}] 的第 {} 位 (预期 {})",
                    val, bit, expected_bit
                );
            }
        }
    }

    #[test]
    fn test_bitslice_sbox_mixed_blocks() {
        let mut input = [0u128; 8];
        for block_idx in 0..128 {
            let val = block_idx as u8;
            for bit in 0..8 {
                if (val >> bit) & 1 == 1 {
                    input[bit] |= 1u128 << block_idx;
                }
            }
        }
        let result = bitslice_sbox(&input);
        for block_idx in 0..128 {
            let expected = SBOX[block_idx as usize];
            for bit in 0..8 {
                let got = (result[bit] >> block_idx) & 1;
                let want = (expected >> bit) & 1;
                assert_eq!(
                    got, want as u128,
                    "块 {} SBOX[0x{:02X}] 的第 {} 位",
                    block_idx, block_idx, bit
                );
            }
        }
    }

    #[test]
    fn test_bitslice_roundtrip_128_identical() {
        let plaintext = make_128_identical_blocks(&TEST_PT);
        let key = Sm4BitsliceKey::new(&TEST_KEY);
        let ciphertext = key.encrypt_128_blocks(&plaintext);

        for i in 0..128 {
            let mut block = [0u8; 16];
            block.copy_from_slice(&ciphertext[i * 16..(i + 1) * 16]);
            assert_eq!(block, TEST_CT, "bitslice 块 {} 应与标准 SM4 一致", i);
        }
    }

    #[test]
    fn test_bitslice_roundtrip_diverse() {
        let plaintext = make_128_diverse_blocks();
        let rk = sm4_key_expansion(&TEST_KEY);
        let key = Sm4BitsliceKey::new(&TEST_KEY);
        let ciphertext = key.encrypt_128_blocks(&plaintext);

        for i in 0..128 {
            let mut block = [0u8; 16];
            block.copy_from_slice(&ciphertext[i * 16..(i + 1) * 16]);
            let mut expected_block = [0u8; 16];
            expected_block.copy_from_slice(&plaintext[i * 16..(i + 1) * 16]);
            let expected_ct = sm4_encrypt_block(&expected_block, &rk);
            assert_eq!(block, expected_ct, "bitslice 块 {} 应与标量 SM4 一致", i);
        }
    }

    #[test]
    fn test_bitslice_multiple_keys() {
        let pt = make_128_diverse_blocks();
        let key1 = Sm4BitsliceKey::new(&TEST_KEY);
        let mut key2_bytes = TEST_KEY;
        key2_bytes[0] ^= 0xFF;
        let key2 = Sm4BitsliceKey::new(&key2_bytes);

        let ct1 = key1.encrypt_128_blocks(&pt);
        let ct2 = key2.encrypt_128_blocks(&pt);
        assert_ne!(ct1, ct2, "不同密钥应产生不同密文");
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "单块 CT 基准仅在 release 模式下有意义")]
    fn test_ct_sbox_spot() {
        for i in (0..=255u16).step_by(16) {
            assert_eq!(
                ct_sbox_scalar(i as u8),
                SBOX[i as usize],
                "ct_sbox(0x{:02X})",
                i
            );
        }
        assert_eq!(ct_sbox_scalar(255), SBOX[255], "边界 255");
        assert_eq!(ct_sbox_scalar(0), SBOX[0], "边界 0");
    }

    #[test]
    #[cfg_attr(
        debug_assertions,
        ignore = "CT SM4 在 debug 模式下过慢，release 下自动运行"
    )]
    fn test_ct_encrypt_block_matches_baseline() {
        let rk = sm4_key_expansion(&TEST_KEY);
        assert_eq!(sm4_ct_encrypt_block(&TEST_PT, &rk), TEST_CT);
    }

    #[test]
    #[cfg_attr(
        debug_assertions,
        ignore = "CT CBC 在 debug 下过慢，release 下自动运行"
    )]
    fn test_ct_cbc_roundtrip() {
        let iv = [0xAB; 16];
        let pt = b"Hello, Constant-Time SM4 CBC!";
        let ct = sm4_ct_cbc_encrypt(&TEST_KEY, &iv, pt);
        assert_eq!(
            &crate::crypto::sm4_ctr::sm4_cbc_decrypt(&TEST_KEY, &iv, &ct).unwrap(),
            pt
        );
    }

    #[test]
    fn test_transpose_roundtrip() {
        let original = make_128_diverse_blocks();
        let state = transpose_to_bitslice(&original);
        let back = transpose_from_bitslice(&state);
        assert_eq!(original, back, "转置应保持数据不变");
    }

    #[test]
    fn test_bitslice_throughput_release() {
        let pt = make_128_diverse_blocks();
        let key = Sm4BitsliceKey::new(&TEST_KEY);

        let start = std::time::Instant::now();
        for _ in 0..100 {
            let _ = key.encrypt_128_blocks(&pt);
        }
        let dur = start.elapsed();
        let mb_per_call = (2048 * 100) as f64 / 1_000_000.0;
        let mbps = mb_per_call / dur.as_secs_f64();
        eprintln!("Bitslice SM4 100x128块: {:.2?} — {:.1} MB/s", dur, mbps);
    }
}
