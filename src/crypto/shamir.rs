//! Shamir 秘密共享 (Shamir's Secret Sharing) 在 GF(2⁸) 上的实现
//!
//! 使用不可约多项式 x⁸ + x⁴ + x³ + x + 1 (0x11B)，与 AES 的有限域相同。
//!
//! # 随机数安全说明
//!
//! 系数生成使用 `rand::rngs::OsRng`（CSPRNG），确保多项式中随机系数的不可预测性。
//!
//! # 原理
//!
//! 将秘密拆分为 `n` 份子秘密，任意 `t` 份可恢复原秘密（`(t, n)`-门限方案）。
//! 每个字节独立处理：构造 `t-1` 次多项式
//!
//! ```text
//! f(x) = a₀ + a₁x + a₂x² + … + aₜ₋₁xᵗ⁻¹
//! ```
//!
//! 其中 `a₀ = 秘密字节`，`a₁ … aₜ₋₁` 为随机系数。在 `x = 1, 2, …, n` 处求值得 `n` 份子秘密。
//! 恢复时用拉格朗日插值计算 `f(0) = a₀ = 秘密字节`。
//!
//! # 份额格式
//!
//! 每份子秘密为 `Vec<u8>`，结构如下：
//!
//! ```text
//! [index_byte, byte_0, byte_1, …, byte_{len-1}]
//! ```
//!
//! - `index_byte`: 份额索引，取值 1..=n
//! - 后续字节为秘密各字节对应的多项式求值结果
//!
//! # 示例
//!
//! ```ignore
//! use crypto::shamir::{split_secret, recover_secret};
//!
//! let secret = b"My secret data";
//! let shares = split_secret(secret, 5, 3);  // 5 份，3 份可恢复
//! let recovered = recover_secret(&shares[..3], 3);
//! assert_eq!(recovered, secret);
//! ```

use rand::RngCore;

// ============================================================
// GF(2⁸) 基本运算
// ============================================================

/// GF(2⁸) 上的加法（按位异或 XOR）。
///
/// 在特征 2 的有限域中，加法与减法等价，均为 XOR。
#[inline]
pub fn gf_add(a: u8, b: u8) -> u8 {
    a ^ b
}

/// GF(2⁸) 上的乘法（ peasant algorithm / Russian peasant multiplication ）。
///
/// 使用不可约多项式 `x⁸ + x⁴ + x³ + x + 1` (0x11B) 进行约简。
/// 逐位处理乘数，左移被乘数并条件 XOR 约简多项式。
pub fn gf_mul(a: u8, b: u8) -> u8 {
    let mut x = a;
    let mut y = b;
    let mut r = 0u8;
    for _ in 0..8 {
        // 若 y 最低位为 1，累加当前 x
        if y & 1 == 1 {
            r ^= x;
        }
        // 检查 x 的最高位，决定是否需要约简
        let carry = x & 0x80;
        x <<= 1;
        if carry != 0 {
            // x⁸ ≡ x⁴ + x³ + x + 1 (mod 0x11B)
            x ^= 0x1B;
        }
        y >>= 1;
    }
    r
}

/// GF(2⁸) 上的乘法逆元。
///
/// 利用费马小定理：在 GF(2⁸) 中，对任意非零元素 `a` 有 `a²⁵⁵ = 1`，
/// 因此 `a⁻¹ = a²⁵⁴`。使用平方-乘算法（exponentiation by squaring）计算。
///
/// 对零元素返回 0（非数学逆元，仅用于避免调用处额外分支）。
pub fn gf_inv(a: u8) -> u8 {
    if a == 0 {
        return 0;
    }
    // a²⁵⁴ = a¹¹¹¹¹¹¹⁰₂，平方-乘算法
    // 254 = 0b11111110，逐位处理
    let mut result = 1u8;
    let mut base = a;
    let mut exp = 254u8;
    while exp > 0 {
        if exp & 1 == 1 {
            result = gf_mul(result, base);
        }
        base = gf_mul(base, base);
        exp >>= 1;
    }
    result
}

// ============================================================
// 多项式求值
// ============================================================

/// 用 Horner 法计算多项式在 GF(2⁸) 上的值。
///
/// 对多项式 `f(x) = coeffs[0] + coeffs[1]·x + … + coeffs[d]·xᵈ`，
/// 按 Horner 规则展开为
///
/// ```text
/// f(x) = coeffs[0] + x·(coeffs[1] + x·(coeffs[2] + … + x·coeffs[d]))
/// ```
///
/// # Panics
///
/// 如果 `coeffs` 为空则 panic。
pub fn gf_poly_eval(coeffs: &[u8], x: u8) -> u8 {
    debug_assert!(!coeffs.is_empty(), "多项式系数不能为空");
    let mut result = coeffs[coeffs.len() - 1];
    for i in (0..coeffs.len() - 1).rev() {
        result = gf_mul(result, x);
        result = gf_add(result, coeffs[i]);
    }
    result
}

// ============================================================
// Shamir 秘密共享核心
// ============================================================

/// 将秘密拆分为 `n` 份子秘密，门限值为 `t`。
///
/// 每个秘密字节独立使用一个 `t-1` 次多项式处理。
///
/// # 参数
///
/// * `secret` - 待拆分的秘密字节切片
/// * `n`      - 生成的子秘密份数（1..=255）
/// * `t`      - 恢复秘密所需的最少份数（门限值，>= 2）
///
/// # 返回值
///
/// 包含 `n` 份子秘密的向量，每份格式为 `[index_byte, byte_0, …, byte_{len-1}]`，
/// 其中 `index_byte` 取值 1..=n。
///
/// # Panics
///
/// 如果 `t < 2`、`n < t`、`n > 255` 或 `secret` 为空则 panic。
pub fn split_secret(secret: &[u8], n: u8, t: u8) -> Vec<Vec<u8>> {
    assert!(t >= 2, "门限 t 必须 >= 2");
    assert!(n >= t, "分享数 n 必须 >= 门限 t");
    assert!(!secret.is_empty(), "秘密不能为空");

    let t_usize = t as usize;

    // 初始化 n 份子秘密，每份第一个字节为该份额的索引（1-based）
    let mut shares: Vec<Vec<u8>> = (1..=n).map(|i| vec![i]).collect();

    // 逐字节处理秘密
    for &secret_byte in secret {
        // 构造多项式系数：coeffs[0] = a₀ = 秘密字节（常数项）
        // coeffs[1..t] 为随机系数 a₁ … aₜ₋₁（使用 OsRng CSPRNG）
        let mut coeffs = Vec::with_capacity(t_usize);
        coeffs.push(secret_byte); // a₀
        for _ in 1..t_usize {
            let mut b = [0u8; 1];
            rand::rngs::OsRng.fill_bytes(&mut b);
            coeffs.push(b[0]);
        }

        // 在 x = 1, 2, …, n 处求多项式值，追加到对应子秘密
        for (i, share) in shares.iter_mut().enumerate() {
            let x = (i + 1) as u8;
            let val = gf_poly_eval(&coeffs, x);
            share.push(val);
        }
    }

    shares
}

/// 从 `t` 份子秘密中恢复原始秘密。
///
/// 使用拉格朗日插值法计算 `f(0)`，即多项式的常数项（原秘密字节）。
///
/// # 参数
///
/// * `shares` - 子秘密切片，每份格式为 `[index_byte, byte_0, …, byte_{len-1}]`
/// * `t`      - 门限值（与 `split_secret` 传入的值一致）
///
/// # 返回值
///
/// 恢复出的秘密字节向量。
///
/// # Panics
///
/// 如果 `shares.len() < t`、份额长度不一致或格式无效则 panic。
pub fn recover_secret(shares: &[Vec<u8>], t: u8) -> Vec<u8> {
    let t = t as usize;
    assert!(
        shares.len() >= t,
        "至少需要 {t} 份子秘密，当前仅有 {}",
        shares.len()
    );

    let chosen = &shares[..t];
    let share_len = chosen[0].len();
    assert!(share_len >= 1, "份额格式无效：缺少索引字节");

    // 检查所有份额长度一致
    for s in chosen.iter().skip(1) {
        assert_eq!(s.len(), share_len, "份额长度不一致");
    }

    // 提取份额索引
    let indices: Vec<u8> = chosen.iter().map(|s| s[0]).collect();
    let secret_len = share_len - 1;

    // 预计算拉格朗日系数 L_i(0) = Π_{j≠i} xⱼ / (xᵢ ⊕ xⱼ)
    // 由于拉格朗日系数与字节位置无关，只需计算一次
    let mut lagrange_coeffs = Vec::with_capacity(t);
    for i in 0..t {
        let mut numerator = 1u8; // Π xⱼ
        let mut denominator = 1u8; // Π (xᵢ ⊕ xⱼ)
        for j in 0..t {
            if i == j {
                continue;
            }
            numerator = gf_mul(numerator, indices[j]);
            denominator = gf_mul(denominator, indices[j] ^ indices[i]);
        }
        // L_i(0) = numerator · denominator⁻¹
        lagrange_coeffs.push(gf_mul(numerator, gf_inv(denominator)));
    }

    // 逐字节插值恢复秘密
    let mut secret = Vec::with_capacity(secret_len);
    for pos in 0..secret_len {
        let mut result = 0u8;
        for i in 0..t {
            let yi = chosen[i][pos + 1]; // 索引字节在 pos 0
            result ^= gf_mul(yi, lagrange_coeffs[i]); // gf_add = XOR
        }
        secret.push(result);
    }

    secret
}

// ============================================================
// 测试
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --------------------------------------------------------
    // GF(2⁸) 运算测试
    // --------------------------------------------------------

    #[test]
    fn test_gf_add_identity() {
        // a ⊕ 0 = a
        for a in 0..=255u8 {
            assert_eq!(gf_add(a, 0), a);
            assert_eq!(gf_add(0, a), a);
        }
    }

    #[test]
    fn test_gf_add_commutative() {
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                assert_eq!(gf_add(a, b), gf_add(b, a));
            }
        }
    }

    #[test]
    fn test_gf_add_self_inverse() {
        // a ⊕ a = 0
        for a in 0..=255u8 {
            assert_eq!(gf_add(a, a), 0);
        }
    }

    #[test]
    fn test_gf_mul_identity() {
        // a · 1 = a
        for a in 0..=255u8 {
            assert_eq!(gf_mul(a, 1), a, "a·1 = a 失败于 a = {a}");
            assert_eq!(gf_mul(1, a), a, "1·a = a 失败于 a = {a}");
        }
    }

    #[test]
    fn test_gf_mul_zero() {
        // a · 0 = 0
        for a in 0..=255u8 {
            assert_eq!(gf_mul(a, 0), 0, "a·0 = 0 失败于 a = {a}");
            assert_eq!(gf_mul(0, a), 0, "0·a = 0 失败于 a = {a}");
        }
    }

    #[test]
    fn test_gf_mul_commutative() {
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                assert_eq!(gf_mul(a, b), gf_mul(b, a), "乘法不交换: a={a}, b={b}");
            }
        }
    }

    #[test]
    fn test_gf_mul_associative() {
        for a in [0x02, 0x03, 0x57, 0x83, 0xC5] {
            for b in [0x0F, 0x42, 0x99, 0xAB, 0x11] {
                for c in [0x01, 0x10, 0x7E, 0xE4, 0xFF] {
                    assert_eq!(
                        gf_mul(gf_mul(a, b), c),
                        gf_mul(a, gf_mul(b, c)),
                        "乘法不结合: a={a:#x}, b={b:#x}, c={c:#x}"
                    );
                }
            }
        }
    }

    #[test]
    fn test_gf_mul_known_vectors() {
        // AES 测试向量
        assert_eq!(gf_mul(0x57, 0x13), 0xFE);
        assert_eq!(gf_mul(0x57, 0x83), 0xC1);
        assert_eq!(gf_mul(0x57, 0x01), 0x57);
        assert_eq!(gf_mul(0x57, 0x00), 0x00);
        // 分配律验证：a·(b⊕c) = a·b ⊕ a·c
        let a = 0x57;
        let b = 0x13;
        let c = 0x83;
        assert_eq!(gf_mul(a, gf_add(b, c)), gf_add(gf_mul(a, b), gf_mul(a, c)));
    }

    #[test]
    fn test_gf_inv_zero() {
        assert_eq!(gf_inv(0), 0);
    }

    #[test]
    fn test_gf_inv_property() {
        // a · a⁻¹ = 1 （对所有非零元素）
        for a in 1..=255u8 {
            let inv = gf_inv(a);
            assert_eq!(gf_mul(a, inv), 1, "a·a⁻¹ = 1 失败于 a = {a}");
            assert_eq!(gf_mul(inv, a), 1, "a⁻¹·a = 1 失败于 a = {a}");
        }
    }

    #[test]
    fn test_gf_inv_unique() {
        // 确认逆元是唯一的
        let mut seen = std::collections::HashSet::new();
        for a in 1..=255u8 {
            let inv = gf_inv(a);
            assert!(seen.insert(inv), "逆元不唯一：{a} → {inv} 已被映射");
        }
    }

    #[test]
    fn test_gf_poly_eval_constant() {
        // 常数多项式：f(x) = 42
        let coeffs = [42u8];
        for x in 0..=255u8 {
            assert_eq!(gf_poly_eval(&coeffs, x), 42);
        }
    }

    #[test]
    fn test_gf_poly_eval_linear() {
        // 一次多项式：f(x) = 3 + 5x
        let coeffs = [3u8, 5];
        // f(0) = 3
        assert_eq!(gf_poly_eval(&coeffs, 0), 3);
        // f(1) = 3 ⊕ 5 = 6
        assert_eq!(gf_poly_eval(&coeffs, 1), 3 ^ 5);
        // f(2) = 3 ⊕ gf_mul(5, 2)
        assert_eq!(gf_poly_eval(&coeffs, 2), 3 ^ gf_mul(5, 2));
    }

    // --------------------------------------------------------
    // Shamir 秘密共享测试
    // --------------------------------------------------------

    #[test]
    fn test_split_recover_roundtrip() {
        let secret = b"Hello, Shamir! This is a top-secret message.";
        let n = 5;
        let t = 3;
        let shares = split_secret(secret, n, t);
        assert_eq!(shares.len(), n as usize);

        // 每个份额格式正确：[索引, secret_bytes...]
        for (idx, share) in shares.iter().enumerate() {
            assert_eq!(share[0], (idx + 1) as u8, "份额索引应递增");
            assert_eq!(share.len(), 1 + secret.len());
        }

        // 用前 t 份恢复
        let recovered = recover_secret(&shares[..t as usize], t);
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_recover_from_any_subset() {
        let secret = b"Any 3 of 5";
        let shares = split_secret(secret, 5, 3);

        // 后 3 份
        let recovered = recover_secret(&shares[2..], 3);
        assert_eq!(recovered, secret);

        // 混合选择 [0, 2, 4]
        let mixed = vec![shares[0].clone(), shares[2].clone(), shares[4].clone()];
        let recovered = recover_secret(&mixed, 3);
        assert_eq!(recovered, secret);

        // 混合选择 [1, 3, 4]
        let mixed2 = vec![shares[1].clone(), shares[3].clone(), shares[4].clone()];
        let recovered = recover_secret(&mixed2, 3);
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_max_shares() {
        // n = 255 的边界情况（小秘密以减少运行时间）
        let secret = b"edge";
        let shares = split_secret(secret, 255, 3);
        assert_eq!(shares.len(), 255);

        // 用任意 t 份恢复
        let recovered = recover_secret(&shares[..3], 3);
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_t_equals_n() {
        // t = n 时，需要所有份额才能恢复
        let secret = b"All shares needed";
        let shares = split_secret(secret, 5, 5);
        assert_eq!(shares.len(), 5);

        let recovered = recover_secret(&shares, 5);
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_t_equals_2() {
        // 最小有效门限 t = 2
        let secret = b"Min threshold";
        let shares = split_secret(secret, 5, 2);
        assert_eq!(shares.len(), 5);

        let recovered = recover_secret(&shares[..2], 2);
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_single_byte_secret() {
        let secret = [0xABu8];
        let shares = split_secret(&secret, 3, 2);
        assert_eq!(shares.len(), 3);
        // 每份格式：[index, byte]
        assert_eq!(shares[0].len(), 2);
        assert_eq!(shares[0][0], 1);

        let recovered = recover_secret(&shares[..2], 2);
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_all_zero_secret() {
        let secret = [0u8; 32];
        let shares = split_secret(&secret, 10, 4);
        let recovered = recover_secret(&shares[..4], 4);
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_all_ff_secret() {
        let secret = [0xFFu8; 16];
        let shares = split_secret(&secret, 7, 3);
        let recovered = recover_secret(&shares[..3], 3);
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_multiple_t_values() {
        let secret = b"Test various thresholds";
        for t in 2..=6 {
            let n = t + 2;
            let shares = split_secret(secret, n, t);
            let recovered = recover_secret(&shares[..t as usize], t);
            assert_eq!(recovered, secret, "t = {t} 时恢复失败");
        }
    }

    #[test]
    fn test_different_secret_lengths() {
        for len in [1, 2, 3, 7, 8, 16, 32, 64, 128, 256] {
            let secret: Vec<u8> = (0..len).map(|i| (i ^ 0xAB) as u8).collect();
            let shares = split_secret(&secret, 5, 3);
            let recovered = recover_secret(&shares[..3], 3);
            assert_eq!(recovered, secret, "秘密长度 {len} 时恢复失败");
        }
    }

    // --------------------------------------------------------
    // 正确性：GF(2⁸) 运算与 Shamir 联合验证
    // --------------------------------------------------------

    #[test]
    fn test_polynomial_interpolation_consistency() {
        // 构造一个已知多项式，取点后用插值恢复常数项
        let coeffs = [0x42u8, 0x57, 0x83]; // f(x) = 0x42 + 0x57·x + 0x83·x²
        let points: Vec<(u8, u8)> = (1..=5).map(|x| (x, gf_poly_eval(&coeffs, x))).collect();

        // 用前 3 个点做拉格朗日插值恢复 f(0)
        let t = 3;
        let indices: Vec<u8> = points[..t].iter().map(|p| p.0).collect();
        let values: Vec<u8> = points[..t].iter().map(|p| p.1).collect();

        let mut result = 0u8;
        for i in 0..t {
            let mut num = 1u8;
            let mut den = 1u8;
            for j in 0..t {
                if i == j {
                    continue;
                }
                num = gf_mul(num, indices[j]);
                den = gf_mul(den, indices[j] ^ indices[i]);
            }
            let li0 = gf_mul(num, gf_inv(den));
            result ^= gf_mul(values[i], li0);
        }
        assert_eq!(result, coeffs[0], "拉格朗日插值未正确恢复常数项");
    }
}
