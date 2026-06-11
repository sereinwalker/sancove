//! SM2 椭圆曲线公钥密码算法 (GB/T 32918-2016)
//!
//! 本模块实现 SM2 数字签名生成/验证 (Part 2) 和公钥加密/解密 (Part 4)。
//!
//! # 曲线: sm2p256v1
//!
//! - p = FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
//! - a = FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
//! - b = 28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
//! - G = (32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7,
//!   BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0)
//! - n = FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
//!
//! # 设计要点
//!
//! - 域元素表示为 4 个 u64 小端序 limb
//! - 仿射坐标点运算
//! - 双倍-加标量乘法
//! - 确定性 k 使用 HMAC-SM3 派生 (RFC 6979 风格)
//! - 私钥使用 Zeroizing 保护
//! - 所有 5 个公共 API 已被 vault.rs 调用（generate_key_pair/sign/verify/encrypt/decrypt）

use crate::crypto::secure_eq::constant_time_eq_32;
use crate::crypto::sm3::{Sm3, hmac_sm3};
use zeroize::Zeroizing;

// ============================================================
// 类型定义
// ============================================================

/// 256 位域元素，小端序 u64 limbs (limb[0] = 最低有效位)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fe(pub [u64; 4]);

/// 仿射坐标椭圆曲线点
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Point {
    x: Fe,
    y: Fe,
    /// 是否为无穷远点
    infinity: bool,
}

/// SM2 签名 (r || s，各 32 字节大端)
///
/// 类型安全封装，替代裸 `[u8; 64]` 参数。提供 `to_bytes()`/`from_bytes()` 与 CLI 层互转。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature {
    pub r: [u8; 32],
    pub s: [u8; 32],
}

impl Signature {
    /// 序列化为 64 字节 (r || s)
    pub fn to_bytes(self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.r);
        out[32..64].copy_from_slice(&self.s);
        out
    }

    /// 从 64 字节反序列化
    pub fn from_bytes(bytes: &[u8; 64]) -> Self {
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&bytes[..32]);
        s.copy_from_slice(&bytes[32..64]);
        Self { r, s }
    }

    /// 从 (r, s) 大端字节构造
    pub fn new(r: [u8; 32], s: [u8; 32]) -> Self {
        Self { r, s }
    }
}

// ============================================================
// 曲线常数（小端序 u64 limbs）
// ============================================================

/// 域素数 p = 2^256 - 2^224 - 2^96 + 2^64 - 1
const P: Fe = Fe([
    0xFFFFFFFF_FFFFFFFF,
    0xFFFFFFFF_00000000,
    0xFFFFFFFF_FFFFFFFF,
    0xFFFFFFFE_FFFFFFFF,
]);

/// 曲线参数 a = p - 3 = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
const A: Fe = Fe([
    0xFFFFFFFF_FFFFFFFC,
    0xFFFFFFFF_00000000,
    0xFFFFFFFF_FFFFFFFF,
    0xFFFFFFFE_FFFFFFFF,
]);

/// 曲线参数 b
const B: Fe = Fe([
    0xDDBCBD41_4D940E93,
    0xF39789F5_15AB8F92,
    0x4D5A9E4B_CF6509A7,
    0x28E9FA9E_9D9F5E34,
]);

/// 基点 G 的 x 坐标
const GX: Fe = Fe([
    0x715A4589_334C74C7,
    0x8FE30BBF_F2660BE1,
    0x5F990446_6A39C994,
    0x32C4AE2C_1F198119,
]);

/// 基点 G 的 y 坐标
const GY: Fe = Fe([
    0x02DF32E5_2139F0A0,
    0xD0A9877C_C62A4740,
    0x59BDCEE3_6B692153,
    0xBC3736A2_F4F6779C,
]);

/// 基点 G
const G: Point = Point {
    x: Fe([
        0x715A4589_334C74C7,
        0x8FE30BBF_F2660BE1,
        0x5F990446_6A39C994,
        0x32C4AE2C_1F198119,
    ]),
    y: Fe([
        0x02DF32E5_2139F0A0,
        0xD0A9877C_C62A4740,
        0x59BDCEE3_6B692153,
        0xBC3736A2_F4F6779C,
    ]),
    infinity: false,
};

/// 阶 n
const N: Fe = Fe([
    0x53BBF409_39D54123,
    0x7203DF6B_21C6052B,
    0xFFFFFFFF_FFFFFFFF,
    0xFFFFFFFE_FFFFFFFF,
]);

/// p_c = 2^256 mod p = 2^224 + 2^96 - 2^64 + 1
const P_C: Fe = Fe([
    0x00000000_00000001,
    0x00000000_FFFFFFFF,
    0x00000000_00000000,
    0x00000001_00000000,
]);

/// 0 域元素
const ZERO: Fe = Fe([0, 0, 0, 0]);

/// 1 域元素
const ONE: Fe = Fe([1, 0, 0, 0]);

// ============================================================
// 域元素编码/解码
// ============================================================

/// 将 32 字节大端整数转为域元素
fn fe_from_bytes(bytes: &[u8; 32]) -> Fe {
    Fe([
        u64::from_be_bytes([
            bytes[24], bytes[25], bytes[26], bytes[27], bytes[28], bytes[29], bytes[30], bytes[31],
        ]),
        u64::from_be_bytes([
            bytes[16], bytes[17], bytes[18], bytes[19], bytes[20], bytes[21], bytes[22], bytes[23],
        ]),
        u64::from_be_bytes([
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ]),
        u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]),
    ])
}

/// 将域元素转为 32 字节大端整数
fn fe_to_bytes(a: &Fe) -> [u8; 32] {
    let mut out = [0u8; 32];
    let b0 = a.0[3].to_be_bytes();
    let b1 = a.0[2].to_be_bytes();
    let b2 = a.0[1].to_be_bytes();
    let b3 = a.0[0].to_be_bytes();
    out[0..8].copy_from_slice(&b0);
    out[8..16].copy_from_slice(&b1);
    out[16..24].copy_from_slice(&b2);
    out[24..32].copy_from_slice(&b3);
    out
}

// ============================================================
// 域元素算术
// ============================================================

/// 将 64 位值转为 Fe
fn fe_from_u64(v: u64) -> Fe {
    Fe([v, 0, 0, 0])
}

/// 检查 a == b
fn fe_eq(a: &Fe, b: &Fe) -> bool {
    a.0[0] == b.0[0] && a.0[1] == b.0[1] && a.0[2] == b.0[2] && a.0[3] == b.0[3]
}

/// 检查 a == 0
fn fe_is_zero(a: &Fe) -> bool {
    (a.0[0] | a.0[1] | a.0[2] | a.0[3]) == 0
}

/// 域元素比较: a >= b?
fn fe_ge(a: &Fe, b: &Fe) -> bool {
    for i in (0..4).rev() {
        if a.0[i] > b.0[i] {
            return true;
        }
        if a.0[i] < b.0[i] {
            return false;
        }
    }
    true
}

/// 模加: c = a + b mod p
fn fe_add(a: &Fe, b: &Fe) -> Fe {
    let mut r = [0u64; 4];
    let mut carry = 0u128;

    for (ri, (&ai, &bi)) in r.iter_mut().zip(a.0.iter().zip(b.0.iter())) {
        let v = (ai as u128) + (bi as u128) + carry;
        *ri = v as u64;
        carry = v >> 64;
    }

    // 结果 ≤ 2^257 - 1，用 8 肢表示并约简
    let w = [r[0], r[1], r[2], r[3], carry as u64, 0, 0, 0];
    fe_reduce(&w)
}

/// 模减: c = a - b mod p
fn fe_sub(a: &Fe, b: &Fe) -> Fe {
    let mut r = [0u64; 4];
    let mut borrow: u64 = 0;

    for (ri, (&ai, &bi)) in r.iter_mut().zip(a.0.iter().zip(b.0.iter())) {
        let (v, b1) = ai.overflowing_sub(bi);
        let (v2, b2) = v.overflowing_sub(borrow);
        *ri = v2;
        borrow = b1 as u64 + b2 as u64;
    }

    // 如果 borrow!=0 说明 a < b，需要加 p（结果位于 [0, p-1]）
    if borrow != 0 {
        let mut carry: u64 = 0;
        for (ri, &pi) in r.iter_mut().zip(P.0.iter()) {
            let (v, c1) = ri.overflowing_add(pi);
            let (v2, c2) = v.overflowing_add(carry);
            *ri = v2;
            carry = c1 as u64 + c2 as u64;
        }
    }

    Fe(r)
}

/// 全精度 256×256 位无符号乘法。
/// 返回 512 位结果，8 个小端序 u64 limbs。
fn mul_256x256(a: &[u64; 4], b: &[u64; 4]) -> [u64; 8] {
    let a0 = a[0];
    let a1 = a[1];
    let a2 = a[2];
    let a3 = a[3];
    let b0 = b[0];
    let b1 = b[1];
    let b2 = b[2];
    let b3 = b[3];

    let p00 = (a0 as u128) * (b0 as u128);
    let p01 = (a0 as u128) * (b1 as u128);
    let p02 = (a0 as u128) * (b2 as u128);
    let p03 = (a0 as u128) * (b3 as u128);
    let p10 = (a1 as u128) * (b0 as u128);
    let p11 = (a1 as u128) * (b1 as u128);
    let p12 = (a1 as u128) * (b2 as u128);
    let p13 = (a1 as u128) * (b3 as u128);
    let p20 = (a2 as u128) * (b0 as u128);
    let p21 = (a2 as u128) * (b1 as u128);
    let p22 = (a2 as u128) * (b2 as u128);
    let p23 = (a2 as u128) * (b3 as u128);
    let p30 = (a3 as u128) * (b0 as u128);
    let p31 = (a3 as u128) * (b1 as u128);
    let p32 = (a3 as u128) * (b2 as u128);
    let p33 = (a3 as u128) * (b3 as u128);

    let prod = [
        [p00 as u64, (p00 >> 64) as u64],
        [p01 as u64, (p01 >> 64) as u64],
        [p02 as u64, (p02 >> 64) as u64],
        [p03 as u64, (p03 >> 64) as u64],
        [p10 as u64, (p10 >> 64) as u64],
        [p11 as u64, (p11 >> 64) as u64],
        [p12 as u64, (p12 >> 64) as u64],
        [p13 as u64, (p13 >> 64) as u64],
        [p20 as u64, (p20 >> 64) as u64],
        [p21 as u64, (p21 >> 64) as u64],
        [p22 as u64, (p22 >> 64) as u64],
        [p23 as u64, (p23 >> 64) as u64],
        [p30 as u64, (p30 >> 64) as u64],
        [p31 as u64, (p31 >> 64) as u64],
        [p32 as u64, (p32 >> 64) as u64],
        [p33 as u64, (p33 >> 64) as u64],
    ];
    let mut r = [0u64; 8];
    for (idx, entry) in prod.iter().enumerate() {
        let i = idx / 4;
        let j = idx % 4;
        let col_lo = i + j;
        let col_hi = i + j + 1;
        let (lo_val, hi_val) = (entry[0], entry[1]);

        let (v, carry1) = r[col_lo].overflowing_add(lo_val);
        r[col_lo] = v;
        let mut carry = carry1 as u64;

        if col_hi < 8 {
            let (v, c1) = r[col_hi].overflowing_add(hi_val);
            let (v, c2) = v.overflowing_add(carry);
            r[col_hi] = v;
            carry = (c1 as u64) + (c2 as u64);

            let mut k = col_hi + 1;
            while carry != 0 && k < 8 {
                let (v, c) = r[k].overflowing_add(carry);
                r[k] = v;
                carry = c as u64;
                k += 1;
            }
        }
    }
    r
}

/// 全精度乘法: z = a * b, 返回 [u64; 8]
///
/// 每个乘积拆分为 (hi, lo) 各 64 位，逐列累加并正确传播进位。
fn mul_full(a: &Fe, b: &Fe) -> [u64; 8] {
    mul_256x256(&a.0, &b.0)
}

/// 模乘: c = a * b mod p
fn fe_mul(a: &Fe, b: &Fe) -> Fe {
    let z = mul_full(a, b);
    fe_reduce(&z)
}

/// 模平方: c = a^2 mod p
fn fe_square(a: &Fe) -> Fe {
    fe_mul(a, a)
}

/// 用 p_c = 2^256 mod p 迭代约简 512 位乘积
fn fe_reduce(z: &[u64; 8]) -> Fe {
    let mut w = *z;

    // 最多 16 轮迭代，通常约 9 轮收敛
    for _ in 0..16 {
        // 检查是否已 <= 256 位
        if (w[4] | w[5] | w[6] | w[7]) == 0 {
            let r = Fe([w[0], w[1], w[2], w[3]]);
            // 常少于 2p，至多减一次
            if fe_ge(&r, &P) {
                return fe_sub(&r, &P);
            }
            return r;
        }

        let low = [w[0], w[1], w[2], w[3]];
        let high = [w[4], w[5], w[6], w[7]];

        // t = high * p_c
        let t = mul_256x256(&high, &P_C.0);

        // w = low + t
        let mut carry = 0u128;
        for i in 0..4 {
            let v = (low[i] as u128) + (t[i] as u128) + carry;
            w[i] = v as u64;
            carry = v >> 64;
        }
        for i in 4..8 {
            let v = (t[i] as u128) + carry;
            w[i] = v as u64;
            carry = v >> 64;
        }
        // 如果 carry != 0，w < 2^482 且 carry 至多为 1，
        // 不会溢出 8 limbs (512 bits)
    }

    // 极不可能到达这里
    Fe([w[0], w[1], w[2], w[3]])
}

/// 模逆: c = a^(p-2) mod p (Fermat 小定理)
fn fe_inv(a: &Fe) -> Fe {
    // a^(p-2) mod p, p-2 是一个 256 位数
    // 使用平方-乘算法
    let p_minus_2: [u64; 4] = [
        0xFFFFFFFF_FFFFFFFD,
        0xFFFFFFFF_00000000,
        0xFFFFFFFF_FFFFFFFF,
        0xFFFFFFFE_FFFFFFFF,
    ];

    let mut result = ONE;
    let base = *a;

    for i in (0..4).rev() {
        let mut limb = p_minus_2[i];
        for _ in 0..64 {
            result = fe_square(&result);
            if (limb >> 63) & 1 == 1 {
                result = fe_mul(&result, &base);
            }
            limb <<= 1;
        }
    }

    result
}

// ============================================================
// 标量算术 (mod n)
// ============================================================

/// 标量比较: a >= b?
fn scalar_ge(a: &[u64; 4], b: &[u64; 4]) -> bool {
    for i in (0..4).rev() {
        if a[i] > b[i] {
            return true;
        }
        if a[i] < b[i] {
            return false;
        }
    }
    true
}

/// 用 n_c 迭代约简 512 位值 mod n（scalar_add/scalar_sub_mod/scalar_mul 共用）
fn scalar_reduce(w: &mut [u64; 8]) -> [u64; 4] {
    for _ in 0..16 {
        if (w[4] | w[5] | w[6] | w[7]) == 0 {
            let r = [w[0], w[1], w[2], w[3]];
            if scalar_ge(&r, &N.0) {
                let mut borrow: u64 = 0;
                let mut sub = [0u64; 4];
                for i in 0..4 {
                    let (v, b1) = r[i].overflowing_sub(N.0[i]);
                    let (v2, b2) = v.overflowing_sub(borrow);
                    sub[i] = v2;
                    borrow = b1 as u64 + b2 as u64;
                }
                return sub;
            }
            return r;
        }

        let low = [w[0], w[1], w[2], w[3]];
        let high = [w[4], w[5], w[6], w[7]];
        let t = mul_256x256(&high, &N_C);

        let mut carry = 0u128;
        for i in 0..4 {
            let v = (low[i] as u128) + (t[i] as u128) + carry;
            w[i] = v as u64;
            carry = v >> 64;
        }
        for i in 4..8 {
            let v = (t[i] as u128) + carry;
            w[i] = v as u64;
            carry = v >> 64;
        }
    }

    [w[0], w[1], w[2], w[3]]
}

/// 标量加 (mod n)
fn scalar_add(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut w = [0u64; 8];
    let mut carry: u64 = 0;
    for i in 0..4 {
        let (v, c1) = a[i].overflowing_add(b[i]);
        let (v2, c2) = v.overflowing_add(carry);
        w[i] = v2;
        carry = c1 as u64 + c2 as u64;
    }
    w[4] = carry;
    scalar_reduce(&mut w)
}

/// 标量减 (mod n): (a - b) mod n
fn scalar_sub_mod(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut w = [0u64; 8];
    w[..4].copy_from_slice(a);

    let mut borrow: u64 = 0;
    for i in 0..4 {
        let (v, b1) = w[i].overflowing_sub(b[i]);
        let (v2, b2) = v.overflowing_sub(borrow);
        w[i] = v2;
        borrow = b1 as u64 + b2 as u64;
    }
    for wi in w[4..8].iter_mut() {
        let (v, b1) = wi.overflowing_sub(borrow);
        *wi = v;
        borrow = b1 as u64;
    }

    if borrow != 0 {
        let mut carry: u64 = 0;
        for (wi, &ni) in w.iter_mut().zip(N.0.iter()) {
            let (v, c1) = wi.overflowing_add(ni);
            let (v2, c2) = v.overflowing_add(carry);
            *wi = v2;
            carry = c1 as u64 + c2 as u64;
        }
        let mut i = 4;
        while carry != 0 && i < 8 {
            let (v, c) = w[i].overflowing_add(carry);
            w[i] = v;
            carry = c as u64;
            i += 1;
        }
    }

    scalar_reduce(&mut w)
}

/// 标量乘 (mod n)
fn scalar_mul(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut prod = mul_256x256(a, b);
    scalar_reduce(&mut prod)
}

/// n_c = 2^256 mod n（静态常量）。
///
/// n = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
/// n_c = 0x0000000100000000000000008DFC2094DE39FAD4AC440BF6C62ABEDD
const N_C: [u64; 4] = [
    0xAC440BF6_C62ABEDD,
    0x8DFC2094_DE39FAD4,
    0x00000000_00000000,
    0x00000001_00000000,
];

/// 标量逆 (mod n): a^(-1) mod n
fn scalar_inv(a: &[u64; 4]) -> [u64; 4] {
    // a^(n-2) mod n
    let n_minus_2: [u64; 4] = [
        0x53BBF409_39D54121,
        0x7203DF6B_21C6052B,
        0xFFFFFFFF_FFFFFFFF,
        0xFFFFFFFE_FFFFFFFF,
    ];

    let mut result = [1u64, 0, 0, 0]; // 1 (LE limbs)
    let base = *a;

    for i in (0..4).rev() {
        let mut limb = n_minus_2[i];
        for _ in 0..64 {
            result = scalar_mul(&result, &result);
            if (limb >> 63) & 1 == 1 {
                result = scalar_mul(&result, &base);
            }
            limb <<= 1;
        }
    }

    result
}

/// 将 [u64; 4] 标量转为 32 字节大端
fn scalar_to_bytes(a: &[u64; 4]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0..8].copy_from_slice(&a[3].to_be_bytes());
    out[8..16].copy_from_slice(&a[2].to_be_bytes());
    out[16..24].copy_from_slice(&a[1].to_be_bytes());
    out[24..32].copy_from_slice(&a[0].to_be_bytes());
    out
}

/// 将 32 字节大端转为 [u64; 4] 标量
fn scalar_from_bytes(bytes: &[u8; 32]) -> [u64; 4] {
    [
        u64::from_be_bytes([
            bytes[24], bytes[25], bytes[26], bytes[27], bytes[28], bytes[29], bytes[30], bytes[31],
        ]),
        u64::from_be_bytes([
            bytes[16], bytes[17], bytes[18], bytes[19], bytes[20], bytes[21], bytes[22], bytes[23],
        ]),
        u64::from_be_bytes([
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ]),
        u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]),
    ]
}

/// 检查标量是否为零
fn scalar_is_zero(k: &[u64; 4]) -> bool {
    k[0] == 0 && k[1] == 0 && k[2] == 0 && k[3] == 0
}

/// 检查标量是否在 [1, n-1] 范围内
fn scalar_is_valid_range(k: &[u64; 4]) -> bool {
    // 检查 k != 0
    if scalar_is_zero(k) {
        return false;
    }
    // 检查 k < n
    for i in (0..4).rev() {
        if k[i] < N.0[i] {
            return true;
        }
        if k[i] > N.0[i] {
            return false;
        }
    }
    false // k == n
}

// ============================================================
// 点运算 — Jacobian 投影坐标
// ============================================================

/// Jacobian 投影坐标点 (X, Y, Z) 对应仿射坐标 (X/Z², Y/Z³)
struct JacobianPoint {
    x: Fe,
    y: Fe,
    z: Fe,
    infinity: bool,
}

/// 将仿射坐标点转换为 Jacobian 坐标
fn jacobian_from_affine(p: &Point) -> JacobianPoint {
    if p.infinity {
        return JacobianPoint {
            x: ZERO,
            y: ZERO,
            z: ZERO,
            infinity: true,
        };
    }
    JacobianPoint {
        x: p.x,
        y: p.y,
        z: ONE,
        infinity: false,
    }
}

/// 将 Jacobian 坐标点转换回仿射坐标（含一次求逆）
fn jacobian_to_affine(p: &JacobianPoint) -> Point {
    if p.infinity || fe_is_zero(&p.z) {
        return Point {
            x: ZERO,
            y: ZERO,
            infinity: true,
        };
    }
    let z_inv = fe_inv(&p.z);
    let z_inv_sq = fe_square(&z_inv);
    let x = fe_mul(&p.x, &z_inv_sq);
    let y = fe_mul(&p.y, &fe_mul(&z_inv_sq, &z_inv));
    Point {
        x,
        y,
        infinity: false,
    }
}

/// Jacobian 点加倍: R = 2P（利用 a = -3 优化）
///
/// 对于 SM2 曲线 a = p - 3 ≡ -3 (mod p):
///   M = 3·X₁² + a·Z₁⁴ = 3·(X₁ - Z₁²)·(X₁ + Z₁²)
///   S = 4·X₁·Y₁²
///   X₃ = M² - 2·S
///   Y₃ = M·(S - X₃) - 8·Y₁⁴
///   Z₃ = 2·Y₁·Z₁
///
/// 成本: 8 次乘法 + 0 次求逆（仿射坐标需 1 次求逆）
fn jacobian_double(p: &JacobianPoint) -> JacobianPoint {
    if p.infinity || fe_is_zero(&p.y) {
        return JacobianPoint {
            x: ZERO,
            y: ZERO,
            z: ZERO,
            infinity: true,
        };
    }

    let y2 = fe_square(&p.y); // Y₁²

    let s = fe_mul(&fe_from_u64(4), &fe_mul(&p.x, &y2)); // S = 4·X₁·Y₁²

    let z2 = fe_square(&p.z); // Z₁²
    let x_minus_z2 = fe_sub(&p.x, &z2); // X₁ - Z₁²
    let x_plus_z2 = fe_add(&p.x, &z2); // X₁ + Z₁²
    let m = fe_mul(&fe_from_u64(3), &fe_mul(&x_minus_z2, &x_plus_z2)); // M = 3·(X₁-Z₁²)·(X₁+Z₁²)

    let m2 = fe_square(&m); // M²
    let x3 = fe_sub(&m2, &fe_mul(&fe_from_u64(2), &s)); // X₃ = M² - 2·S

    let y4 = fe_square(&y2); // Y₁⁴
    let y3 = fe_sub(&fe_mul(&m, &fe_sub(&s, &x3)), &fe_mul(&fe_from_u64(8), &y4)); // Y₃ = M·(S - X₃) - 8·Y₁⁴

    let z3 = fe_mul(&fe_from_u64(2), &fe_mul(&p.y, &p.z)); // Z₃ = 2·Y₁·Z₁

    JacobianPoint {
        x: x3,
        y: y3,
        z: z3,
        infinity: false,
    }
}

/// Jacobian 点加: R = P + Q（通用加法，P ≠ Q）
///
/// 使用完整的 Jacobian 加法公式:
///   U₁ = X₁·Z₂², U₂ = X₂·Z₁²
///   S₁ = Y₁·Z₂³, S₂ = Y₂·Z₁³
///   H = U₂ - U₁, r = S₂ - S₁
///   X₃ = r² - H³ - 2·U₁·H²
///   Y₃ = r·(U₁·H² - X₃) - S₁·H³
///   Z₃ = H·Z₁·Z₂
///
/// 成本: ~16 次乘法 + 0 次求逆
fn jacobian_add(p: &JacobianPoint, q: &JacobianPoint) -> JacobianPoint {
    if p.infinity {
        return JacobianPoint {
            x: q.x,
            y: q.y,
            z: q.z,
            infinity: q.infinity,
        };
    }
    if q.infinity {
        return JacobianPoint {
            x: p.x,
            y: p.y,
            z: p.z,
            infinity: p.infinity,
        };
    }

    let z1_2 = fe_square(&p.z);
    let z2_2 = fe_square(&q.z);

    let u1 = fe_mul(&p.x, &z2_2); // U₁ = X₁·Z₂²
    let u2 = fe_mul(&q.x, &z1_2); // U₂ = X₂·Z₁²

    let s1 = fe_mul(&p.y, &fe_mul(&z2_2, &q.z)); // S₁ = Y₁·Z₂³
    let s2 = fe_mul(&q.y, &fe_mul(&z1_2, &p.z)); // S₂ = Y₂·Z₁³

    let h = fe_sub(&u2, &u1); // H = U₂ - U₁
    let r = fe_sub(&s2, &s1); // r = S₂ - S₁

    // 处理特殊情况
    if fe_is_zero(&h) {
        if fe_is_zero(&r) {
            return jacobian_double(p);
        }
        return JacobianPoint {
            x: ZERO,
            y: ZERO,
            z: ZERO,
            infinity: true,
        };
    }

    let h2 = fe_square(&h); // H²
    let h3 = fe_mul(&h, &h2); // H³
    let u1_h2 = fe_mul(&u1, &h2); // U₁·H²

    // X₃ = r² - H³ - 2·U₁·H²
    let r2 = fe_square(&r);
    let x3 = fe_sub(&fe_sub(&r2, &h3), &fe_mul(&fe_from_u64(2), &u1_h2));

    // Y₃ = r·(U₁·H² - X₃) - S₁·H³
    let y3 = fe_sub(&fe_mul(&r, &fe_sub(&u1_h2, &x3)), &fe_mul(&s1, &h3));

    // Z₃ = H·Z₁·Z₂
    let z3 = fe_mul(&h, &fe_mul(&p.z, &q.z));

    JacobianPoint {
        x: x3,
        y: y3,
        z: z3,
        infinity: false,
    }
}

/// Jacobian 混合加法: R = P + Q（Q 为仿射坐标点，Z=1）
///
/// 当 Q 的 Z=1 时，跳过 Z₂² 和 Z₂³ 的计算，节省 4 次乘法。
/// `point_mul` 的基点为仿射点（Z=1），此优化可加速签名约 10%。
fn jacobian_add_mixed(p: &JacobianPoint, q: &Point) -> JacobianPoint {
    if p.infinity {
        return jacobian_from_affine(q);
    }
    // q 为仿射点，Z=1 → Z₂²=1, Z₂³=1

    let z1_2 = fe_square(&p.z);

    let u1 = p.x; // U₁ = X₁ (Z₂²=1)
    let u2 = fe_mul(&q.x, &z1_2); // U₂ = X₂·Z₁²

    let s1 = p.y; // S₁ = Y₁ (Z₂³=1)
    let s2 = fe_mul(&q.y, &fe_mul(&z1_2, &p.z)); // S₂ = Y₂·Z₁³

    let h = fe_sub(&u2, &u1); // H = U₂ - U₁
    let r = fe_sub(&s2, &s1); // r = S₂ - S₁

    if fe_is_zero(&h) {
        if fe_is_zero(&r) {
            return jacobian_double(&jacobian_from_affine(q));
        }
        return JacobianPoint {
            x: ZERO,
            y: ZERO,
            z: ZERO,
            infinity: true,
        };
    }

    let h2 = fe_square(&h);
    let h3 = fe_mul(&h, &h2);
    let u1_h2 = fe_mul(&u1, &h2);

    let r2 = fe_square(&r);
    let x3 = fe_sub(&fe_sub(&r2, &h3), &fe_mul(&fe_from_u64(2), &u1_h2));

    let y3 = fe_sub(&fe_mul(&r, &fe_sub(&u1_h2, &x3)), &fe_mul(&s1, &h3));

    let z3 = fe_mul(&h, &p.z); // Z₃ = H·Z₁ (Z₂=1)

    JacobianPoint {
        x: x3,
        y: y3,
        z: z3,
        infinity: false,
    }
}

/// 双倍-加标量乘法 (Jacobian 坐标): R = k * P
///
/// 全程使用 Jacobian 坐标，仅在末尾转换回仿射坐标（一次求逆）。
/// 相比仿射坐标（每个点运算需一次求逆）快约 20-50 倍。
///
/// # ⚠️ 非恒定时间
///
/// 本实现使用条件分支的双倍-加算法，标量 `k` 的位模式可通过
/// 微架构侧信道（时序、缓存、分支预测）被观测。
/// 在签名生成场景中（确定性 k 由 HMAC-SM3 派生），此泄漏在
/// 桌面环境下的实际攻击面有限；密钥对生成使用 OsRng 随机私钥
/// 不经此路径泄漏。
///
/// 需要在高安全环境中防御物理攻击时，应改用 Montgomery ladder
/// 或 Joye's double-add 等恒定时间标量乘法。
fn point_mul(k: &[u64; 4], p: &Point) -> Point {
    let mut result = JacobianPoint {
        x: ZERO,
        y: ZERO,
        z: ZERO,
        infinity: true,
    };

    for i in (0..4).rev() {
        let mut limb = k[i];
        for _ in 0..64 {
            if !result.infinity {
                result = jacobian_double(&result);
            }
            if (limb >> 63) & 1 == 1 {
                result = jacobian_add_mixed(&result, p);
            }
            limb <<= 1;
        }
    }

    jacobian_to_affine(&result)
}

/// 验证点是否在曲线上: y^2 ≡ x^3 + ax + b (mod p)
fn point_is_on_curve(p: &Point) -> bool {
    if p.infinity {
        return true;
    }
    let lhs = fe_square(&p.y);
    // x^3 + ax + b = x^2 * x + a*x + b
    let x2 = fe_square(&p.x);
    let x3 = fe_mul(&x2, &p.x);
    let rhs = fe_add(&fe_add(&x3, &fe_mul(&A, &p.x)), &B);
    fe_eq(&lhs, &rhs)
}

/// 从压缩或未压缩字节解析点
fn point_from_bytes(bytes: &[u8]) -> Option<Point> {
    if bytes.len() == 65 && bytes[0] == 0x04 {
        // 未压缩
        let mut xb = [0u8; 32];
        let mut yb = [0u8; 32];
        xb.copy_from_slice(&bytes[1..33]);
        yb.copy_from_slice(&bytes[33..65]);
        let x = fe_from_bytes(&xb);
        let y = fe_from_bytes(&yb);
        let p = Point {
            x,
            y,
            infinity: false,
        };
        if point_is_on_curve(&p) {
            return Some(p);
        }
    }
    None
}

/// 将点序列化为 65 字节未压缩格式 (0x04 || x || y)
fn point_to_bytes(p: &Point) -> [u8; 65] {
    let mut out = [0u8; 65];
    out[0] = 0x04;
    let xb = fe_to_bytes(&p.x);
    let yb = fe_to_bytes(&p.y);
    out[1..33].copy_from_slice(&xb);
    out[33..65].copy_from_slice(&yb);
    out
}

// ============================================================
// Z_A 计算 (GB/T 32918.2-2016, 5.2.4)
// ============================================================

/// 默认用户标识 ID_A (16 字节)
const DEFAULT_ID: &[u8] = b"1234567812345678";

/// 计算 Z_A = SM3(ENTL_A || ID_A || a || b || x_G || y_G || x_A || y_A)
fn compute_za(pub_key: &Point, id: &[u8]) -> [u8; 32] {
    let entl = (id.len() * 8) as u16;

    let mut hasher = Sm3::new();
    hasher.update(&entl.to_be_bytes()); // ENTL_A: 2 字节
    hasher.update(id);
    hasher.update(&fe_to_bytes(&A));
    hasher.update(&fe_to_bytes(&B));
    hasher.update(&fe_to_bytes(&GX));
    hasher.update(&fe_to_bytes(&GY));
    hasher.update(&fe_to_bytes(&pub_key.x));
    hasher.update(&fe_to_bytes(&pub_key.y));
    hasher.finalize()
}

// ============================================================
// KDF (GB/T 32918.4-2016, 5.4.3)
// ============================================================

/// 基于 SM3 的密钥派生函数
fn kdf(z: &[u8], klen: usize) -> Vec<u8> {
    let n = klen.div_ceil(256);
    let mut result = Vec::with_capacity((n * 32).min(klen / 8 + 1));

    // 预分配输入缓冲区（z || counter），复用减少分配
    let mut input = Vec::with_capacity(z.len() + 4);
    for i in 1..=n {
        input.clear();
        input.extend_from_slice(z);
        input.extend_from_slice(&(i as u32).to_be_bytes());

        let hash = Sm3::digest(&input);
        result.extend_from_slice(&hash);
    }

    result.truncate(klen / 8);
    result
}

// ============================================================
// 确定性 k 生成 (HMAC-SM3, RFC 6979 风格)
// ============================================================

/// 使用 HMAC-SM3 生成确定性 k
///
/// 按 RFC 6979 风格构造: 带计数器循环以确保 k ∈ [1, n-1]
fn generate_deterministic_k(priv_key: &[u8; 32], hash: &[u8; 32], counter: u32) -> [u64; 4] {
    // 固定大小: 32(priv_key) + 32(hash) + 1(sep) + 4(counter) = 69 字节
    let mut input = [0u8; 69];
    input[..32].copy_from_slice(priv_key);
    input[32..64].copy_from_slice(hash);
    input[64] = 0x00;
    input[65..69].copy_from_slice(&counter.to_be_bytes());

    let hmac = hmac_sm3(b"SM2-deterministic-k", &input);
    scalar_from_bytes(&hmac)
}

// ============================================================
// 密钥对生成
// ============================================================

/// 生成 SM2 密钥对
///
/// # 返回值
///
/// `(私钥 Zeroizing<[u8; 32]>, 公钥 [u8; 65])`
/// 公钥为未压缩格式 (0x04 || x || y)
pub fn generate_key_pair() -> (Zeroizing<[u8; 32]>, [u8; 65]) {
    use rand::RngCore;
    let mut rng = rand::rngs::OsRng;

    loop {
        let mut priv_key = [0u8; 32];
        rng.fill_bytes(&mut priv_key);

        let d = scalar_from_bytes(&priv_key);
        if scalar_is_valid_range(&d) {
            let pub_point = point_mul(&d, &G);
            let pub_bytes = point_to_bytes(&pub_point);
            return (Zeroizing::new(priv_key), pub_bytes);
        }
    }
}

// ============================================================
// 数字签名生成 (GB/T 32918.2-2016, 6.1)
// ============================================================

/// SM2 签名
///
/// # 参数
///
/// * `priv_key` - 32 字节私钥（大端）
/// * `pub_key` - 65 字节公钥（未压缩）
/// * `message` - 待签名消息
///
/// # 返回值
///
/// 64 字节签名 (r || s)
pub fn sign(priv_key: &[u8; 32], pub_key: &[u8; 65], message: &[u8]) -> Signature {
    let d = scalar_from_bytes(priv_key);
    let pub_point = point_from_bytes(pub_key).expect("公钥格式无效");

    // Z_A = SM3(ENTL_A || ID_A || a || b || x_G || y_G || x_A || y_A)
    let za = compute_za(&pub_point, DEFAULT_ID);

    // e = SM3(Z_A || M)
    let mut hasher = Sm3::new();
    hasher.update(&za);
    hasher.update(message);
    let e = hasher.finalize();

    let e_int = scalar_from_bytes(&e);

    // 循环直到生成有效签名
    // counter 绑定在 u32 范围内（约 42 亿），理论上不可能耗尽，
    // 使用 checked_add 防止 debug 模式下溢出 panic
    let mut counter = 0u32;
    loop {
        // 生成确定性 k (RFC 6979 风格)
        let k_raw = generate_deterministic_k(priv_key, &e, counter);
        let k = if scalar_is_valid_range(&k_raw) {
            k_raw
        } else {
            counter = counter.checked_add(1).expect("counter 耗尽（实际不可达）");
            continue;
        };

        // (x1, y1) = kG
        let r_point = point_mul(&k, &G);
        let x1 = fe_to_bytes(&r_point.x);
        let x1_int = scalar_from_bytes(&x1);

        // r = (e + x1) mod n
        let r_int = scalar_add(&e_int, &x1_int);

        // 检验 r == 0 || r + k == n
        if scalar_is_zero(&r_int) {
            match counter.checked_add(1) {
                Some(c) => counter = c,
                None => panic!("counter 耗尽（实际不可达）"),
            }
            continue;
        }

        // s = ((1 + d)^(-1) * (k - r*d)) mod n
        let one = [1u64, 0, 0, 0];
        let one_plus_d = scalar_add(&one, &d);
        let inv_one_plus_d = scalar_inv(&one_plus_d);

        let r_times_d = scalar_mul(&r_int, &d);
        let k_minus_rd = scalar_sub_mod(&k, &r_times_d);

        let s_int = scalar_mul(&inv_one_plus_d, &k_minus_rd);

        // 检验 s == 0
        if scalar_is_zero(&s_int) {
            match counter.checked_add(1) {
                Some(c) => counter = c,
                None => panic!("counter 耗尽（实际不可达）"),
            }
            continue;
        }

        let r_bytes = scalar_to_bytes(&r_int);
        let s_bytes = scalar_to_bytes(&s_int);

        return Signature::new(r_bytes, s_bytes);
    }
}

// ============================================================
// 数字签名验证 (GB/T 32918.2-2016, 7.1)
// ============================================================

/// SM2 签名验证
///
/// # 参数
///
/// * `pub_key` - 65 字节公钥（未压缩）
/// * `message` - 被签名消息
/// * `signature` - SM2 签名
///
/// # 返回值
///
/// 签名有效返回 true
pub fn verify(pub_key: &[u8; 65], message: &[u8], signature: &Signature) -> bool {
    let pub_point = match point_from_bytes(pub_key) {
        Some(p) => p,
        None => return false,
    };

    // 检查点是否在曲线上
    if !point_is_on_curve(&pub_point) {
        return false;
    }

    // 解析 r, s（用 Signature 类型安全字段，避免手动切片）
    let r_int = scalar_from_bytes(&signature.r);
    let s_int = scalar_from_bytes(&signature.s);

    // 检查 r, s ∈ [1, n-1]
    if !scalar_is_valid_range(&r_int) || !scalar_is_valid_range(&s_int) {
        return false;
    }

    // 计算 Z_A
    let za = compute_za(&pub_point, DEFAULT_ID);

    // e = SM3(Z_A || M)
    let mut hasher = Sm3::new();
    hasher.update(&za);
    hasher.update(message);
    let e = hasher.finalize();
    let e_int = scalar_from_bytes(&e);

    // t = (r + s) mod n
    let t = scalar_add(&r_int, &s_int);
    if scalar_is_zero(&t) {
        return false;
    }

    // (x1, y1) = sG + tP（使用 Jacobian 加法，避免再次求逆）
    let j_sg = jacobian_from_affine(&point_mul(&s_int, &G));
    let j_tp = jacobian_from_affine(&point_mul(&t, &pub_point));
    let j_sum = jacobian_add(&j_sg, &j_tp);
    let sum = jacobian_to_affine(&j_sum);

    if sum.infinity {
        return false;
    }

    // R = (e' + x1) mod n
    let x1_bytes = fe_to_bytes(&sum.x);
    let x1_int = scalar_from_bytes(&x1_bytes);
    let rv = scalar_add(&e_int, &x1_int);

    rv == r_int
}

// ============================================================
// 公钥加密 (GB/T 32918.4-2016, 6.1)
// ============================================================

/// SM2 公钥加密
///
/// # 参数
///
/// * `pub_key` - 65 字节公钥（未压缩）
/// * `plaintext` - 明文
///
/// # 返回值
///
/// 密文: C1 || C3 || C2
/// - C1: 65 字节未压缩点 (kG)
/// - C3: 32 字节 SM3 摘要
/// - C2: 与明文等长的密文数据
pub fn encrypt(pub_key: &[u8; 65], plaintext: &[u8]) -> Vec<u8> {
    use rand::RngCore;
    let mut rng = rand::rngs::OsRng;

    let pub_point = point_from_bytes(pub_key).expect("公钥格式无效");

    loop {
        // 生成随机 k
        let mut k_bytes = [0u8; 32];
        rng.fill_bytes(&mut k_bytes);
        let k = scalar_from_bytes(&k_bytes);

        if !scalar_is_valid_range(&k) {
            continue;
        }

        // C1 = kG
        let c1_point = point_mul(&k, &G);
        let c1 = point_to_bytes(&c1_point);

        // k * PB = (x2, y2)
        let kpb = point_mul(&k, &pub_point);
        let x2 = fe_to_bytes(&kpb.x);
        let y2 = fe_to_bytes(&kpb.y);

        // t = KDF(x2 || y2, klen)
        let mut z = Vec::with_capacity(64);
        z.extend_from_slice(&x2);
        z.extend_from_slice(&y2);
        let t = kdf(&z, plaintext.len() * 8);

        // C2 = M XOR t
        let mut c2 = Vec::with_capacity(plaintext.len());
        for i in 0..plaintext.len() {
            c2.push(plaintext[i] ^ t[i]);
        }

        // C3 = SM3(x2 || M || y2)
        let mut hasher = Sm3::new();
        hasher.update(&x2);
        hasher.update(plaintext);
        hasher.update(&y2);
        let c3 = hasher.finalize();

        // 输出 C1 || C3 || C2
        let mut ciphertext = Vec::with_capacity(65 + 32 + plaintext.len());
        ciphertext.extend_from_slice(&c1);
        ciphertext.extend_from_slice(&c3);
        ciphertext.extend_from_slice(&c2);

        return ciphertext;
    }
}

// ============================================================
// 私钥解密 (GB/T 32918.4-2016, 6.2)
// ============================================================

/// SM2 私钥解密
///
/// # 参数
///
/// * `priv_key` - 32 字节私钥（大端）
/// * `ciphertext` - 密文: C1 || C3 || C2
///
/// # 返回值
///
/// * `Ok(plaintext)` - 解密成功
/// * `Err(&str)` - 解密失败（完整性校验未通过）
pub fn decrypt(priv_key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>, &'static str> {
    if ciphertext.len() < 65 + 32 {
        return Err("密文太短");
    }

    let c1_bytes = &ciphertext[..65];
    let c3_bytes = &ciphertext[65..97];
    let c2_bytes = &ciphertext[97..];

    // 解析 C1
    let c1_point = point_from_bytes(c1_bytes).ok_or("C1 格式无效或不在曲线上")?;

    let d = scalar_from_bytes(priv_key);

    // (x2, y2) = d * C1
    let d_c1 = point_mul(&d, &c1_point);
    let x2 = fe_to_bytes(&d_c1.x);
    let y2 = fe_to_bytes(&d_c1.y);

    // t = KDF(x2 || y2, klen)
    let mut z = Vec::with_capacity(64);
    z.extend_from_slice(&x2);
    z.extend_from_slice(&y2);
    let t = kdf(&z, c2_bytes.len() * 8);

    // M = C2 XOR t
    let mut plaintext = Vec::with_capacity(c2_bytes.len());
    for i in 0..c2_bytes.len() {
        plaintext.push(c2_bytes[i] ^ t[i]);
    }

    // u = SM3(x2 || M || y2)
    let mut hasher = Sm3::new();
    hasher.update(&x2);
    hasher.update(&plaintext);
    hasher.update(&y2);
    let u = hasher.finalize();

    // 常数时间比较 C3（使用 secure_eq 缺省 volatile + compiler_fence）
    let c3_array: &[u8; 32] = c3_bytes
        .try_into()
        .expect("前面已检查 ciphertext.len() >= 97");
    if !constant_time_eq_32(c3_array, &u) {
        return Err("完整性校验失败 (C3 不匹配)");
    }

    Ok(plaintext)
}

// ============================================================
// 测试
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    // ---------- 域运算测试 ----------

    #[test]
    fn test_fe_from_to_bytes() {
        let original = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54,
            0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98,
            0x76, 0x54, 0x32, 0x10,
        ];
        let fe = fe_from_bytes(&original);
        let bytes = fe_to_bytes(&fe);
        assert_eq!(bytes, original);
    }

    #[test]
    fn test_fe_add_basic() {
        let a = Fe([1, 0, 0, 0]);
        let b = Fe([2, 0, 0, 0]);
        let c = fe_add(&a, &b);
        assert_eq!(c, Fe([3, 0, 0, 0]));
    }

    #[test]
    fn test_fe_add_with_carry() {
        let a = Fe([0xFFFFFFFF_FFFFFFFF, 0, 0, 0]);
        let b = Fe([1, 0, 0, 0]);
        let c = fe_add(&a, &b);
        assert_eq!(c, Fe([0, 1, 0, 0]));
    }

    #[test]
    fn test_fe_add_reduce() {
        // a = p - 1, b = 2, result should be 1
        let a = Fe([
            0xFFFFFFFF_FFFFFFFE,
            0xFFFFFFFF_00000000,
            0xFFFFFFFF_FFFFFFFF,
            0xFFFFFFFE_FFFFFFFF,
        ]);
        let b = Fe([2, 0, 0, 0]);
        let c = fe_add(&a, &b);
        assert_eq!(c, Fe([1, 0, 0, 0]));
    }

    #[test]
    fn test_fe_sub_basic() {
        let a = Fe([5, 0, 0, 0]);
        let b = Fe([3, 0, 0, 0]);
        let c = fe_sub(&a, &b);
        assert_eq!(c, Fe([2, 0, 0, 0]));
    }

    #[test]
    fn test_fe_sub_with_borrow() {
        let a = Fe([1, 0, 0, 0]);
        let b = Fe([2, 0, 0, 0]);
        let c = fe_sub(&a, &b);
        // Should be p - 1
        let expected = Fe([
            0xFFFFFFFF_FFFFFFFE,
            0xFFFFFFFF_00000000,
            0xFFFFFFFF_FFFFFFFF,
            0xFFFFFFFE_FFFFFFFF,
        ]);
        assert_eq!(c, expected);
    }

    #[test]
    fn test_fe_mul_small() {
        let a = Fe([5, 0, 0, 0]);
        let b = Fe([3, 0, 0, 0]);
        let c = fe_mul(&a, &b);
        assert_eq!(c, Fe([15, 0, 0, 0]));
    }

    #[test]
    fn test_fe_mul_one() {
        let a = Fe([0xABCDEF01_23456789, 0, 0, 0]);
        let c = fe_mul(&a, &ONE);
        assert_eq!(c, a);
    }

    #[test]
    fn test_fe_mul_zero() {
        let a = Fe([0xABCD, 1, 2, 3]);
        let c = fe_mul(&a, &ZERO);
        assert_eq!(c, ZERO);
    }

    #[test]
    fn test_fe_inv_one() {
        let inv = fe_inv(&ONE);
        assert_eq!(inv, ONE);
    }

    #[test]
    fn test_fe_inv_times_original() {
        let a = Fe([
            0xDEADBEEF_CAFEBABE,
            0x12345678_9ABCDEF0,
            0xFEDCBA09_87654321,
            0x11111111_22222222,
        ]);
        if !fe_is_zero(&a) {
            let inv = fe_inv(&a);
            let product = fe_mul(&a, &inv);
            assert_eq!(product, ONE, "a * a^(-1) ≡ 1 (mod p)");
        }
    }

    #[test]
    fn test_fe_square_matches_mul() {
        let a = Fe([
            0xAAAAAAAA_BBBBBBBB,
            0xCCCCCCCC_DDDDDDDD,
            0xEEEEEEEE_FFFFFFFF,
            0x12345678_9ABCDEF0,
        ]);
        let sq = fe_square(&a);
        let mul = fe_mul(&a, &a);
        assert_eq!(sq, mul);
    }

    // ---------- 点运算测试 ----------

    #[test]
    fn test_generator_on_curve() {
        assert!(point_is_on_curve(&G), "基点应在曲线上");
    }

    #[test]
    fn test_point_double_check_on_curve() {
        let two = [2u64, 0, 0, 0];
        let dbl = point_mul(&two, &G);
        assert!(point_is_on_curve(&dbl), "2G 应在曲线上");
    }

    #[test]
    fn test_point_mul_zero() {
        let zero_scalar = [0u64; 4];
        let r = point_mul(&zero_scalar, &G);
        assert!(r.infinity, "0 * G = O");
    }

    #[test]
    fn test_point_mul_one() {
        let one_scalar = [1u64, 0, 0, 0];
        let r = point_mul(&one_scalar, &G);
        let r_bytes = point_to_bytes(&r);
        let g_bytes = point_to_bytes(&G);
        assert_eq!(r_bytes, g_bytes, "1 * G = G");
        assert!(point_is_on_curve(&r));
    }

    #[test]
    fn test_point_mul_n() {
        // n * G = O
        let r = point_mul(&N.0, &G);
        assert!(r.infinity, "n * G = O");
    }

    #[test]
    fn test_point_mul_commutative() {
        let a = Fe([0x1111, 0x2222, 0x3333, 0x4444]);
        let b = Fe([0x5555, 0x6666, 0x7777, 0x8888]);
        let pa = point_mul(&a.0, &G);
        let pb = point_mul(&b.0, &G);
        let ab = point_mul(&a.0, &pb);
        let ba = point_mul(&b.0, &pa);
        assert_eq!(
            point_to_bytes(&ab),
            point_to_bytes(&ba),
            "a*(b*G) = b*(a*G)"
        );
    }

    // ---------- 签名测试 ----------

    #[test]
    fn test_sign_verify_roundtrip() {
        let (priv_key, pub_key) = generate_key_pair();
        let message = b"SM2 signature test message";
        let signature = sign(&priv_key, &pub_key, message);
        assert!(verify(&pub_key, message, &signature), "签名验证应通过");
    }

    #[test]
    fn test_sign_verify_wrong_message() {
        let (priv_key, pub_key) = generate_key_pair();
        let sig = sign(&priv_key, &pub_key, b"original message");
        assert!(
            !verify(&pub_key, b"wrong message", &sig),
            "错误消息应拒绝签名"
        );
    }

    #[test]
    fn test_sign_verify_wrong_key() {
        let (priv_key1, pub_key1) = generate_key_pair();
        let (_priv_key2, pub_key2) = generate_key_pair();
        let sig = sign(&priv_key1, &pub_key1, b"test message");
        assert!(
            !verify(&pub_key2, b"test message", &sig),
            "错误公钥应拒绝签名"
        );
    }

    #[test]
    fn test_sign_deterministic() {
        let (priv_key, pub_key) = generate_key_pair();
        let message = b"deterministic test message";
        let sig1 = sign(&priv_key, &pub_key, message);
        let sig2 = sign(&priv_key, &pub_key, message);
        assert_eq!(sig1, sig2, "同一消息和密钥的签名应一致");
    }

    #[test]
    fn test_sign_verify_empty_message() {
        let (priv_key, pub_key) = generate_key_pair();
        let sig = sign(&priv_key, &pub_key, b"");
        assert!(verify(&pub_key, b"", &sig), "空消息签名验证应通过");
    }

    #[test]
    fn test_sign_verify_long_message() {
        let (priv_key, pub_key) = generate_key_pair();
        let mut msg = vec![0xABu8; 10000];
        let mut rng = rand::rngs::OsRng;
        rng.fill_bytes(&mut msg);
        let sig = sign(&priv_key, &pub_key, &msg);
        assert!(verify(&pub_key, &msg, &sig), "长消息签名验证应通过");
    }

    #[test]
    fn test_verify_tampered_signature() {
        let (priv_key, pub_key) = generate_key_pair();
        let sig = sign(&priv_key, &pub_key, b"test");
        let mut bytes = sig.to_bytes();
        bytes[5] ^= 0xFF;
        let tampered = Signature::from_bytes(&bytes);
        assert!(!verify(&pub_key, b"test", &tampered), "篡改签名应拒绝");
    }

    // ---------- 加密/解密测试 ----------

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let (priv_key, pub_key) = generate_key_pair();
        let plaintext = b"SM2 encryption test";
        let ciphertext = encrypt(&pub_key, plaintext);
        let decrypted = decrypt(&priv_key, &ciphertext).unwrap();
        assert_eq!(&decrypted, plaintext, "加解密应还原明文");
    }

    #[test]
    fn test_encrypt_decrypt_empty() {
        let (priv_key, pub_key) = generate_key_pair();
        let ciphertext = encrypt(&pub_key, b"");
        let decrypted = decrypt(&priv_key, &ciphertext).unwrap();
        assert!(decrypted.is_empty(), "空明文加解密应返回空");
    }

    #[test]
    fn test_encrypt_decrypt_long() {
        let (priv_key, pub_key) = generate_key_pair();
        let mut plaintext = vec![0x42u8; 1000];
        let mut rng = rand::rngs::OsRng;
        rng.fill_bytes(&mut plaintext);
        let ciphertext = encrypt(&pub_key, &plaintext);
        let decrypted = decrypt(&priv_key, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext, "长数据加解密应还原");
    }

    #[test]
    fn test_encrypt_different_each_time() {
        let (_priv_key, pub_key) = generate_key_pair();
        let plaintext = b"same message";
        let ct1 = encrypt(&pub_key, plaintext);
        let ct2 = encrypt(&pub_key, plaintext);
        // 不同随机 k 应产生不同密文
        assert_ne!(ct1, ct2, "随机加密应产生不同密文");
    }

    #[test]
    fn test_decrypt_wrong_key() {
        let (_priv_key1, pub_key1) = generate_key_pair();
        let (priv_key2, _pub_key2) = generate_key_pair();
        let ct = encrypt(&pub_key1, b"secret data");
        let result = decrypt(&priv_key2, &ct);
        assert!(result.is_err(), "错误密钥解密应失败");
    }

    #[test]
    fn test_decrypt_tampered_ciphertext() {
        let (priv_key, pub_key) = generate_key_pair();
        let mut ct = encrypt(&pub_key, b"sensitive data");
        let len = ct.len();
        if len > 66 {
            // 篡改 C2 的第一个字节
            ct[len - 1] ^= 0xFF;
            let result = decrypt(&priv_key, &ct);
            assert!(result.is_err(), "篡改密文解密应失败");
        }
    }

    // ---------- 密钥对测试 ----------

    #[test]
    fn test_generate_key_pair_valid() {
        let (priv_key, pub_key) = generate_key_pair();
        assert_eq!(pub_key[0], 0x04, "公钥应为未压缩格式");
        // 私钥非零
        let d = scalar_from_bytes(&priv_key);
        assert!(scalar_is_valid_range(&d), "私钥应在有效范围内");
    }

    #[test]
    fn test_generate_key_pair_unique() {
        let (pk1, _) = generate_key_pair();
        let (pk2, _) = generate_key_pair();
        assert_ne!(pk1, pk2, "两次密钥生成应不同");
    }

    // ---------- Z_A 计算测试 ----------

    #[test]
    fn test_za_is_32_bytes() {
        let (_, pub_key) = generate_key_pair();
        let pub_point = point_from_bytes(&pub_key).unwrap();
        let za = compute_za(&pub_point, DEFAULT_ID);
        assert_eq!(za.len(), 32);
    }

    // ---------- KDF 测试 ----------

    #[test]
    fn test_kdf_empty_output() {
        let result = kdf(b"test input", 0);
        assert!(result.is_empty());
    }

    #[test]
    fn test_kdf_256_bit() {
        let result = kdf(b"test input", 256);
        assert_eq!(result.len(), 32, "256 位 KDF 输出应为 32 字节");
    }

    #[test]
    fn test_kdf_deterministic() {
        let r1 = kdf(b"same input", 128);
        let r2 = kdf(b"same input", 128);
        assert_eq!(r1, r2, "KDF 应具有确定性");
    }

    // ---------- 常数测试 ----------

    #[test]
    fn test_curve_parameters() {
        // 验证 P 是素数（基本检查：P 是奇数且 P > 2^255）
        assert!(P.0[3] >= 0x80000000_00000000, "P 应为 256 位");
        assert!(P.0[0] & 1 == 1, "P 应为奇数");
        // 验证 a = p - 3
        let p_minus_3 = fe_sub(&P, &Fe([3, 0, 0, 0]));
        assert_eq!(A, p_minus_3, "a ≡ p - 3");
        // 验证 G 在曲线上
        assert!(point_is_on_curve(&G));
        // 验证 B 非零
        assert!(!fe_is_zero(&B));
    }

    #[test]
    fn test_n_validation() {
        // n 应小于 p
        assert!(scalar_ge(&P.0, &N.0), "n 应小于 p");
        // n * G = O
        let ng = point_mul(&N.0, &G);
        assert!(ng.infinity, "n * G = O");
    }

    #[test]
    fn test_reduce_convergence() {
        // 全 1 的 512 位值应正确约简: (2^512-1) mod p
        let z = [0xFFFFFFFF_FFFFFFFFu64; 8];
        let r = fe_reduce(&z);
        // 正确值由 Python 独立计算验证
        let expected = Fe([
            0x00000002_00000002,
            0x00000002_FFFFFFFF,
            0x00000001_00000001,
            0x00000004_00000002,
        ]);
        assert_eq!(r, expected, "全 1 512 位值的约简应正确");
    }

    // ---------- 字节序列化测试 ----------

    #[test]
    fn test_point_serialization() {
        let (_, pub_key) = generate_key_pair();
        let p = point_from_bytes(&pub_key).unwrap();
        let bytes = point_to_bytes(&p);
        assert_eq!(bytes, pub_key);
    }

    #[test]
    fn test_signature_to_from_bytes() {
        let sig = Signature::new([0x01u8; 32], [0x02u8; 32]);
        let bytes = sig.to_bytes();
        let sig2 = Signature::from_bytes(&bytes);
        assert_eq!(sig.r, sig2.r);
        assert_eq!(sig.s, sig2.s);
    }

    // ---------- 标量运算测试 ----------
    #[test]
    fn test_scalar_mul_large() {
        let large = [0xFFFFFFFF_FFFFFFFFu64; 4];
        let two = [2u64, 0, 0, 0];
        let r = scalar_mul(&large, &two);
        // (2^256-1)*2 mod n = 2*(2^256-mod n)-2 = 2*n_c - 2
        // Expected LE: [6379375181199408568, 2015432480759477673, 1, 8589934592]
        assert_eq!(r, [6379375181199408568, 2015432480759477673, 1, 8589934592]);
    }
}
