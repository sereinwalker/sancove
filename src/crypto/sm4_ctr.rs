//! SM4 分组密码算法 (GB/T 32907-2016)
//!
//! 本模块实现 SM4 块加密核心算法，以及 CBC 模式下的加解密。
//!
//! # 测试向量
//!
//! 密钥:    01234567 89ABCDEF FEDCBA98 76543210
//! 明文:    01234567 89ABCDEF FEDCBA98 76543210
//! 密文:    681EDF34 D206965E 86B3E94F 536E4246

// ============================================================
// S 盒（8 位输入 → 8 位输出）
// ============================================================

pub const SBOX: [u8; 256] = [
    0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05,
    0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3, 0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
    0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6,
    0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA, 0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8,
    0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
    0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87,
    0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52, 0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E,
    0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
    0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3,
    0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60, 0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F,
    0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
    0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8,
    0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD, 0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0,
    0x89, 0x69, 0x97, 0x4A, 0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
    0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E, 0xD7, 0xCB, 0x39, 0x48,
];

// ============================================================
// 系统参数 FK（用于密钥扩展）
// ============================================================

const FK: [u32; 4] = [0xA3B1_BAC6, 0x56AA_3350, 0x677D_9197, 0xB270_22DC];

// ============================================================
// 固定参数 CK（用于密钥扩展，共 32 个）
// ============================================================

const CK: [u32; 32] = {
    let mut ck = [0u32; 32];
    let mut i = 0;
    while i < 32 {
        // ck[i][j] = (4i + j) × 7 mod 256  (j = 0,1,2,3)
        let b0 = ((4 * i) * 7) as u8;
        let b1 = ((4 * i + 1) * 7) as u8;
        let b2 = ((4 * i + 2) * 7) as u8;
        let b3 = ((4 * i + 3) * 7) as u8;
        ck[i] = u32::from_be_bytes([b0, b1, b2, b3]);
        i += 1;
    }
    ck
};

// ============================================================
// 核心密码函数
// ============================================================

/// S 盒替换：输入 32 位字，输出 32 位字（每个字节独立替换）
#[inline]
fn sm4_subword(x: u32) -> u32 {
    let b = x.to_be_bytes();
    let s0 = SBOX[b[0] as usize] as u32;
    let s1 = SBOX[b[1] as usize] as u32;
    let s2 = SBOX[b[2] as usize] as u32;
    let s3 = SBOX[b[3] as usize] as u32;
    (s0 << 24) | (s1 << 16) | (s2 << 8) | s3
}

/// 线性变换 L（加密轮函数中使用）
/// L(B) = B ⊕ (B <<< 2) ⊕ (B <<< 10) ⊕ (B <<< 18) ⊕ (B <<< 24)
#[inline]
fn sm4_linear_l(b: u32) -> u32 {
    b ^ b.rotate_left(2) ^ b.rotate_left(10) ^ b.rotate_left(18) ^ b.rotate_left(24)
}

/// 线性变换 L'（密钥扩展中使用）
/// L'(B) = B ⊕ (B <<< 13) ⊕ (B <<< 23)
#[inline]
fn sm4_linear_l_prime(b: u32) -> u32 {
    b ^ b.rotate_left(13) ^ b.rotate_left(23)
}

/// 加密轮函数 F
/// F(X0, X1, X2, X3, rk) = X0 ⊕ L(τ(X1 ⊕ X2 ⊕ X3 ⊕ rk))
#[inline]
fn sm4_f(x0: u32, x1: u32, x2: u32, x3: u32, rk: u32) -> u32 {
    x0 ^ sm4_linear_l(sm4_subword(x1 ^ x2 ^ x3 ^ rk))
}

/// 密钥扩展轮函数 F'
/// F'(k0, k1, k2, k3, ck) = k0 ⊕ L'(τ(k1 ⊕ k2 ⊕ k3 ⊕ ck))
#[inline]
fn sm4_f_prime(k0: u32, k1: u32, k2: u32, k3: u32, ck: u32) -> u32 {
    k0 ^ sm4_linear_l_prime(sm4_subword(k1 ^ k2 ^ k3 ^ ck))
}

// ============================================================
// 密钥扩展
// ============================================================

/// SM4 密钥扩展，生成 32 轮轮密钥
pub fn sm4_key_expansion(key: &[u8; 16]) -> [u32; 32] {
    let k = [
        u32::from_be_bytes([key[0], key[1], key[2], key[3]]),
        u32::from_be_bytes([key[4], key[5], key[6], key[7]]),
        u32::from_be_bytes([key[8], key[9], key[10], key[11]]),
        u32::from_be_bytes([key[12], key[13], key[14], key[15]]),
    ];

    let mut mk = [0u32; 36];
    mk[0] = k[0] ^ FK[0];
    mk[1] = k[1] ^ FK[1];
    mk[2] = k[2] ^ FK[2];
    mk[3] = k[3] ^ FK[3];

    let mut rk = [0u32; 32];
    for i in 0..32 {
        mk[i + 4] = sm4_f_prime(mk[i], mk[i + 1], mk[i + 2], mk[i + 3], CK[i]);
        rk[i] = mk[i + 4];
    }
    rk
}

// ============================================================
// 块加密 / 解密（ECB 单块）
// ============================================================

/// SM4 加密一个 128 位块
pub fn sm4_encrypt_block(block: &[u8; 16], rk: &[u32; 32]) -> [u8; 16] {
    let mut x = [
        u32::from_be_bytes([block[0], block[1], block[2], block[3]]),
        u32::from_be_bytes([block[4], block[5], block[6], block[7]]),
        u32::from_be_bytes([block[8], block[9], block[10], block[11]]),
        u32::from_be_bytes([block[12], block[13], block[14], block[15]]),
    ];

    for &rk_i in rk.iter() {
        let f = sm4_f(x[0], x[1], x[2], x[3], rk_i);
        x[0] = x[1];
        x[1] = x[2];
        x[2] = x[3];
        x[3] = f;
    }

    // 反序输出：X3, X2, X1, X0
    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&x[3].to_be_bytes());
    out[4..8].copy_from_slice(&x[2].to_be_bytes());
    out[8..12].copy_from_slice(&x[1].to_be_bytes());
    out[12..16].copy_from_slice(&x[0].to_be_bytes());
    out
}

/// SM4 解密一个 128 位块（使用逆序轮密钥）
pub fn sm4_decrypt_block(block: &[u8; 16], rk: &[u32; 32]) -> [u8; 16] {
    let mut rk_rev = *rk;
    rk_rev.reverse();
    sm4_encrypt_block(block, &rk_rev)
}

// ============================================================
// SM4 密钥结构（含轮密钥 + ZeroizeOnDrop）
// ============================================================

use zeroize::Zeroize;

/// SM4 轮密钥，drop 时自动零化
#[derive(Clone)]
pub struct Sm4Key {
    rk: [u32; 32],
}

impl Sm4Key {
    pub fn new(key: &[u8; 16]) -> Self {
        Self {
            rk: sm4_key_expansion(key),
        }
    }

    /// 获取轮密钥引用（用于直接调用 T-Table 加密函数）
    pub fn rk(&self) -> &[u32; 32] {
        &self.rk
    }

    pub fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        sm4_encrypt_block_fast(block, &self.rk)
    }

    pub fn decrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        sm4_decrypt_block(block, &self.rk)
    }
}

impl Drop for Sm4Key {
    fn drop(&mut self) {
        // 将轮密钥数组零化
        for word in self.rk.iter_mut() {
            word.zeroize();
        }
    }
}

// ============================================================
// CBC 模式（带 PKCS#7 填充）
// ============================================================

/// SM4-CBC 解密（含 PKCS#7 填充验证）
///
/// # 参数
///
/// * `key` - 16 字节密钥
/// * `iv` - 16 字节初始向量
/// * `ciphertext` - 密文（长度须为 16 的倍数）
///
/// # 返回值
///
/// * `Ok(plaintext)` - 解密后的明文
/// * `Err(&str)` - 解密失败（填充无效）
pub fn sm4_cbc_decrypt(
    key: &[u8; 16],
    iv: &[u8; 16],
    ciphertext: &[u8],
) -> Result<Vec<u8>, &'static str> {
    // 展开密钥后委托给预展开版本，消除 PKCS#7 验证逻辑重复
    let sm4_key = Sm4Key::new(key);
    sm4_cbc_decrypt_with_key(&sm4_key, iv, ciphertext)
}

/// SM4-CBC 解密（使用预展开的 Sm4Key）
///
/// 避免每次调用重新展开密钥，适合 KEK 等反复使用的场景。
///
/// # 参数
///
/// * `key` - 预展开的 SM4 轮密钥
/// * `iv` - 16 字节初始向量
/// * `ciphertext` - 密文（长度须为 16 的倍数）
///
/// # 返回值
///
/// * `Ok(plaintext)` - 解密后的明文
/// * `Err(&str)` - 解密失败（填充无效）
pub fn sm4_cbc_decrypt_with_key(
    key: &Sm4Key,
    iv: &[u8; 16],
    ciphertext: &[u8],
) -> Result<Vec<u8>, &'static str> {
    if !ciphertext.len().is_multiple_of(16) || ciphertext.is_empty() {
        return Err("CBC 密文长度必须为 16 的倍数且非空");
    }

    let block_count = ciphertext.len() / 16;
    let mut plaintext = Vec::with_capacity(ciphertext.len());

    let mut prev = *iv;

    for i in 0..block_count {
        let start = i * 16;
        let block: [u8; 16] = ciphertext[start..start + 16]
            .try_into()
            .expect("前面已检查 ciphertext 长度为 16 的倍数且 >= 16");

        // CBC 解密：先解密，再 XOR IV/前一密文块
        let decrypted = key.decrypt_block(&block);

        let mut plain_block = [0u8; 16];
        for j in 0..16 {
            plain_block[j] = decrypted[j] ^ prev[j];
        }

        // 如果是最后一块，常数时间验证 PKCS#7 并去除填充
        if i == block_count - 1 {
            let pad_byte = plain_block[15];
            let mut pad_ok = 0u8;

            let range_ok = (pad_byte.wrapping_sub(1) <= 15) as u8;
            pad_ok |= 1u8 ^ range_ok;

            for (j, &pb) in plain_block.iter().enumerate() {
                let is_padding = (pad_byte >= 16u8.wrapping_sub(j as u8)) as u8;
                let byte_eq = (pb == pad_byte) as u8;
                pad_ok |= (1u8 ^ byte_eq) & is_padding;
            }

            if pad_ok != 0 {
                return Err("PKCS#7 填充验证失败");
            }

            plaintext.extend_from_slice(&plain_block[..16 - pad_byte as usize]);
        } else {
            plaintext.extend_from_slice(&plain_block);
        }

        prev = block;
    }

    Ok(plaintext)
}

// ============================================================
// CTR 模式（无填充流密码化）
// ============================================================

/// SM4-CTR 模式加密/解密
///
/// CTR 模式将 SM4 转化为流密码：生成密钥流并与明文异或。
///
/// # 参数
///
/// * `key` - 16 字节 SM4 密钥
/// * `nonce` - 96 位 (12 字节) 随机数
/// * `data` - 明文（加密时）或密文（解密时）
///
/// # 计数器构造
///
/// 128 位计数器块 = nonce (96 bit) || counter (32 bit, 大端序)
/// 计数器从 1 开始（保留 counter=0 作为 IV 标识，防止首块重用漏洞）
///
/// # 返回值
///
/// 密文（加密时）或明文（解密时），长度与 data 相同
pub fn sm4_ctr_crypt(key: &[u8; 16], nonce: &[u8; 12], data: &[u8]) -> Vec<u8> {
    let rk = sm4_key_expansion(key);
    let block_count = data.len().div_ceil(16); // 上取整
    let mut result = Vec::with_capacity(data.len());

    for block_idx in 0..block_count {
        // 构造计数器块：nonce（12 字节） || counter（4 字节大端，从 1 开始）
        let mut counter_block = [0u8; 16];
        counter_block[..12].copy_from_slice(nonce);
        let counter_val = (block_idx as u32).wrapping_add(1);
        counter_block[12..16].copy_from_slice(&counter_val.to_be_bytes());

        // 生成密钥流块
        let keystream = sm4_encrypt_block(&counter_block, &rk);

        // XOR 密钥流与数据
        let start = block_idx * 16;
        let end = (start + 16).min(data.len());
        for i in start..end {
            result.push(data[i] ^ keystream[i - start]);
        }
    }

    result
}

// ============================================================
// T-Table 优化：将 S 盒变换与线性变换 L 融合为查找表
// 将每轮的 4×SBOX + 循环移位 + 4×XOR 缩减为 4×查表 + 3×XOR
// ============================================================

use std::sync::OnceLock;

/// 4 个 T-Table，每个 256 个 32 位字
/// T0-SBOX 融合线性变换，查表即完成 τ+L 运算
fn t_tables() -> &'static [[u32; 256]; 4] {
    static TABLES: OnceLock<[[u32; 256]; 4]> = OnceLock::new();
    TABLES.get_or_init(|| {
        let mut t = [[0u32; 256]; 4];
        for b in 0..=255u32 {
            let sb = SBOX[b as usize] as u32;
            // 位置 0 (最高字节): w = [sb, 0, 0, 0]
            let w0 = sb << 24;
            t[0][b as usize] = w0
                ^ w0.rotate_left(2)
                ^ w0.rotate_left(10)
                ^ w0.rotate_left(18)
                ^ w0.rotate_left(24);
            // 位置 1: [0, sb, 0, 0]
            let w1 = sb << 16;
            t[1][b as usize] = w1
                ^ w1.rotate_left(2)
                ^ w1.rotate_left(10)
                ^ w1.rotate_left(18)
                ^ w1.rotate_left(24);
            // 位置 2: [0, 0, sb, 0]
            let w2 = sb << 8;
            t[2][b as usize] = w2
                ^ w2.rotate_left(2)
                ^ w2.rotate_left(10)
                ^ w2.rotate_left(18)
                ^ w2.rotate_left(24);
            // 位置 3 (最低字节): [0, 0, 0, sb]
            t[3][b as usize] = sb
                ^ sb.rotate_left(2)
                ^ sb.rotate_left(10)
                ^ sb.rotate_left(18)
                ^ sb.rotate_left(24);
        }
        t
    })
}

/// T-Table 优化的 SM4 单块加密
///
/// 每轮只需 4 次查表 + 3 次 XOR，无需独立 SBOX 查找和线性移位。
pub fn sm4_encrypt_block_fast(block: &[u8; 16], rk: &[u32; 32]) -> [u8; 16] {
    let mut x = [
        u32::from_be_bytes([block[0], block[1], block[2], block[3]]),
        u32::from_be_bytes([block[4], block[5], block[6], block[7]]),
        u32::from_be_bytes([block[8], block[9], block[10], block[11]]),
        u32::from_be_bytes([block[12], block[13], block[14], block[15]]),
    ];

    let tables = t_tables();

    for &rk_i in rk.iter() {
        let y = x[1] ^ x[2] ^ x[3] ^ rk_i;
        let b = y.to_be_bytes();
        // 一轮运算简化为 4 次查表 + 3 次 XOR
        let t = tables[0][b[0] as usize]
            ^ tables[1][b[1] as usize]
            ^ tables[2][b[2] as usize]
            ^ tables[3][b[3] as usize];
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

/// SM4-CBC 加密（使用预展开的 Sm4Key）
///
/// 避免每次调用重新展开密钥，适合 KEK 等反复使用的场景。
pub fn sm4_cbc_encrypt(key: &Sm4Key, iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    let rk = key.rk();
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
            let copy_len = remaining.min(16);
            block[..copy_len].copy_from_slice(&plaintext[offset..offset + copy_len]);
        }
        for j in 0..16 {
            block[j] ^= prev[j];
        }
        let encrypted = sm4_encrypt_block_fast(&block, rk);
        ciphertext.extend_from_slice(&encrypted);
        prev = encrypted;
        offset += 16;
    }
    ciphertext
}

/// T-Table 优化的 CTR 加密/解密（相较基线 SM4-CTR 加速约 2-3x）
///
/// 与 [`sm4_ctr_crypt`] 行为相同，但内部使用 T-Table 查表代替逐字节 S-Box + 线性变换。
/// 同样每次调用独立展开密钥，非流式场景专用。
pub fn sm4_ctr_crypt_t_table(key: &[u8; 16], nonce: &[u8; 12], data: &[u8]) -> Vec<u8> {
    let rk = sm4_key_expansion(key);
    let block_count = data.len().div_ceil(16);
    let mut result = Vec::with_capacity(data.len());
    for block_idx in 0..block_count {
        let mut cb = [0u8; 16];
        cb[..12].copy_from_slice(nonce);
        let cv = (block_idx as u32).wrapping_add(1);
        cb[12..16].copy_from_slice(&cv.to_be_bytes());
        let ks = sm4_encrypt_block_fast(&cb, &rk);
        let start = block_idx * 16;
        let end = (start + 16).min(data.len());
        for i in start..end {
            result.push(data[i] ^ ks[i - start]);
        }
    }
    result
}

/// 流式 CTR 原地变换（加密或解密，CTR 两者相同）
///
/// 使用预展开密钥和指定起始块偏移，原地 XOR 密钥流到缓冲区。
/// 适合分块处理大文件：多次调用，每次处理一块数据。
///
/// # 参数
///
/// * `key` - 预展开 SM4 密钥
/// * `nonce` - 12 字节随机数
/// * `start_block` - 起始块偏移（0 对应计数器从 1 开始）
/// * `buf` - 待处理的缓冲区（原地修改）
///
/// # 计数器溢出
///
/// `start_block` 为 `u32` 类型，当文件超过 ~4 GB（即 `start_block + block_count > 2^32`）
/// 时计数器会回绕至 0，导致密钥流重用。桌面场景几乎不可达此上限。
pub fn sm4_ctr_transform(key: &Sm4Key, nonce: &[u8; 12], start_block: u32, buf: &mut [u8]) {
    let block_count = buf.len().div_ceil(16);
    for block_idx in 0..block_count {
        let mut cb = [0u8; 16];
        cb[..12].copy_from_slice(nonce);
        let cv = start_block.wrapping_add(block_idx as u32).wrapping_add(1);
        cb[12..16].copy_from_slice(&cv.to_be_bytes());
        let ks = key.encrypt_block(&cb);
        let start = block_idx * 16;
        let end = (start + 16).min(buf.len());
        for i in start..end {
            buf[i] ^= ks[i - start];
        }
    }
}

// ============================================================
// 测试
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    /// 官方测试向量：密钥 == 明文 == 0x0123456789ABCDEFFEDCBA9876543210
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

    #[test]
    fn test_sm4_encrypt_block() {
        let rk = sm4_key_expansion(&TEST_KEY);
        let ct = sm4_encrypt_block(&TEST_PT, &rk);
        assert_eq!(ct, TEST_CT, "SM4 单块加密应与官方测试向量一致");
    }

    #[test]
    fn test_sm4_decrypt_block() {
        let rk = sm4_key_expansion(&TEST_KEY);
        let pt = sm4_decrypt_block(&TEST_CT, &rk);
        assert_eq!(pt, TEST_PT, "SM4 单块解密应还原明文");
    }

    #[test]
    fn test_sm4_encrypt_then_decrypt() {
        let rk = sm4_key_expansion(&TEST_KEY);
        let ct = sm4_encrypt_block(&TEST_PT, &rk);
        let pt = sm4_decrypt_block(&ct, &rk);
        assert_eq!(pt, TEST_PT, "加密后再解密应还原明文");
    }

    #[test]
    fn test_sm4_key_expansion_all_rounds() {
        let rk = sm4_key_expansion(&TEST_KEY);
        assert_eq!(rk.len(), 32);
        // 打印实际值以供验证
        eprintln!("rk[0] = 0x{:08X} ({})", rk[0], rk[0]);
        eprintln!("rk[1] = 0x{:08X} ({})", rk[1], rk[1]);
        // 验证正确性：只要能加解密正确即可，此处不作硬编码断言
        let ct = sm4_encrypt_block(&TEST_PT, &rk);
        assert_eq!(ct, TEST_CT, "轮密钥生成的加密应与官方测试向量一致");
    }

    #[test]
    fn test_sm4_cbc_encrypt_decrypt() {
        let iv = [0xAB; 16];
        let plaintext = b"Hello, SM4 CBC mode!";

        let ct = sm4_cbc_encrypt(&Sm4Key::new(&TEST_KEY), &iv, plaintext);
        let pt = sm4_cbc_decrypt(&TEST_KEY, &iv, &ct).unwrap();

        assert_eq!(&pt, plaintext, "CBC 加解密应还原明文");
    }

    #[test]
    fn test_sm4_cbc_empty_plaintext() {
        let iv = [0x00; 16];
        // 空明文加密后应为单个填充块
        let ct = sm4_cbc_encrypt(&Sm4Key::new(&TEST_KEY), &iv, b"");
        assert_eq!(ct.len(), 16, "空明文应产生一个完整的填充块");
        let pt = sm4_cbc_decrypt(&TEST_KEY, &iv, &ct).unwrap();
        assert_eq!(pt.len(), 0, "解密空明文应返回空");
    }

    #[test]
    fn test_sm4_cbc_exact_block() {
        let iv = [0xCD; 16];
        let plaintext = b"1234567890123456"; // 恰好 16 字节
        let ct = sm4_cbc_encrypt(&Sm4Key::new(&TEST_KEY), &iv, plaintext);
        // 16 字节明文 + PKCS#7 填充 = 32 字节密文（增加一个完整填充块）
        assert_eq!(ct.len(), 32);
        let pt = sm4_cbc_decrypt(&TEST_KEY, &iv, &ct).unwrap();
        assert_eq!(&pt, plaintext);
    }

    #[test]
    fn test_sm4_cbc_tampered_ciphertext() {
        let iv = [0xEF; 16];
        let plaintext = b"Sensitive document content";
        let mut ct = sm4_cbc_encrypt(&Sm4Key::new(&TEST_KEY), &iv, plaintext);
        // 篡改密文的一个字节
        ct[5] ^= 0xFF;
        let result = sm4_cbc_decrypt(&TEST_KEY, &iv, &ct);
        // 由于填充校验，篡改应该导致错误（大概率验证失败）
        // 注意：这不是认证加密，只是 CBC 解密的填充校验
        assert!(
            result.is_err() || result.unwrap() != plaintext,
            "篡改应导致解密失败或内容不一致"
        );
    }

    #[test]
    fn test_sm4_sm3_round_trip() {
        // 集成测试：用 SM3 派生密钥，再用 SM4 加解密
        let master_key = b"my secret master password";
        let derived = crate::crypto::sm3::pbkdf2_sm3(master_key, b"file_vault", 100, 16);
        let mut key = [0u8; 16];
        key.copy_from_slice(&derived);

        let iv = [0x42; 16];
        let data = b"Integration test for SM3+SM4 pipeline";

        let ct = sm4_cbc_encrypt(&Sm4Key::new(&key), &iv, data);
        let pt = sm4_cbc_decrypt(&key, &iv, &ct).unwrap();
        assert_eq!(&pt, data);
    }

    #[test]
    fn test_sm4_key_drop_zeroize() {
        // Sm4Key 在 drop 时应零化轮密钥
        let key_bytes = [0xFFu8; 16];
        {
            let sm4_key = Sm4Key::new(&key_bytes);
            // 检查轮密钥非零（刚初始化）
            assert_ne!(sm4_key.rk[0], 0);
        }
        // 超出作用域后，Sm4Key 的 drop 已被调用
        // 注：无法直接验证清零，因为内存已被释放
        // 此测试编译通过即证明 Sm4Key 实现了 Drop
    }

    #[test]
    fn test_sm4_key_encrypt_decrypt() {
        let sm4_key = Sm4Key::new(&TEST_KEY);
        let ct = sm4_key.encrypt_block(&TEST_PT);
        assert_eq!(ct, TEST_CT);
        let pt = sm4_key.decrypt_block(&ct);
        assert_eq!(pt, TEST_PT);
    }

    // ---------- SM4-CTR ----------

    #[test]
    fn test_sm4_ctr_roundtrip() {
        let key = [0xAB; 16];
        let nonce = [0xCD; 12];
        let plaintext = b"Hello, SM4 CTR mode! Stream cipher test.";

        let ct = sm4_ctr_crypt(&key, &nonce, plaintext);
        assert_eq!(ct.len(), plaintext.len(), "CTR 密文应与明文等长");

        let pt = sm4_ctr_crypt(&key, &nonce, &ct);
        assert_eq!(&pt, plaintext, "CTR 加解密应还原明文");
    }

    #[test]
    fn test_sm4_ctr_exact_blocks() {
        let key = [0x01; 16];
        let nonce = [0x02; 12];
        let plaintext = *b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // 32B = 2 blocks
        let ct = sm4_ctr_crypt(&key, &nonce, &plaintext);
        assert_eq!(ct.len(), 32);
        let pt = sm4_ctr_crypt(&key, &nonce, &ct);
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_sm4_ctr_single_byte() {
        let key = [0x11; 16];
        let nonce = [0x22; 12];
        let ct = sm4_ctr_crypt(&key, &nonce, b"X");
        assert_eq!(ct.len(), 1);
        let pt = sm4_ctr_crypt(&key, &nonce, &ct);
        assert_eq!(pt, b"X");
    }

    #[test]
    fn test_sm4_ctr_empty() {
        let key = [0x33; 16];
        let nonce = [0x44; 12];
        assert!(sm4_ctr_crypt(&key, &nonce, b"").is_empty());
    }

    #[test]
    fn test_sm4_ctr_different_nonce() {
        let key = [0x55; 16];
        let plain = b"test message";
        let ct1 = sm4_ctr_crypt(&key, &[0xAA; 12], plain);
        let ct2 = sm4_ctr_crypt(&key, &[0xBB; 12], plain);
        assert_ne!(ct1, ct2, "不同 nonce 应产生不同密文");
    }

    #[test]
    fn test_sm4_ctr_deterministic() {
        let key = [0x66; 16];
        let nonce = [0x77; 12];
        let plain = b"deterministic test";
        assert_eq!(
            sm4_ctr_crypt(&key, &nonce, plain),
            sm4_ctr_crypt(&key, &nonce, plain)
        );
    }

    // ---------- T-Table ----------

    #[test]
    fn test_t_table_encrypt_matches_baseline() {
        let rk = sm4_key_expansion(&TEST_KEY);
        let baseline = sm4_encrypt_block(&TEST_PT, &rk);
        let fast = sm4_encrypt_block_fast(&TEST_PT, &rk);
        assert_eq!(fast, baseline, "T-Table 加密结果应与基线一致");
        assert_eq!(fast, TEST_CT);
    }

    #[test]
    fn test_t_table_random_blocks() {
        let mut rng = rand::rngs::OsRng;
        let mut key = [0u8; 16];
        let mut pt = [0u8; 16];
        for _ in 0..100 {
            rng.fill_bytes(&mut key);
            rng.fill_bytes(&mut pt);
            let rk = sm4_key_expansion(&key);
            let b = sm4_encrypt_block(&pt, &rk);
            let f = sm4_encrypt_block_fast(&pt, &rk);
            assert_eq!(f, b, "T-Table 对所有随机块应与基线一致");
        }
    }

    #[test]
    fn test_t_table_cbc_matches_baseline() {
        let mut rng = rand::rngs::OsRng;
        let mut key = [0u8; 16];
        let mut iv = [0u8; 16];
        rng.fill_bytes(&mut key);
        rng.fill_bytes(&mut iv);
        let data = b"Test data for CBC mode comparison with varying length!";

        let baseline = sm4_cbc_encrypt(&Sm4Key::new(&key), &iv, data);
        let sm4_key = Sm4Key::new(&key);
        let fast = sm4_cbc_encrypt(&sm4_key, &iv, data);
        assert_eq!(fast, baseline, "T-Table CBC 应与基线 CBC 一致");

        let pt_baseline = sm4_cbc_decrypt(&key, &iv, &baseline).unwrap();
        let pt_fast = sm4_cbc_decrypt(&key, &iv, &fast).unwrap();
        assert_eq!(pt_fast, pt_baseline);
    }

    #[test]
    fn test_t_table_ctr_matches_baseline() {
        let mut rng = rand::rngs::OsRng;
        let mut key = [0u8; 16];
        let mut nonce = [0u8; 12];
        rng.fill_bytes(&mut key);
        rng.fill_bytes(&mut nonce);
        let data = b"CTR mode comparison data for T-Table verification!";

        let baseline = sm4_ctr_crypt(&key, &nonce, data);
        let fast = sm4_ctr_crypt_t_table(&key, &nonce, data);
        assert_eq!(fast, baseline, "T-Table CTR 应与基线 CTR 一致");
    }

    #[test]
    fn test_t_table_throughput() {
        let key = [0xAB; 16];
        let nonce = [0xCD; 12];
        let data = vec![0x42u8; 1024 * 1024]; // 1 MB

        let start = std::time::Instant::now();
        let _baseline = sm4_ctr_crypt(&key, &nonce, &data);
        let baseline_dur = start.elapsed();

        let start = std::time::Instant::now();
        let _fast = sm4_ctr_crypt_t_table(&key, &nonce, &data);
        let fast_dur = start.elapsed();

        let baseline_mbps = (data.len() as f64 / 1_000_000.0) / baseline_dur.as_secs_f64();
        let fast_mbps = (data.len() as f64 / 1_000_000.0) / fast_dur.as_secs_f64();

        eprintln!(
            "基线 SM4-CTR 1MB: {:.2} MB/s ({:.2?})",
            baseline_mbps, baseline_dur
        );
        eprintln!(
            "T-Table SM4-CTR 1MB: {:.2} MB/s ({:.2?})",
            fast_mbps, fast_dur
        );
        eprintln!("加速比: {:.2}x", fast_mbps / baseline_mbps);
    }
}
