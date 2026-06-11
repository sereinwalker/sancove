# Sancove — 基于国密算法的保密文件库

## 项目报告

---

## 一、项目背景与目标

### 1.1 背景

随着信息安全的日益重要，国家密码管理局发布了 SM3（杂凑算法）和 SM4（分组密码算法）等国密标准。然而，现有加密工具大多基于国际算法（AES、SHA 等），缺乏对国密算法的原生支持。本项目旨在从零实现 SM3 和 SM4 算法，并构建一个完整的保密文件库系统。

### 1.2 目标

- **纯软件实现**：不依赖任何第三方加密库（除数值计算外），从数学原理出发实现 SM3/SM4
- **安全架构**：设计 KEK/DEK 双层密钥体系，实现零知识元数据保护
- **生产可用**：支持文件导入/导出/列表/移除的完整生命周期管理
- **流式加密**：64 KB 分块流水线，支持 GB 级文件
- **认证加密**：Encrypt-then-MAC 协议（SM4-CTR + HMAC-SM3）
- **性能优化**：通过 T-Table 等技术优化 SM4 性能
- **用户界面**：提供 CLI 和 GUI 两种交互方式，支持拖放导入
- **密码安全**：内置密码强度在线评估

### 1.3 技术栈

| 层面     | 技术选型                                  |
| -------- | ----------------------------------------- |
| 编程语言 | Rust 2024 edition                         |
| 密码算法 | SM3 (杂凑) + SM4 (分组密码)，纯 Rust 实现 |
| 存储层   | SQLite (rusqlite, bundled)                |
| GUI 框架 | egui / eframe 0.27                        |
| 序列化   | serde + bincode                           |
| 内存保护 | zeroize (ZeroizeOnDrop)                   |

---

## 二、国密算法实现

### 2.1 SM3 密码杂凑算法

SM3 是中国国家密码管理局发布的密码杂凑算法标准，输出 256 位（32 字节）杂凑值。

**核心参数**：

- 消息分组：512 位（64 字节）
- 输出长度：256 位（32 字节）
- 压缩轮数：64 轮
- 初始值 IV：`7380166f 4914b2b9 172442d7 da8a0600 a96f30bc 163138aa e38dee4d b0fb0e4e`

**实现结构**：

```
消息填充 (M||1||0||L) → 分组 (16×32bit) → 消息扩展 (132×32bit) → 64轮压缩
```

**消息扩展**：将 16 个消息字 `W[0..15]` 扩展为 132 个字 `W[0..67]` + `W'[0..63]`：

```
W[j] = P₁(W[j-16] ⊕ W[j-9] ⊕ ROTL₁₅(W[j-3])) ⊕ ROTL₇(W[j-13]) ⊕ W[j-6]    (16 ≤ j ≤ 67)
W'[j] = W[j] ⊕ W[j+4]                                                      (0 ≤ j ≤ 63)
```

**压缩函数**（64 轮）：

```
SS1 = ROTL₇(ROTL₁₂(A) + E + ROTL₂₀(Tⱼ))
SS2 = SS1 ⊕ ROTL₁₂(A)
TT1 = FFⱼ(A,B,C) + D + SS2 + W'[j]
TT2 = GGⱼ(E,F,G) + H + SS1 + W[j]
D = C; C = ROTL₉(B); B = A; A = TT1
H = G; G = ROTL₁₉(F); F = E; E = P₀(TT2)
```

**布尔函数**：

```
FFⱼ(A,B,C) = A⊕B⊕C          (0 ≤ j ≤ 15)   // 异或
FFⱼ(A,B,C) = (A∧B)∨(A∧C)∨(B∧C)  (16 ≤ j ≤ 63)  // 多数投票

GGⱼ(E,F,G) = E⊕F⊕G          (0 ≤ j ≤ 15)   // 异或
GGⱼ(E,F,G) = (E∧F)∨(¬E∧G)  (16 ≤ j ≤ 63)  // 选择函数
```

**置换函数**：

```
P₀(X) = X ⊕ ROTL₉(X) ⊕ ROTL₁₇(X)    // 压缩函数内使用
P₁(X) = X ⊕ ROTL₁₅(X) ⊕ ROTL₂₃(X)   // 消息扩展使用
```

**衍生实现**：

- **HMAC-SM3**：基于 SM3 的哈希消息认证码，采用 `ipad`/`opad` 构造，支持流式增量更新
- **PBKDF2-SM3**：基于 RFC 2898 的密码派生函数，支持任意输出长度。优化实现绕过 Sm3 结构体，直接操作 `[u32; 8]` 状态数组和预计算 padding 块，消除迭代热路径中的 clone/drop/zeroize 开销。600k 次迭代 ~278 ms（release）。

### 2.2 SM4 分组密码算法

SM4 是中国国家密码管理局发布的分组密码算法标准，分组长度 128 位，密钥长度 128 位。

**核心参数**：

- 分组大小：128 位（16 字节）
- 密钥长度：128 位（16 字节）
- 加密轮数：32 轮
- 轮密钥：32 个 32 位字（从 128 位密钥扩展生成）

#### 2.2.1 密钥扩展

```
(K₀, K₁, K₂, K₃) = key XOR FK
r_k[i] = K_{i+4} = K_i ⊕ T'(K_{i+1}⊕K_{i+2}⊕K_{i+3}⊕CK[i])
```

其中 `FK` 为系统参数，`CK` 为固定常数，`T'` 为非线性变换（S-Box）+ 线性变换 L'。

#### 2.2.2 轮函数

```
X_{i+4} = X_i ⊕ T(X_{i+1}⊕X_{i+2}⊕X_{i+3}⊕rk[i])
```

其中 `T(·)` = 非线性变换 `τ(·)`（4 个 S-Box 并行）+ 线性变换 L：

```
L(B) = B ⊕ ROTL₂(B) ⊕ ROTL₁₀(B) ⊕ ROTL₁₈(B) ⊕ ROTL₂₄(B)
```

#### 2.2.3 S-Box

SM4 使用一个 8×8 的 S-Box（16×16 查找表），基于仿射变换和逆映射构造。共 256 个字节。

#### 2.2.4 T-Table 优化

T-Table 将轮函数中的 S-Box 查找和线性变换 L 合并为 4 个预计算查找表（每表 256 个 32 位字）：

```
T0[x] = (S[x] << 24) | (S[x] << 16) | (S[x] << 8) | S[x]   (经 L 变换旋转)
```

每轮加密从 4 个表中各查一个值并异或，将 4 次 S-Box 查找 + L 变换合并为 4 次 T-Table 查找。

**Bitslice 实现**（128 路并行常数时间）：

bitslice SM4 将 128 个 16 字节块编码为比特平面（每个 `u128` 保存 128 个块的同一比特位），S-Box 通过逐项位匹配覆盖全部 256 个候选值，确保无数据依赖的缓存访问。关键优化包括 S-Box 256 个输出值的预先 `u128` 位平面展开（消除运行时 `wrapping_neg()` 调用）、8 位比较循环手动展开、转置函数使用 u32 字加载代替逐字节操作。

Bitslice 不是 GB/T 32907-2016 定义的标准实现方式（标准附录直接给出 S-Box 查表），但输出完全等价——仅用于基准性能对比，不参与 vault 生产加密路径。

**基准测试结果（release 模式）**：

| 实现方式               | 吞吐量     |
| ---------------------- | ---------- |
| 基线 32 轮循环 + S-Box | 116 MB/s   |
| T-Table 优化           | 139 MB/s   |
| 加速比                 | **1.19×**  |

### 2.3 加密模式

#### CBC 模式（元数据加密）

- 用于加密 DEK（数据加密密钥）和文件元数据信封
- PKCS#7 填充（始终至少填充 1 字节）
- 常数时间填充验证（防 Padding Oracle 攻击）

#### CTR 模式（文件加密）

- 96-bit 随机 nonce + 32-bit 大端计数器（从 1 开始）
- 流密码化，无需填充（消除 Padding 侧信道）
- 同一密钥下 IV 不可重用（RFC 3686 约束）
- 最大安全加密量：2³²-1 个块（约 64 GB）

#### Encrypt-then-MAC 协议（文件完整性保护）

```
加密：C = SM4-CTR_enc(DEK_enc, nonce, P)
标签：T = HMAC-SM3(DEK_mac, nonce || C)
验证：T' ≟ T  (常数时间比较)
解密：P = SM4-CTR_dec(DEK_enc, nonce, C)
```

---

## 三、系统架构

### 3.1 四层架构图

```
┌──────────────────────────────────────────────┐
│ Layer 4: 表现层                              │
│   CLI (clap 命令行)   │   GUI (egui 图形界面) │
├──────────────────────────────────────────────┤
│ Layer 3: 业务层                              │
│   Vault 核心控制 (创建/打开/导入/导出/移除)   │
│   KEK/DEK 密钥管理   │   Verify-then-Decrypt │
├──────────────────────────────────────────────┤
│ Layer 2: 密码引擎                            │
│   SM4 (基线 + T-Table) │ SM3 (HMAC/PBKDF2)  │
│   CTR/CBC 模式        │   常数时间比较       │
├──────────────────────────────────────────────┤
│ Layer 1: 数据层                              │
│   SQLite (安全 PRAGMA) │   盲哈希索引        │
│   元数据密文信封       │   文件系统存储       │
└──────────────────────────────────────────────┘
```

### 3.2 双层密钥系统 (KEK/DEK)

```
用户密码 ──PBKDF2-SM3──→ KEK (16B) ──SM4-CBC──→ 加密后 DEK (存数据库)
                                                          │
OsRng (系统真随机数) ──────→ DEK (32B) ←───────────────────┘
                                ├── DEK_enc[0..16] ──SM4-CTR──→ 文件密文
                                └── DEK_mac[16..32] ─HMAC-SM3──→ 完整性标签
```

- **KEK (Key Encryption Key)**：由用户密码通过 PBKDF2-SM3（600,000 次迭代，OWASP 2023 推荐值）派生，用于加密每个文件的 DEK
- **DEK (Data Encryption Key)**：每个文件独立生成 32 字节真随机数
- **密钥封装**：DEK 被 KEK 用 SM4-CBC 加密后存入 SQLite

### 3.3 SQLite 零知识存储

| 字段                 | 说明                                                       |
| -------------------- | ---------------------------------------------------------- |
| `blind_index` (PK)   | HMAC-SM3(DEK_mac, Vault_Salt\|\| Filename) — 32 字节盲哈希 |
| `iv`                 | 12 字节 CTR 模式 nonce                                     |
| `dek_iv`             | DEK 加密 IV（16 字节）                                     |
| `encrypted_dek`      | SM4-CBC(KEK, IV, DEK)                                      |
| `encrypted_metadata` | SM4-CBC(DEK_enc, IV_meta, FileMetadata)                    |
| `hmac_tag`           | HMAC-SM3(DEK_mac, nonce\|\| ciphertext)                    |

**安全加固 PRAGMA**：

- `journal_mode=WAL` + `synchronous=NORMAL`（WAL 模式，读写不互斥）
- `mmap_size=0`（禁用内存映射，防止物理页泄露）
- `temp_store=MEMORY`（临时表建在内存中）
- `secure_delete=ON`（删除记录时覆写磁盘）
- `auto_vacuum=INCREMENTAL`（增量回收空间）
- `busy_timeout=5000`（等待锁超时 5 秒）

**配置完整性保护**（`config_hmac` 表）：

- `vault_config` 表中存储库级配置（盐值、密码验证标签等）
- 每项配置写入时同步计算 HMAC-SM3(KEK, key || value) 并存入 `config_hmac` 表
- 打开保险箱时验证 HMAC，检测到篡改立即拒绝访问
- 修改密码时重新计算并存储所有配置项的 HMAC

### 3.4 异步 GUI 模型

```
UI 线程 (egui update)              后台线程 (std::thread::spawn)
┌─────────────────────┐           ┌─────────────────────────┐
│  点击"导入"          │ ──触发──→ │  lock(Mutex<Vault>)     │
│  显示 Spinner        │           │  sm4_ctr_encrypt(file)  │
│  ctx.request_repaint│ ←─完成── │  hmac_sm3 integrity     │
│  显示结果 ✓/✗        │           │  unlock(Mutex<Vault>)   │
└─────────────────────┘           └─────────────────────────┘
```

文件导入导出在后台线程执行，通过 `Arc<Mutex<...>>` 跨线程传递进度状态，`ctx.request_repaint()` 触发 UI 更新。

### 3.5 流式 I/O 模型

```
导入: 源文件 ──read(64KB)──→ SM4-CTR 加密 ──HMAC 增量──→ 写入加密文件
导出: 加密文件 ──read(64KB)──→ HMAC 增量 ──验证通过──→ SM4-CTR 解密 ──write──→ 输出文件
```

- **64 KB 分块缓冲区**：内存开销恒定，与文件大小无关
- **流式 HMAC**：`HmacSm3` 状态机增量更新，不缓存全文件
- **零拷贝 CTR 变换**：`sm4_ctr_transform` 原地 XOR 密钥流到缓冲区

### 3.6 密码强度评估

创建和修改密码时实时评估强度：

- **熵值计算**：log₂(字符集大小^长度)
- **字符类别**：小写/大写/数字/特殊字符组合检测
- **模式检测**：连续序列（abc/321）、重复字符（aaa）、键盘序列（qwerty）
- **弱口令过滤**：Top 50 常见密码黑名单

---

## 四、安全分析

### 4.1 侧信道防护

| 攻击向量           | 防护措施                                                 |
| ------------------ | -------------------------------------------------------- |
| **时序侧信道**     | 常数时间比较（`volatile` XOR 累加，无分支）              |
| **Cache 时序**     | T-Table 实现由 bitslice 常数时间 S-Box 覆盖（bench 对比），生产 vault 路径使用 T-Table（桌面单用户安全上下文可接受） |
| **Padding Oracle** | CTR 模式无填充；CBC 仅用于数据库包裹加密且统一错误消息   |
| **内存提取**       | `ZeroizeOnDrop` + `write_volatile` + `compiler_fence`    |

### 4.2 密钥安全

- **KEK/DEK 分离**：即使数据库泄露，攻击者仍需破解密码（PBKDF2-SM3）才能获得 KEK
- **每文件独立 DEK**：一个 DEK 泄露不影响其他文件
- **PBKDF2 迭代**：600,000 次 SM3 迭代（OWASP 2023 推荐值）大幅增加暴力破解成本
- **域隔离盐值**：每个保险箱有独立 `vault_salt`，防彩虹表

### 4.3 完整性保护

- **Encrypt-then-MAC**：先加密后计算 HMAC，防止选择密文攻击
- **Verify-then-Decrypt**：先验证 HMAC 再解密，拒绝篡改数据
- **常数时间 HMAC 比较**：防止通过时序差异逐字节伪造标签
- **配置 HMAC 完整性**：vault_config 每项写入同步计算 HMAC-SM3(KEK, key || value)，打开和改密时校验，防御配置篡改攻击

### 4.4 存储安全

- **零知识盲索引**：文件名经 HMAC-SM3 哈希后作为检索键，服务器无法得知文件名
- **元数据加密**：文件名、文件大小等信息均加密存储
- **SQLite 安全模式**：禁用 WAL/Journal 防止数据残留

### 4.5 已知局限

- **T-Table MemJam 攻击**：在 Intel CPU 上，T-Table 实现可能受 4K 别名缓存时序攻击。本项目的 T-Table 主要用于性能基准对比，生产推荐使用 bitslice 实现
- **密码强度依赖**：最终安全性取决于用户密码强度
- **无前向安全**：KEK 泄露后，所有文件可被解密（需部署周期性密钥轮换）

---

## 五、性能基准测试

内建基准测试覆盖 **9 大类别、22 项指标**，GUI 和 CLI 双模式展示，无需外部工具。

### 5.1 测试环境

| 项目     | 规格                             |
| -------- | -------------------------------- |
| CPU      | Intel (MinGW64, Windows 11)      |
| 编译模式 | `cargo build --release`          |
| 框架     | Rust 内建 `run_all_benches()` + `run_io_benches()` |

### 5.2 SM4 加密吞吐量（1MB 数据）

| 实现方式               | 吞吐量       | 加速比 |
| ---------------------- | ------------ | ------ |
| 基线 32 轮 + S-Box     | 116.3 MB/s   | 1.00×  |
| T-Table 优化           | 138.6 MB/s   | 1.19×  |
| 常数时间 bitslice (4KB)| 6765.8 KB/s  | —      |

### 5.3 SM4-CBC 密钥包裹（KEK 路径，1MB 数据）

| 操作   | 吞吐量    |
| ------ | --------- |
| 加密   | 150.0 MB/s |
| 解密   | 125.1 MB/s |

### 5.4 HMAC-SM3 完整性校验（1MB 数据）

| 吞吐量    |
| --------- |
| 319.4 MB/s |

### 5.5 PBKDF2-SM3 密钥派生

采用 HMAC ipad/opad 状态预计算优化（RFC 2104），固定密码时内层 HMAC 块压缩从 4 次降至 2 次。

| 迭代次数       | 耗时 (release) |
| -------------- | -------------- |
| 100,000        | 45 ms          |
| 600,000 (当前) | 278 ms         |

### 5.6 SM2 公钥密码

| 操作     | 耗时   |
| -------- | ------ |
| 密钥生成 | 2.1 ms |
| 签名     | 1.8 ms |
| 验签     | 3.1 ms |

### 5.7 Shamir 秘密共享（KEK 灾备）

| 操作       | 耗时    |
| ---------- | ------- |
| 5-of-3 分片| 37.3 μs |
| 3 份恢复   | 1.2 μs  |

### 5.8 全链路文件操作（含加解密 + HMAC）

| 文件大小 | 导入       | 导出       |
| -------- | ---------- | ---------- |
| 1 KB     | 1299.3 μs  | 1685.9 μs  |
| 1 MB     | 26.1 ms    | 15.3 ms    |
| 10 MB    | 555.3 ms   | 130.3 ms   |
| 批量 10×1MB | 342.5 ms | —          |

> **注**：SM4-CTR 流式加密在小文件（1KB）上系统调用开销占主导（文件打开/关闭、SQLite BLOB I/O 等），g 级文件 I/O 占主导。10MB 导入较慢因加密过程与 SQLite BLOB 写入交织。

### 5.9 保险箱操作

| 操作           | 耗时  |
| -------------- | ----- |
| 打开（登录）   | 293 ms |

> 打开耗时 = PBKDF2（~278 ms）+ SQLite 配置读取 + 配置 HMAC 逐项校验 + SM2 密钥加载 + 审计日志初始化。PBKDF2 优化（状态直操作绕过 Sm3 clone/drop）从 ~304ms 降至 ~278ms。

## 六、项目结构

```
sancove/
├── Cargo.toml                  # 项目配置与依赖
├── REPORT.md                   # 项目报告（本文档）
├── README.md                   # 项目首页说明
├── .github/workflows/
│   └── release.yml             # GitHub Actions 自动构建发布
├── .cargo/config.toml          # Cargo 别名 (cargo gui)
├── src/
│   ├── main.rs                 # CLI 入口（clap 约 20 子命令）
│   ├── lib.rs                  # 库入口（6 个模块导出）
│   ├── bench.rs                # 内建基准测试（全产品覆盖 9 类 22+ 项指标）
│   ├── db.rs                   # SQLite 数据层（SAVEPOINT 嵌套事务）
│   ├── vault/                   # 保险箱核心业务逻辑（10 子模块）
│   │   ├── mod.rs              # Vault 结构体 + 子模块导出
│   │   ├── core.rs             # 创建/打开/保存
│   │   ├── import.rs           # 文件/文件夹/共享导入
│   │   ├── export.rs           # 文件导出（Verify-then-Decrypt）
│   │   ├── files.rs            # 列表/删除/重命名
│   │   ├── manage.rs           # 改密/备份/恢复/事务
│   │   ├── helpers.rs          # KEK 派生/SM2 密钥存储
│   │   ├── internal.rs         # DEK 解密/元数据解密/消毒
│   │   ├── interface.rs        # SM2 签名/审计/Shamir 接口
│   │   ├── error.rs            # VaultError 类型
│   │   └── tests.rs            # 集成测试
│   ├── gui/
│   │   ├── mod.rs              # GUI 模块导出
│   │   ├── app.rs              # 应用主窗口 + 线程池管理
│   │   ├── login.rs            # 登录界面
│   │   ├── layout.rs           # 主界面布局（工具栏 + 文件表格）
│   │   ├── dialogs.rs          # 对话框（改密/备份/SM2/共享/基准）
│   │   ├── ops.rs              # 后台批量操作
│   │   ├── update.rs           # UI 状态更新 + 通知
│   │   ├── task.rs             # 后台任务管理 + 进度跟踪
│   │   ├── types.rs            # 类型定义 + 常量
│   │   └── icons.rs            # 跨平台图标系统
│   ├── audit_log/
│   │   ├── mod.rs              # 哈希链 + HMAC 审计日志
│   │   ├── error.rs            # 错误类型（ChainBroken/Corrupt）
│   │   └── export.rs           # JSON 导出
│   └── crypto/
│       ├── mod.rs              # 密码模块导出
│       ├── sm3.rs              # SM3 杂凑 + HMAC + PBKDF2（状态直操作优化）
│       ├── sm4_ctr.rs          # SM4 分组密码 + CBC/CTR + T-Table
│       ├── sm4_bitslice.rs     # SM4 常数时间 bitslice（u128 位平面优化）
│       ├── sm2.rs              # SM2 签名/加密（GB/T 32918.2+4）
│       ├── shamir.rs           # Shamir 秘密共享（GF(256) Lagrange）
│       ├── password_strength.rs# 密码强度评估
│       ├── secure_erase.rs     # 安全文件擦除（DoD 3 遍）
│       └── secure_eq.rs        # 常数时间比较（volatile XOR）
```

## 七、使用说明

### 7.1 终端用户 — 下载预编译二进制

从 GitHub Releases 下载 ZIP，解压即用：

```bash
# 图形界面
sancove.exe gui

# 命令行模式
sancove.exe --help
```

### 7.2 开发者 — 从源码编译

```bash
# 日常开发（debug 模式，编译快）
cargo build
cargo test

# 日常使用 GUI（release 模式，运行快）
cargo gui

# CLI 模式
cargo run --release -- create /path/to/vault
cargo run --release -- import /path/to/vault file.txt
cargo run --release -- list /path/to/vault
cargo run --release -- export /path/to/vault <blind_index_hex> /output/dir

# 环境变量指定密码（否则交互式输入）
export VAULT_PASS="your_password"
```

> **为什么分两种模式**：debug 编译快（~2s 增量）适合开发迭代，release 运行快（PBKDF2 ~304 ms, SM4 106 MB/s）适合日常使用。终端用户从 Releases 下载的一律是 release 版本。

启动 GUI 后进入登录界面：

1. 输入保险箱存储目录路径和密码
2. 点击"创建"新建保险箱或"打开"加载已有保险箱
3. 主界面展示文件列表，支持导入/导出/移除操作
4. 批量操作（多选导入/导出/移除）

### 7.3 运行测试

```bash
cargo test                # 所有 200+ 测试（debug 模式，编译快）
cargo test --release      # release 模式（含常数时间 SM4 全链路测试）
cargo test sm3            # 特定模块测试
```

---

## 八、总结与展望

### 项目亮点

#### 🔐 密码算法（纯 Rust 实现，不依赖 OpenSSL）

- **SM3 杂凑算法**：完整实现国标 GB/T 32905，64 轮压缩函数，输出 256 位
- **SM4 分组密码**：三种实现（基线 124 MB/s / T-Table 146 MB/s / 常数时间 bitslice），支持 CTR/CBC 模式
- **SM2 数字签名**：GB/T 32918.2-2016，sm2p256v1 曲线，确定性 k（RFC 6979 风格），45 项测试
- **Shamir 秘密共享**：GF(256) 有限域，Lagrange 插值 k/n 门限恢复
- **PBKDF2-SM3**：基于 RFC 2898 的密码派生函数，HMAC ipad/opad 预计算优化，600k 迭代仅 ~304 ms

#### 🏰 安全架构

- **KEK/DEK 双层密钥**：用户密码派生 KEK → KEK 加密每文件独立 DEK → DEK 加密文件内容，一个 DEK 泄露不影响其他文件
- **Encrypt-then-MAC 协议**：先 SM4-CTR 加密，再 HMAC-SM3 完整性标签，抵御选择密文攻击
- **Verify-then-Decrypt 协议**：导出时先常数时间验证 HMAC，通过后再解密输出，拒绝篡改数据
- **盲哈希索引**：HMAC-SM3(DEK_mac, salt ‖ filename) 作为检索键，零知识存储，元数据加密
- **配置完整性**：vault_config 每项写入同步 HMAC-SM3(KEK, key ‖ value) 签名，打开/改密时校验防篡改

#### 🛡️ 侧信道防护

- **常数时间比较**：`write_volatile` XOR 累加，无分支数据依赖，防时序侧信道
- **内存零化**：`ZeroizeOnDrop` 自动零化密钥 + `compiler_fence`，登录密码跨线程零化
- **Padding Oracle 防御**：CTR 模式无填充；CBC 仅用于元数据且统一错误消息
- **常数时间 SM4**：全扫描掩码 S-Box（256 项全遍历），无缓存时序泄露（release 模式验证）

#### ⚡ 性能优化

- **T-Table 查表优化**：4 预计算查找表替代 S-Box + 线性变换 L，加速比 1.19×
- **PBKDF2 ipad/opad 状态预计算**：固定密码时内层 HMAC 块压缩从 4 次降为 2 次，600k 迭代 ~353 ms
- **HMAC 零拷贝**：`HmacSm3` 流式状态机增量更新，消除 3 处临时 Vec 分配
- **流式 I/O**：64 KB 分块流水线（read → CTR 加密 → HMAC → write），内存开销恒定，支持 GB 级文件
- **内建全产品基准测试**：9 大类 22+ 项指标，覆盖 SM4 三种实现对比、SM4-CBC 密钥包裹、HMAC-SM3 吞吐、PBKDF2 多档迭代、SM2 密钥生成/签名/验签、Shamir 微秒级分片/恢复、全链路多尺寸文件 I/O（1KB/1MB/10MB）、批量导入、保险箱打开登录，GUI/CLI 双模式展示

#### 🗄️ 存储层

- **SQLite 安全加固**：WAL + NORMAL、`mmap_size=0`、`secure_delete=ON`、`temp_store=MEMORY`、`auto_vacuum=INCREMENTAL`
- **SAVEPOINT 嵌套事务**：批量操作两阶段提交（先逐项操作 → 全部成功时释放），消除 N+1 lock/unlock 竞争
- **崩溃安全写入**：写前自动备份，写入异常时原地恢复，防止写中断数据库损坏
- **安全擦除**：DoD 5220.22-M 标准 3 遍覆写（随机 → 全 0x00 → 全 0xFF）

#### 📋 审计日志

- **双重完整性保护**：SM3 哈希链（`prev_hash` 链接） + HMAC-SM3(KEK) 摘要，防篡改可验证
- **目录操作逐文件记录**：导出/删除目录时逐文件写入审计日志（数据库完整存储），GUI 100 字符截断防界面阻塞
- **模块重构**：新增 `Corrupt` 错误变体区分数据损坏与链篡改；集中式 `log_audit_event` 消除重复代码
- **JSON 导出**：审计日志可导出为 JSON，时间戳 chrono 格式友好展示

#### 🖥️ 图形界面（egui）

- **双模式交互**：CLI（clap 约 20 子命令）+ egui GUI，拖放导入批量操作
- **目录导航**：虚拟目录树浏览，单击导航、面包屑路径、创建/删除/重命名/剪切目录
- **文件夹剪切**：一键导出并移除目录，递归处理子目录，保持文件结构，逐文件审计
- **批量操作**：多选导入/导出/移除，显示 X/Y 进度，后台线程不阻塞 UI
- **暗色模式**：工具栏一键切换深色/浅色主题
- **密码强度指示器**：实时熵值计算 + 字符类别 + 模式检测 + 弱口令黑名单
- **内建基准面板**：GUI 内实时展示全产品性能（SM4 三种实现/SM4-CBC/HMAC/PBKDF2/SM2 签名/Shamir/多尺寸全链路 I/O/批量导入/保险箱打开），可滚动展示，支持一键复制结果
- **SM2 共享**：用对方 SM2 公钥加密 DEK 生成共享包，支持导入/导出
- **灾备恢复**：Shamir 子秘密重构 KEK 并设置新密码（GUI 对话框）
- **跨平台图标系统**：统一 emoji 图标封装 `gui/icons.rs`，单源修改全局生效
- **光标模式**：默认箭头光标，I-beam 仅显示在可编辑文本区域

#### ✅ 代码质量

- **200 项测试**：release 模式全部通过，3 ignored（常数时间 SM4 长测试），0 失败
- **编译零警告**：`cargo clippy` 零 dead_code、零 collapsible_if
- **三轮全面代码复审**：7 维度（性能/逻辑/冗余/命名/常量/注释/跨模块）覆盖全部 30+ 源文件，累计修复 30+ 项问题
- **事务原子性审计**：全链路事务正确性验证（拖放导入、批量操作、单文件导出、文件夹导航）
- **DB 层重构**：共享 `apply_safe_pragmas` 消除重复 PRAGMA 配置

#### 🚀 工程化

- **自动构建发布**：GitHub Actions 标签推送自动 `cargo build --release` → ZIP 打包 → GitHub Release
- **cargo gui 别名**：一行命令启动 release GUID
- **README + REPORT**：完整的中文项目文档

### 未来改进方向

- **流式导出零缓冲**：分块 HMAC 使导出阶段也彻底流式化（当前导出需两遍扫描——先校验全量 HMAC，再解密）
- **文件版本管理/增量备份**：保留文件历史版本，支持按时间点恢复
- **云存储集成**：将加密文件同步到对象存储，本地仅保留索引
- **SM2 加密/解密集成到 CLI/GUI**：当前 SM2 加密/解密仅库级 API 可用，CLI/GUI 未公开
- **SM4-GCM 标准模式**：CTR+HMAC 已实现等价认证加密安全，GCM 模式可作为标准合规选项添加
- **Boomslice AVX2**：当前 bitslice 为 128 路 u128 标量实现，可引入 AVX2/AVX-512 指令集实现真正 SIMD bitslice S-Box

---

_本项目为密码学课程大作业，算法实现仅供学习和研究使用。_
