# Sancove — 基于国密标准的保密文件库

> 基于 SM2/SM3/SM4 国密标准的加密文件保险箱。纯 Rust 实现，GUI/CLI 双模式。

[![构建与发布](https://github.com/sereinwalker/sancove/actions/workflows/release.yml/badge.svg)](https://github.com/sereinwalker/sancove/actions/workflows/release.yml)

---

## 📥 下载即用

从 [Releases](https://github.com/sereinwalker/sancove/releases) 下载 `sancove-windows-msvc.zip`，解压运行：

```bash
# 图形界面（推荐）
sancove.exe gui

# 命令行
sancove.exe --help
```

预编译二进制为 release 全优化，PBKDF2 密钥派生仅 ~278 ms，保险箱打开 ~293 ms。

---

## 🔐 核心特性

### 密码学引擎

| 功能 | 说明 |
|------|------|
| **SM4 加密** | GB/T 32907-2016 分组密码，CTR 流模式加密文件 + CBC 模式加密数据库 |
| **SM3 杂凑** | GB/T 32905-2016，256 位输出，用于 HMAC 和 PBKDF2 |
| **SM2 公钥密码** | GB/T 32918.2-2016 数字签名 + ECIES 加密，sm2p256v1 曲线 |
| **Bitslice 常数时间** | 128 路并行 u128 位平面 S-Box，抗缓存/时序侧信道攻击 |
| **PBKDF2-SM3** | 600k 迭代密钥派生，状态直操作优化 ~278 ms |
| **T-Table** | 4 预计算查找表加速比 ~1.19× |
| **HMAC-SM3** | 流式增量更新接口，常数时间比较 |
| **Shamir 秘密共享** | GF(256) Lagrange 插值，k/n 门限恢复 |

### 保险箱功能

| 功能 | 说明 |
|------|------|
| **双层密钥体系** | PBKDF2-SM3 派生 KEK → 加密 DEK → 加密文件，每文件独立 32B 真随机密钥 |
| **Encrypt-then-MAC** | 先 SM4-CTR 加密，再 HMAC-SM3 完整性标签 |
| **Verify-then-Decrypt** | 先常数时间验证 HMAC，再解密输出，拒绝篡改数据 |
| **盲哈希索引** | HMAC-SM3(DEK_mac, salt ‖ filename) 作为检索键，零知识存储 |
| **元数据加密** | 文件名、大小等信息加密后存入数据库 |
| **流式 I/O** | 64 KB 分块流水线，内存开销恒定，支持 GB 级文件 |
| **SQLite 安全加固** | WAL+NORMAL、secure_delete=ON、temp_store=MEMORY |
| **配置完整性** | 每项配置同步 HMAC 签名，打开/改密时校验防篡改 |
| **崩溃安全** | 事务写前自动备份回滚，异常时恢复原始数据库 |
| **安全擦除** | DoD 5220.22-M 标准 3 遍覆写（随机 → 全 0x00 → 全 0xFF） |
| **审计日志** | SM3 哈希链 + HMAC-SM3 双重完整性保护，可验证可导出 |

---

## 🖥️ GUI 概述

### 登录
选择保险箱目录 → 输入密码（支持显示/隐藏）→ 实时密码强度评估 → 打开或创建

### 主界面

工具栏（分组菜单）：

| 分组 | 功能 |
|------|------|
| **管理 ▼** | 修改密码、备份、KEK 分片 |
| **工具 ▼** | 刷新、公钥复制、审计日志、基准测试、SM2 签名/验签 |
| **导入 ▼** | 导入文件、导入文件夹 |
| **登出** | 返回登录（后台任务进行时禁用） |

文件列表：复选框多选 → 文件名 / 大小 / 导入时间 → 操作按钮（导出 / 导出并移除 / 改名 / 删除）

目录导航：虚拟目录树（/ 分隔），单击进入下层，返回上级链接。每行支持导出、剪切、改名、删除。

批量操作：选中文件后可批量导出、批量导出并移除（剪切）、批量删除。后台线程执行，实时显示进度。

### 对话框

| 对话框 | 说明 |
|--------|------|
| **修改密码** | 旧密码验证 + 新密码 ×2，所有 DEK 自动用新 KEK 重加密 |
| **基准测试** | 运行全产品性能基准（SM4/CBC/HMAC/PBKDF2/SM2/Shamir/I/O/保险箱打开/批量导入） |
| **审计日志** | 最近 500 条记录、哈希链验证、JSON 导出 |
| **SM2 签名/验签** | 文件数字签名与验证 |
| **KEK 分片** | 配置 n/t 参数，生成 Shamir 子秘密 hex |
| **KEK 恢复** | 输入 t 份子秘密 + 新密码，重构 KEK |

---

## ⌨️ CLI 命令参考

所有命令交互式密码输入，`sancove <命令> --help` 查看详细参数和别名。

| 命令 | 别名 | 说明 |
|------|------|------|
| `create` | `new` | 创建保险箱 |
| `list` | `ls` | 列出文件 |
| `import` | `add` | 导入文件 |
| `export` | `exp` | 导出文件（需盲索引） |
| `remove` | `rm` | 删除文件 |
| `rename` | `mv` | 重命名文件 |
| `cut` | — | 剪切（导出并删除） |
| `import-folder` | `import-dir` | 导入文件夹 |
| `export-directory` | `export-dir` | 导出目录到本地 |
| `remove-directory` | `rmdir` | 删除目录 |
| `rename-directory` | `mvdir` | 重命名目录 |
| `change-password` | `passwd` | 修改密码 |
| `split-kek [-n] [-t]` | `split` | Shamir 分片 |
| `recover-kek -t <子秘密...>` | `recover` | 从分片恢复 |
| `sm2-pubkey` | `pubkey` | 查看 SM2 公钥 |
| `sm2-sign` | `sign` | 文件签名 |
| `sm2-verify` | `verify-sig` | 验证签名 |
| `share-export` | `share` | 共享导出 |
| `share-import` | `share-in` | 共享导入 |
| `audit-log` | `audit` | 查看审计日志 |
| `audit-log-verify` | `audit-verify` | 验证日志完整性 |
| `audit-log-export` | `audit-export` | 导出日志 JSON |
| `backup` | `bak` | 备份保险箱 |
| `restore` | `rest` | 恢复保险箱 |
| `bench` | `benchmark` | 性能基准 |
| `gui [目录]` | — | 启动 GUI |

---

## 🔒 安全设计

| 层级 | 技术 |
|------|------|
| **密码派生** | PBKDF2-SM3，600,000 次迭代（OWASP 推荐值），SM3 状态直操作优化 |
| **密钥体系** | KEK/DEK 双层分离，KEK 加密 DEK，DEK 加密文件 |
| **文件加密** | SM4-CTR 流模式 + 每文件独立 32B DEK，Encrypt-then-MAC (HMAC-SM3) |
| **数据库加密** | SM4-CBC，PKCS#7 填充 + 常数时间填充验证 |
| **完整性** | HMAC-SM3 常数时间 volatile XOR 比较，Verify-then-Decrypt |
| **元数据** | 盲哈希索引 HMAC(DEK_mac, salt ‖ filename) + 密文存储 |
| **SQLite** | WAL+NORMAL、mmap_size=0、secure_delete=ON、temp_store=MEMORY |
| **配置完整性** | vault_config 每项写入同步 HMAC 签名，打开/改密校验 |
| **内存** | ZeroizeOnDrop 自动零化密钥 + write_volatile + compiler_fence |
| **文件擦除** | DoD 5220.22-M 3 遍覆写 |
| **审计日志** | SM3 哈希链 + HMAC-SM3(KEK) 双重防护 |

---

## 📁 项目结构

```
sancove/
├── Cargo.toml
├── README.md
├── .github/workflows/
│   └── release.yml              # CI 自动构建
├── src/
│   ├── main.rs                  # CLI 入口（27 个子命令，含别名）
│   ├── lib.rs
│   ├── bench.rs                 # 内建基准测试（9 类 22+ 项指标）
│   ├── db.rs                    # SQLite 数据层（SAVEPOINT 嵌套事务）
│   ├── vault/                   # 保险箱核心业务逻辑
│   │   ├── core.rs              # 创建/打开/保存
│   │   ├── import.rs            # 导入（含文件夹/共享导入）
│   │   ├── export.rs            # 导出（Verify-then-Decrypt）
│   │   ├── files.rs             # 文件列表/删除/重命名
│   │   ├── manage.rs            # 改密/备份/恢复/事务
│   │   ├── helpers.rs           # KEK 派生/SM2 密钥存储
│   │   ├── internal.rs          # DEK 解密/元数据解密
│   │   ├── interface.rs         # SM2 签名/审计/Shamir 接口
│   │   ├── error.rs             # 错误类型
│   │   └── tests.rs             # 集成测试
│   ├── gui/                     # egui 图形界面
│   │   ├── app.rs / login.rs / layout.rs
│   │   ├── dialogs.rs / ops.rs / update.rs
│   │   ├── task.rs / types.rs / icons.rs
│   ├── audit_log/               # 哈希链 + HMAC 审计日志
│   └── crypto/                  # 国密算法实现
│       ├── sm3.rs               # SM3 + HMAC + PBKDF2
│       ├── sm4_ctr.rs           # SM4 核心 + CBC/CTR/T-Table
│       ├── sm4_bitslice.rs      # SM4 常数时间 bitslice
│       ├── sm2.rs               # SM2 签名/验证
│       ├── shamir.rs            # Shamir 秘密共享
│       ├── password_strength.rs # 密码强度评估
│       ├── secure_erase.rs      # 安全文件擦除
│       └── secure_eq.rs         # 常数时间比较
```

---

## 🛠️ 从源码编译

需要 [Rust 工具链](https://rustup.rs/)（1.75+）。

```bash
git clone https://github.com/sereinwalker/sancove.git
cd sancove

cargo build --release            # release 构建
cargo run --release -- gui       # 启动 GUI
cargo test                       # 运行 200+ 测试
cargo test --release             # release 模式测试（含常数时间验证）
```

---

_基于 SM2/SM3/SM4 国密标准的保密文件库 — 密码学课程大作业_
