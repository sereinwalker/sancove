# Sancove — 基于国密算法的保密文件库

> Sanctuary · Cove — 密码学课程大作业项目

SM4/SM3 国密算法加密的保密文件保险箱，支持图形界面（egui）和命令行双模式。

[![构建与发布](https://github.com/YOUR_USERNAME/sancove/actions/workflows/release.yml/badge.svg)](https://github.com/YOUR_USERNAME/sancove/actions/workflows/release.yml)

---

## 目录

- [快速开始](#快速开始)
- [功能总览](#功能总览)
- [CLI 命令参考](#cli-命令参考)
- [GUI 使用指南](#gui-使用指南)
- [安全设计](#安全设计)
- [目录结构](#目录结构)
- [运行测试](#运行测试)

---

## 快速开始

### 👤 用户 — 下载即用

从 [Releases](https://github.com/YOUR_USERNAME/sancove/releases) 下载最新 `sancove-windows-msvc.zip`，解压后运行：

```bash
# 图形界面模式（推荐）
sancove.exe gui

# 命令行模式
sancove.exe --help
```

> 预编译二进制 = release 模式全优化，PBKDF2 密钥派生仅 ~278 ms，SM4-TT 加密达 140+ MB/s，保险箱打开约 293 ms。

### 🛠️ 开发者 — 从源码编译

需要 [Rust 工具链](https://rustup.rs/)（1.75+）。

```bash
# 克隆仓库
git clone https://github.com/YOUR_USERNAME/sancove.git
cd sancove

# 日常开发（debug 模式，编译快）
cargo build          # ≈2s 增量编译
cargo test           # 快速验证

# 日常使用 GUI（release 模式，运行快）
cargo gui            # 等价 cargo run --release -- gui

# 命令行模式
cargo run --release -- create /path/to/vault
cargo run --release -- import /path/to/vault file.txt
cargo run --release -- list /path/to/vault
```

---

## 功能总览

### 🔐 密码学引擎

| 功能 | 说明 |
|------|------|
| **SM3 哈希** | 国标 GB/T 32905 杂凑算法，输出 256 位（32 字节），纯 Rust 实现 |
| **HMAC-SM3** | 基于 SM3 的哈希消息认证码，流式增量更新接口 |
| **PBKDF2-SM3** | 基于 RFC 2898 的密码密钥派生函数，HMAC ipad/opad 预计算优化 |
| **SM4-CTR 加密** | 国标 GB/T 32907 分组密码，CTR 流模式（96-bit nonce + 32-bit counter） |
| **SM4-CBC 加密** | PKCS#7 填充，常数时间填充验证（防 Padding Oracle 攻击） |
| **T-Table 优化** | 4 预计算查找表替代 S-Box + 线性变换，加速比 ~1.19× |
| **PBKDF2-SM3** | SM3 状态直操作优化（绕过 Sm3 结构体 clone/drop），600k 次仅 ~278 ms |
| **SM2 签名/验证** | GB/T 32918.2-2016 数字签名，sm2p256v1 曲线，确定性 k（RFC 6979 风格） |
| **SM2 加密/解密** | 椭圆曲线集成加密方案（ECIES），密钥封装 + 数据封装 |
| **Shamir 秘密共享** | GF(256) 有限域，Lagrange 插值 k/n 门限恢复 |

### 🏦 保密文件库

| 功能 | 说明 |
|------|------|
| **双层密钥** | KEK（PBKDF2-SM3 密码派生）加密 DEK（每文件独立 32B 真随机数） |
| **Encrypt-then-MAC** | 先 SM4-CTR 加密，再 HMAC-SM3 计算完整性标签 |
| **Verify-then-Decrypt** | 导出时先验证 HMAC 常时比较，再解密输出 |
| **盲哈希索引** | HMAC-SM3(DEK_mac, salt ‖ filename) 作为检索键，零知识存储 |
| **元数据加密** | 文件名、大小等信息加密后存入数据库 |
| **SQLite 安全加固** | WAL+NORMAL 模式、`mmap_size=0`、`secure_delete=ON`、`temp_store=MEMORY` |
| **配置完整性** | `config_hmac` 表存储每项配置的 HMAC 签名，打开/改密时校验防篡改 |
| **流式 I/O** | 64 KB 分块流水线读/加密/写，内存开销恒定，支持 GB 级文件 |
| **事务保护** | SAVEPOINT 嵌套事务 + 批量操作两阶段提交，消除 N+1 lock/unlock 竞争 |
| **崩溃安全** | 写前自动备份回滚，写入异常时自动恢复原始数据库 |
| **安全擦除** | DoD 5220.22-M 标准 3 遍覆写（随机 → 全 0x00 → 全 0xFF） |
| **审计日志** | SM3 哈希链 + HMAC-SM3 双重完整性保护，日志可验证、可 JSON 导出，目录操作逐文件记录 |

### 🖥️ 图形界面

| 功能 | 说明 |
|------|------|
| **登录界面** | 保险箱路径选择 + 密码输入，支持创建/打开 |
| **文件列表** | 表格展示（文件名/大小/时间/盲索引），行级操作按钮 |
| **拖放导入** | 从文件管理器直接拖入文件批量导入 |
| **批量操作** | 多选文件批量导入/导出/移除，显示 X/Y 进度 |
| **文件夹导入** | 递归导入文件夹内所有文件 |
| **文件夹导航** | 虚拟目录树浏览，支持目录创建/删除/重命名/剪切 |
| **文件夹剪切** | 导出目录到本地文件系统后从保险箱移除，递归保持文件结构 |
| **SM2 共享** | 用对方 SM2 公钥加密 DEK，生成共享包导入导出 |
| **灾备恢复** | Shamir 子秘密重构 KEK 并设置新密码 |
| **密码强度** | 实时熵值计算 + 模式检测 + 弱口令过滤条 |
| **暗色模式** | 工具栏一键切换深色/浅色主题 |
| **基准面板** | 内建全产品性能基准（SM4/SM4-CBC/HMAC/PBKDF2/SM2/Shamir/全链路I/O/保险箱打开）
| **审计日志** | 查看/验证/导出审计日志记录，payload 超 100 字符截断展示 |
| **图标系统** | 跨平台 emoji 图标统一封装，单源修改全局生效 |
| **光标模式** | 默认箭头光标，I-beam 仅显示在可编辑文本区域 |

---

## CLI 命令参考

所有 CLI 命令通过交互式密码输入（隐藏回显），不支持无交互密码参数。

### ⚡ 基本操作

```bash
# 创建新保险箱（需输入密码 ×2 确认）
sancove create /path/to/vault

# 打开并列出保险箱文件
sancove list /path/to/vault

# 导入文件
sancove import /path/to/vault document.pdf

# 导入文件夹（递归）
sancove import-folder /path/to/vault ./my_docs/

# 导出文件（需盲索引）
sancove export /path/to/vault <64位hex盲索引> /output/dir

# 导出保险箱目录到本地文件系统
sancove export-directory /path/to/vault "work/docs" /output/dir

# 移除文件
sancove remove /path/to/vault <64位hex盲索引>

# 移除保险箱目录（含目录下所有文件）
sancove remove-directory /path/to/vault "work/docs"

# 重命名文件
sancove rename /path/to/vault <64位hex盲索引> "新文件名.pdf"

# 重命名保险箱目录
sancove rename-directory /path/to/vault "work/docs" "archive"

# 剪切文件（导出并删除）
sancove cut /path/to/vault <64位hex盲索引> /output/path
```

### 🔑 密码管理

```bash
# 修改保险箱密码
sancove change-password /path/to/vault

# 将 KEK 拆分为 Shamir 子秘密（n=5, t=3 表示 5 份中任意 3 份可恢复）
sancove split-kek /path/to/vault --n 5 --t 3

# 从 Shamir 子秘密重构 KEK 并设置新密码
sancove recover-kek /path/to/vault --t 3 --shares <hex1> <hex2> <hex3>
```

### 🔏 SM2 签名与共享

```bash
# 查看保险箱 SM2 公钥
sancove sm2-pubkey /path/to/vault

# 用 SM2 签名文件（输出 64 字节原始签名）
sancove sm2-sign /path/to/vault document.pdf signature.sig

# 验证 SM2 签名
sancove sm2-verify /path/to/vault document.pdf signature.sig

# 导出共享文件（用对方公钥加密 DEK）
sancove share-export /path/to/vault <64位hex盲索引> \
  <130字符hex公钥> share_package.dat

# 导入共享文件（用本 vault SM2 私钥解密 DEK）
sancove share-import /path/to/vault share_package.dat
```

### 📋 审计日志

```bash
# 查看最近 50 条审计日志
sancove audit-log /path/to/vault

# 验证审计日志完整性（哈希链 + HMAC）
sancove audit-log-verify /path/to/vault

# 导出审计日志为 JSON
sancove audit-log-export /path/to/vault audit_log.json
```

### 🗄️ 备份恢复

```bash
# 备份保险箱到指定目录
sancove backup /path/to/vault /backup/dir

# 从备份恢复保险箱（会覆盖目标目录，需确认）
sancove restore /backup/dir /path/to/vault
```

### 📊 基准测试

```bash
# 运行性能基准测试
sancove bench /path/to/vault
```

### 🎨 图形界面

```bash
# 启动 GUI（文件关联入口）
sancove gui /path/to/vault
```

---

## GUI 使用指南

### 登录界面

启动 `sancove gui` 后进入登录界面：

1. **目录选择** — 输入或粘贴保险箱存储路径
2. **密码输入** — 隐藏回显输入，支持 👁️ 切换可见性
3. **密码强度条** — 实时显示熵值、字符类别、模式检测评分
4. **创建/打开** — 点击"创建保险箱"新建（需二次确认密码）或"打开"进入

> 密码强度评估实时检测：字符类别组合、连续序列（abc/321）、重复字符（aaa）、键盘序列（qwerty）、Top 50 弱口令黑名单。

### 主界面

登录成功后进入文件管理主界面。

**工具栏（顶栏）：**

| 按钮 | 功能 |
|------|------|
| 📂 | 打开保险箱目录（文件管理器） |
| 🔄 | 刷新文件列表 |
| 🖤/☀️ | 切换暗色/浅色主题 |
| 🔑 | 查看/复制 SM2 公钥 |
| ⏱️ | 运行性能基准测试 |
| 📋 | 查看审计日志 |
| 🔐 | 修改保险箱密码 |
| 💾 | 备份保险箱 |
| 📤 | 恢复保险箱 |
| ↔️ | 导出共享文件 |
| 分割 | 生成 Shamir 子秘密 |
| 🚪 | 登出返回登录界面 |

**文件列表（表格）：**

| 列 | 说明 |
|----|------|
| 文件名 | 可重命名（双击编辑），支持目录层级导航 |
| 大小 | 自动换算 B/KB/MB |
| 创建时间 | 时间戳显示 |
| 盲索引（前 16 位） | 用于 CLI 导出 |
| 操作 | 📤导出 / 🗑️移除 / 📋共享 |

**目录导航：**

- 文件按 `/` 分隔的虚拟路径组织（与文件系统无关的目录树）
- 支持创建子目录、删除目录、重命名目录、剪切目录（导出并移除）
- 单击目录行进入下层，单击「返回上级」回到上层
- 目录操作行提供导出/剪切/改名/删除按钮

### 批量操作

1. **多选** — 点击行首复选框选择多个文件
2. **全量导入** — 文件选择器导入，支持批量覆盖确认
3. **批量导出** — 选中的文件批量导出到本地目录
4. **批量移除** — 选中的文件批量移除（确认对话框）
5. **拖放导入** — 直接拖入文件到窗口自动批量导入

每个批量操作均在后台线程执行，界面实时显示进度（X/Y），完成后状态栏通知结果。

### 对话框

| 对话框 | 功能 |
|--------|------|
| **改密** | 输入旧密码 + 新密码 ×2，密码强度实时指示 |
| **备份** | 选择备份目录，后台执行 |
| **恢复** | 选择备份目录，确认后恢复（需验证备份密码） |
| **基准测试** | 后台运行全产品基准（SM4/SM4-CBC/HMAC/PBKDF2/SM2/Shamir/多尺寸I/O/批量导入/保险箱打开），完成后滚动展示报告 |
| **审计日志** | 最近 50 条 + 验证 + JSON 导出，payload 超 100 字符自动截断展示 |
| **SM2 公钥** | 查看 130 字符 hex 公钥，一键复制 |
| **共享导出** | 输入对方公钥和输出路径，生成共享包 |
| **Shamir 分片** | 选择 n/t 参数，展示各份子秘密 hex 字符串 |
| **Shamir 恢复** | 输入 t 份子秘密 + 新密码，重构 KEK |

---

## 安全设计

| 层级 | 技术 |
|------|------|
| **密码派生** | PBKDF2-SM3，600,000 次迭代（OWASP 2023 推荐值） |
| **密钥体系** | KEK/DEK 双层分离，KEK 加密 DEK，DEK 加密文件 |
| **文件加密** | SM4-CTR 流模式 + 每文件独立 32B DEK（真随机数） |
| **完整性** | Encrypt-then-MAC，HMAC-SM3 常数时间 `volatile` XOR |
| **验证协议** | Verify-then-Decrypt，拒绝篡改数据 |
| **元数据** | 盲哈希索引 `HMAC(DEK_mac, salt ‖ filename)` + 密文存储 |
| **SQLite** | WAL+NORMAL、`mmap_size=0`、`secure_delete=ON`、`temp_store=MEMORY` |
| **配置** | vault_config 每项写入同步 HMAC 签名，打开/改密校验 |
| **内存** | `ZeroizeOnDrop` 自动零化密钥 + `write_volatile` + `compiler_fence` |
| **填充** | CTR 模式无填充；CBC 仅用于元数据且错误消息统一 |
| **文件擦除** | DoD 5220.22-M 3 遍覆写（随机 → 全 0x00 → 全 0xFF） |
| **审计日志** | SM3 哈希链（`prev_hash` 链接）+ HMAC-SM3(KEK) 双重防护 |

### 约定

```
Encrypt-then-MAC — 加密 → HMAC → 存储
Verify-then-Decrypt — 加载 → 验证 HMAC → 解密

不含"按密码加密"；所有密码仅派生 KEK，不直接用于加密。
```

---

## 目录结构

```
sancove/
├── Cargo.toml                  # 项目配置与依赖
├── REPORT.md                   # 项目报告
├── README.md                   # 本文档
├── .github/workflows/
│   └── release.yml             # GitHub Actions 自动构建发布
├── .cargo/config.toml          # cargo gui 别名配置
├── src/
│   ├── main.rs                 # CLI 入口（clap 约 20 子命令）
│   ├── lib.rs                  # 库入口（7 个公共模块导出）
│   ├── bench.rs                # 内建基准测试（全产品覆盖 9 类 22+ 项指标）
│   ├── db.rs                   # SQLite 数据层（SAVEPOINT 嵌套事务）
│   ├── vault/                   # 保险箱核心业务逻辑（10 子模块）
│   │   ├── mod.rs              # vault 模块导出 + Vault 主结构体
│   │   ├── core.rs             # 创建/打开/保存保险箱
│   │   ├── import.rs           # 文件导入（含文件夹/共享导入）
│   │   ├── export.rs           # 文件导出（Verify-then-Decrypt）
│   │   ├── files.rs            # 文件列表/删除/重命名
│   │   ├── manage.rs           # 改密/备份/恢复/事务
│   │   ├── helpers.rs          # KEK 派生/SM2 密钥存储
│   │   ├── internal.rs         # 内部辅助方法（DEK 解密/元数据解密）
│   │   ├── interface.rs        # SM2 签名/审计/Shamir 接口
│   │   ├── error.rs            # 错误类型
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
│   │   ├── types.rs            # 类型定义
│   │   └── icons.rs            # 跨平台图标系统
│   ├── audit_log/
│   │   ├── mod.rs              # 哈希链 + HMAC 审计日志
│   │   ├── error.rs            # 错误类型（ChainBroken/Corrupt）
│   │   └── export.rs           # JSON 导出 + chrono 格式化
│   └── crypto/
│       ├── mod.rs              # 密码模块导出
│       ├── sm3.rs              # SM3 杂凑 + HMAC + PBKDF2
│       ├── sm4_ctr.rs          # SM4 分组密码 + CBC/CTR + T-Table
│       ├── sm4_bitslice.rs     # SM4 常数时间 bitslice
│       ├── sm2.rs              # SM2 签名/验证（GB/T 32918.2）
│       ├── shamir.rs           # Shamir 秘密共享（GF(256) Lagrange）
│       ├── password_strength.rs# 密码强度评估
│       ├── secure_erase.rs     # 安全文件擦除（DoD 3 遍）
│       └── secure_eq.rs        # 常数时间比较（volatile XOR）
```

---

## 运行测试

```bash
# 所有测试（debug 模式，编译快）
cargo test                # 200+ 项测试

# release 模式（含常数时间 SM4 全链路测试）
cargo test --release

# 特定模块
cargo test sm3            # SM3 相关测试
cargo test vault          # 保险箱核心测试
cargo test gui            # GUI 模块测试
cargo test sm2            # SM2 签名验证测试（耗时较长）

# 代码质量
cargo clippy              # 静态分析
cargo clippy -- -W clippy::pedantic   # 更严格的检查
```

---

_基于国密算法 (SM3/SM4/SM2) 的保密文件库，密码学课程大作业。_
