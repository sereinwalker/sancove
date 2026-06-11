//! 基于国密算法的保密文件库 - 核心库
//!
//! 提供 CLI 和 GUI 两种前端共享的业务逻辑：
//!
//! - `vault` — 保密文件库核心（创建/打开、导入/导出、密码修改、SM2 共享、Shamir 灾备）
//! - `gui` — egui 图形界面（登录、主界面、批量操作）
//! - `db` — SQLite 数据库持久化层
//! - `crypto` — 国密算法实现（SM3、SM4-CTR/CBC、SM2、PBKDF2、Shamir）
//! - `audit_log` — 哈希链 + HMAC 审计日志
//! - `bench` — 性能基准测试

pub mod audit_log;
pub mod bench;
pub mod crypto;
pub mod db;
pub mod gui;
pub mod vault;
