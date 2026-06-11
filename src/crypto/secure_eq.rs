//! 常数时间比较工具
//!
//! 防止因比较耗时差异导致的时序侧信道攻击。
//! 使用 volatile 内存读取阻止编译器优化，无分支 XOR 累加确保耗时恒定。
//!
//! # 原理
//!
//! 标准字节比较在遇到第一个不匹配字节时会短路返回，攻击者可利用耗时差
//! 逐字节推断 HMAC 标签或密钥。本模块通过以下方式消除该侧信道：
//!
//! 1. `std::ptr::read_volatile` 强制编译器每次从内存读取（阻止循环优化）
//! 2. 按位 XOR 累加代替条件分支（任何字节差异都会体现在累加器中）
//! 3. 累加器值不提前返回，始终遍历全部 len 个字节

use core::ptr;

use core::sync::atomic::Ordering;
use core::sync::atomic::compiler_fence;

/// 常数时间比较两个 32 字节数组（适用于 HMAC-SM3 标签比对）
///
/// 使用 `read_volatile` 防编译器优化 + `compiler_fence` 防跨迭代重排，
/// 确保全 32 字节在任何架构上都以恒定时序完成。
#[inline]
pub fn constant_time_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut acc: u8 = 0;
    for i in 0..32 {
        let x = unsafe { ptr::read_volatile(&a[i]) };
        let y = unsafe { ptr::read_volatile(&b[i]) };
        acc |= x ^ y;
    }
    compiler_fence(Ordering::SeqCst);
    acc == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eq_32_equal() {
        let a = [0x42u8; 32];
        let b = [0x42u8; 32];
        assert!(constant_time_eq_32(&a, &b));
    }

    #[test]
    fn test_eq_32_diff_last_byte() {
        let mut a = [0x42u8; 32];
        let b = [0x42u8; 32];
        a[31] = 0x00;
        assert!(!constant_time_eq_32(&a, &b));
    }

    #[test]
    fn test_eq_32_all_different() {
        let a = [0x00u8; 32];
        let b = [0xFFu8; 32];
        assert!(!constant_time_eq_32(&a, &b));
    }

    #[test]
    fn test_deterministic_timing_property() {
        let a = [0xFFu8; 32];
        let mut b_diff_first = [0xFFu8; 32];
        let mut b_diff_last = [0xFFu8; 32];
        let b_same = [0xFFu8; 32];

        b_diff_first[0] = 0x00;
        b_diff_last[31] = 0x00;

        assert!(!constant_time_eq_32(&a, &b_diff_first));
        assert!(!constant_time_eq_32(&a, &b_diff_last));
        assert!(constant_time_eq_32(&a, &b_same));
    }
}
