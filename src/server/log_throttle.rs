//! 按「类别 + 时间」节流的日志出口。
//!
//! 为什么需要它：项目里有多条**未认证对端可驱动**的日志路径 —— TLS 握手失败/软丢弃、
//! DoT 的准入拒绝、明文监听口缺证书……这些事件每条消息都带对端地址（所以**按消息去重
//! 没有用**，每条都不同），而对端完全控制发送速率。一条近百字节 × 每秒上万条，一天就是
//! GB 级；本机磁盘长期在 95%，而 `daily.local` 是 copytruncate，两次轮转之间文件**无上界**。
//! 结果不只是"日志难看"：磁盘写满会让 named/面板落盘失败，等于可远程拖垮整机
//! （项目里已经有过一次因写满盘让 GeoIP merge 死在半途的记录）。
//!
//! 与 [`crate::server::dns::warn_once`] 的分工：那个按**消息内容**去重（适合"同一句错误
//! 反复出现"）；这里按**类别 + 时间**（适合同一类事件由不同对端/不同参数反复触发）。
//!
//! tag 用 `&'static str`（调用点都是字面量）：表的大小因此**天然有界** —— 不会出现
//! 「攻击者用参数把表撑爆」那种内存放大。

// 用 std 的 Mutex 而不是 parking_lot：这里要的正是「容忍 poisoning」语义
// （缓存只是一张时间表，持锁时 panic 不该让日志出口永久失效），
// 而 parking_lot 的 lock() 不返回 Result、没有这套语义。
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

static LAST: Mutex<Option<HashMap<String, Instant>>> = Mutex::new(None);

/// 表的上限。tag 只应由**配置/常量**派生（引擎名、固定类别），所以正常情况下最多几十个；
/// 这个上限纯粹是「万一有人把请求数据当 tag」时的兜底 —— 到顶就整表清空（节流表清空的
/// 后果只是「下一次都放行」，不会漏掉日志、也不会影响正确性）。
const MAX_TAGS: usize = 512;

/// 同一 `tag` 最快每 `every` 打一条 warn；**首次一定打**（否则排障时看不到第一现场）。
///
/// `every` 由调用点给：频繁且低信息量的（握手失败、引擎报错）给分钟级，罕见的给秒级。
///
/// **tag 不要用请求数据拼**（那会让表被撑大、节流失效）：用引擎名/类别这类**配置派生**
/// 的字符串。
pub fn warn_every(tag: &str, every: Duration, msg: &str) {
    if !due(tag, every) {
        return;
    }
    log::warn!("{msg}");
}

/// 同 [`warn_every`] 的 info 版本。
pub fn info_every(tag: &str, every: Duration, msg: &str) {
    if !due(tag, every) {
        return;
    }
    log::info!("{msg}");
}

/// 该 tag 现在是否到了可以再打一条的时候（到了就记账并返回 true）。
///
/// 先判定再放锁再 log：`log::warn!` 内部会拿 env_logger 的锁，把它放在本函数的锁里
/// 会与「日志锁 → 本锁」的反向顺序构成死锁风险。
fn due(tag: &str, every: Duration) -> bool {
    let mut g = LAST.lock().unwrap_or_else(|e| e.into_inner());
    let m = g.get_or_insert_with(HashMap::new);
    if m.len() >= MAX_TAGS {
        m.clear();
    }
    let now = Instant::now();
    match m.get(tag) {
        Some(t) if now.duration_since(*t) < every => false,
        _ => {
            m.insert(tag.to_string(), now);
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 首次必打，之后在窗口内被折叠，窗口过后再放行；不同 tag 互不影响。
    #[test]
    fn first_always_prints_then_folds_within_the_window() {
        // tag 用本测试自己的名字，避免与其它测试（同进程并行）互相影响。
        let tag = "unit-test-fold";
        assert!(due(tag, Duration::from_secs(3600)), "首次必须放行");
        assert!(!due(tag, Duration::from_secs(3600)), "窗口内必须折叠");
        assert!(due(tag, Duration::ZERO), "窗口为 0 时必须放行");
        assert!(due("unit-test-other-tag", Duration::from_secs(3600)), "换 tag 不受影响");
    }
}