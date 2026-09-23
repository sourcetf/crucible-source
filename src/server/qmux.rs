//! QMux —— **协议本体未实现**。这里是一个真的在生效的流预算，加上一份诚实的现状说明。
//!
//! # 已实现（真的生效，不是摆着）
//!
//! 每连接一份的**并发请求流预算**：`h3.rs` 开流时取名额（[`stream_opened`]）、
//! 结束时释放（[`stream_closed`]，或守卫 Drop），超限时如实回 503 并记日志。
//! 各连接的计数汇总到进程级 [`QMUX_BUDGET`]，供日志观察。
//!
//! 这道闸门的上限（[`DEFAULT_MAX_ACTIVE`] = 100）刻意与 quinn 的默认
//! `max_concurrent_bidi_streams` 对齐，所以它**不会比传输层本身更严**，
//! 正常客户端碰不到；它真正拦的是「账目错了」——漏释放导致的计数泄漏。
//!
//! # 未实现（说清楚，别让桩代码看起来像做完了）
//!
//! `draft-ietf-quic-qmux-01` 的**协议本体一行都没实现**：
//!
//! - 没有 QMUX 帧类型 / 流类型，没有对应的 wire 编码；
//! - 没有连接 ID 映射、没有多路复用调度、没有协商参数；
//! - 没有和 quinn 连接层挂钩（quinn 0.11 也没有暴露所需的连接事件）。
//!
//! 原因是：**在本仓库能拿到的材料里无法确定该草案的确切 wire format**。
//! 已全树检索过 `qmux`（源码、`*.md`/`*.toml`/`*.txt`/`*.json`/`*.h`、构建日志、
//! 以及 `www-doh/`、`bench/`、`scripts/`、`www/`、`www-apps/` 与快照目录
//! `orig/`、`base_src/`、`_rhead/`、`_ridx/`），命中的只有：
//!
//! - 本文件（及其两份副本）自己的注释；
//! - 若干构建/对比日志里「`qmux.rs` 是个 stub」「`QmuxBudget`/`QMUX_BUDGET` 从未被使用」的记录。
//!
//! **没有草案正文、没有抓包样本、没有一致性测试向量。**
//!
//! 另需指出两处容易误判为「有实现」的线索：`api_cmp.txt` 里出现过
//! `UNIQUE: struct QmuxManager`、`uniq1.txt` 里出现过 `qmux.rs  QmuxManager`，
//! 但那是**另一份代码快照的符号清单**，本仓库树里并不存在 `QmuxManager` 的实现
//! （全树 grep 只命中这两个文本文件），不能据此反推协议。
//!
//! 顺带更正原注释的一处混淆：它自称「RFC 9000 §5.1.2 流预算 — draft-ietf-quic-qmux-01
//! 最小实现」。RFC 9000 §5.1.2 讲的是 QUIC 自己的流 ID 与并发流计数规则，
//! 那是传输层的事（quinn 已经实现）；把它和另一份草案绑在一起当成本模块的实现，
//! 是名不副实的。
//!
//! 取舍：**编一个能编译但语义错的协议，比留一个诚实的桩更糟**——前者看起来是完成了，
//! 会让后续的人按错的格式去对接。所以这里不发明 wire format。
//!
//! # 要补齐需要什么
//!
//! 下列任意一份材料就够开工：
//!
//! 1. `draft-ietf-quic-qmux-01` 正文（确定帧类型取值、流建立/关闭语义）；
//! 2. 一份该草案的真实抓包或互操作记录；
//! 3. 上游参考实现（或某个实现了它的 `quinn` 分支 / PR），据此判断是否需要
//!    给 quinn 加连接事件钩子；
//! 4. 一致性测试向量。
//!
//! 拿到 1 或 2 之后，本文件应从「流预算」升级为真正的 QMux 状态机，
//! 并且预算要从 `h3.rs` 的每请求粒度下沉到 QMUX 自己的流粒度。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// 单连接默认并发请求流上限。
///
/// 与 quinn 默认 `max_concurrent_bidi_streams`（100，见
/// `quinn-proto-0.11.17/src/config/transport.rs`）对齐：闸门不比传输层更严，
/// 正常流量不会因为它被拒。
pub const DEFAULT_MAX_ACTIVE: u64 = 100;

/// 每连接一份的并发流预算。
///
/// 只有 [`QMUX_BUDGET`] 这一个实例没有 parent；其余（`per_connection` 出来的）
/// 都挂到它下面做汇总。
pub struct QmuxBudget {
    active: AtomicU64,
    total_opened: AtomicU64,
    total_closed: AtomicU64,
    rejected: AtomicU64,
    max_active: AtomicU64,
    /// 汇总目标（进程级）。子预算的增减同时计入它。
    parent: Option<&'static QmuxBudget>,
}

impl Default for QmuxBudget {
    fn default() -> Self {
        Self {
            active: AtomicU64::new(0),
            total_opened: AtomicU64::new(0),
            total_closed: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
            max_active: AtomicU64::new(DEFAULT_MAX_ACTIVE),
            parent: None,
        }
    }
}

impl QmuxBudget {
    /// 新建一条连接自己的预算。
    ///
    /// `h3.rs::handle_incoming` 在每条 QUIC 连接上调用一次，并把结果传给
    /// 该连接的所有请求任务。上限继承 [`QMUX_BUDGET`]，便于只在一个地方调。
    pub fn per_connection() -> Arc<Self> {
        let max = QMUX_BUDGET.max_active.load(Ordering::Acquire);
        Arc::new(Self {
            max_active: AtomicU64::new(max),
            parent: Some(&QMUX_BUDGET),
            ..Self::default()
        })
    }

    /// 占用一个并发名额；成功返回 RAII 守卫（Drop 自动释放）。
    ///
    /// 超限时返回 [`QmuxReject`]，调用方应回 503 —— 而不是把这次请求算成
    /// 「已服务」。旧桩代码的问题正是：计数器存在，但没有任何人读它。
    pub fn acquire(self: &Arc<Self>) -> Result<QmuxGuard, QmuxReject> {
        let cur = self.active.fetch_add(1, Ordering::AcqRel);
        let max = self.max_active.load(Ordering::Acquire);
        if cur + 1 > max {
            // 自己加的那一份要退回去，否则拒绝一次就永久少一个名额。
            self.active.fetch_sub(1, Ordering::AcqRel);
            self.rejected.fetch_add(1, Ordering::AcqRel);
            return Err(QmuxReject {
                active: cur,
                max,
            });
        }
        self.total_opened.fetch_add(1, Ordering::AcqRel);
        if let Some(p) = self.parent {
            p.active.fetch_add(1, Ordering::AcqRel);
            p.total_opened.fetch_add(1, Ordering::AcqRel);
        }
        Ok(QmuxGuard {
            budget: Arc::clone(self),
            released: false,
        })
    }

    /// 释放一个名额（由守卫保证只调用一次）。
    fn release(&self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
        self.total_closed.fetch_add(1, Ordering::AcqRel);
        if let Some(p) = self.parent {
            p.active.fetch_sub(1, Ordering::AcqRel);
            p.total_closed.fetch_add(1, Ordering::AcqRel);
        }
    }

    /// 一行汇总，给日志用（字段少，不单独做 Display）。
    pub fn stats_line(&self) -> String {
        format!(
            "active={} opened={} closed={} rejected={} max={}",
            self.active.load(Ordering::Acquire),
            self.total_opened.load(Ordering::Acquire),
            self.total_closed.load(Ordering::Acquire),
            self.rejected.load(Ordering::Acquire),
            self.max_active.load(Ordering::Acquire),
        )
    }
}

/// 名额守卫：Drop 时释放。
///
/// 这一层是刻意的——`h3.rs` 里从取名额到请求结束之间有很多 `return Ok(())`
/// 的早退分支（客户端复位、超时、cancel 都是常态），靠手写配对释放必然漏账。
pub struct QmuxGuard {
    budget: Arc<QmuxBudget>,
    released: bool,
}

impl QmuxGuard {
    /// 释放名额。幂等：之后再被 Drop 也不会重复扣减。
    fn release(mut self) {
        self.release_inner();
    }

    fn release_inner(&mut self) {
        if !self.released {
            self.released = true;
            self.budget.release();
        }
    }
}

impl Drop for QmuxGuard {
    fn drop(&mut self) {
        self.release_inner();
    }
}

/// 被预算拒绝。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QmuxReject {
    /// 拒绝时的在途并发数。
    pub active: u64,
    /// 当前上限。
    pub max: u64,
}

impl std::fmt::Display for QmuxReject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "qmux over budget: active={} max={}", self.active, self.max)
    }
}

impl std::error::Error for QmuxReject {}

/// 进程级汇总预算：**不做闸门**，只做跨连接的计数汇总，并为新连接提供默认上限。
///
/// 为什么不在这里设全局闸门：全局上限会在高并发下误伤正常流量
/// （quinn 每连接默认就允许 100 条并发双向流，两条连接的正常业务加起来就能到 200），
/// 而这道闸门本来要防的是「计数漏释放」，那是每连接的问题。
pub static QMUX_BUDGET: once_cell::sync::Lazy<QmuxBudget> =
    once_cell::sync::Lazy::new(QmuxBudget::default);

/// 开流登记：检查该连接的并发上限并占用一个名额。
///
/// 与 `h3.rs` 原来的调用形状一致（处理请求前开、处理后关），
/// 但返回的是 RAII 守卫，早退 / panic 都会释放。
pub fn stream_opened(budget: &Arc<QmuxBudget>) -> Result<QmuxGuard, QmuxReject> {
    budget.acquire()
}

/// 关流登记：显式释放名额。
///
/// 守卫的 `Drop` 也会释放，两者幂等，所以「显式关」和「早退漏关」都不会算错。
pub fn stream_closed(guard: QmuxGuard) {
    guard.release();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_rejects_and_releases() {
        let b = Arc::new(QmuxBudget::default());
        assert_eq!(b.max_active.load(Ordering::Acquire), DEFAULT_MAX_ACTIVE);
        let g1 = b.acquire().expect("first");
        // 拿到守卫就占了一个名额。
        assert!(b.stats_line().contains("active=1"));
        drop(g1);
        assert!(b.stats_line().contains("active=0"));
        assert!(b.stats_line().contains("closed=1"));
    }

    #[test]
    fn budget_does_not_overcount_on_reject() {
        let b = Arc::new(QmuxBudget {
            max_active: AtomicU64::new(1),
            ..QmuxBudget::default()
        });
        let g = b.acquire().expect("first fits");
        assert!(b.acquire().is_err(), "second must be rejected");
        assert!(b.stats_line().contains("active=1"));
        assert!(b.stats_line().contains("rejected=1"));
        // 被拒之后名额没有被吃掉：释放后还能再拿一个。
        drop(g);
        assert!(b.acquire().is_ok());
    }

    #[test]
    fn explicit_close_is_idempotent() {
        let b = Arc::new(QmuxBudget::default());
        let g = b.acquire().expect("first");
        stream_closed(g);
        assert!(b.stats_line().contains("active=0"));
        assert!(b.stats_line().contains("closed=1"));
    }
}
