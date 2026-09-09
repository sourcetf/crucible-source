//! RFC 9000 §5.1.2 流预算 — draft-ietf-quic-qmux-01 最小实现.
//! h3 路径在握手通过后开流时调用 try_open；流关闭时 close.
use std::sync::atomic::{AtomicU64, Ordering};
pub fn stream_opened() {}
pub fn stream_closed() {}

pub struct QmuxBudget {
    active: AtomicU64,
    total_opened: AtomicU64,
    total_closed: AtomicU64,
    max_active: AtomicU64,
}

impl Default for QmuxBudget {
    fn default() -> Self {
        Self {
            active: AtomicU64::new(0),
            total_opened: AtomicU64::new(0),
            total_closed: AtomicU64::new(0),
            max_active: AtomicU64::new(100),
        }
    }
}

impl QmuxBudget {
    pub fn try_open(&self) -> Result<(), String> {
        let cur = self.active.fetch_add(1, Ordering::AcqRel);
        let max = self.max_active.load(Ordering::Acquire);
        if cur + 1 > max {
            self.active.fetch_sub(1, Ordering::AcqRel);
            return Err(format!("qmux overbudget {}/{}", cur + 1, max));
        }
        self.total_opened.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }
    pub fn close(&self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
        self.total_closed.fetch_add(1, Ordering::AcqRel);
    }
    pub fn active(&self) -> u64 { self.active.load(Ordering::Acquire) }
    pub fn set_max(&self, n: u64) { self.max_active.store(n, Ordering::Release); }
}

pub static QMUX_BUDGET: once_cell::sync::Lazy<QmuxBudget> =
    once_cell::sync::Lazy::new(QmuxBudget::default);
