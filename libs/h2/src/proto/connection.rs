//! Connection-level H2 knobs mirrored from the historical vendored fork.

use crate::{BATCH_CAP, COALESCE_WRITES_DEFAULT};

/// Fair-gate / h2o-aligned connection settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionSettings {
    pub batch_cap: usize,
    pub coalesce_writes: bool,
    pub max_send_buffer_size: usize,
    pub initial_window_size: u32,
    pub initial_connection_window_size: u32,
    pub max_concurrent_streams: u32,
}

pub const DEFAULT_SETTINGS: ConnectionSettings = ConnectionSettings {
    batch_cap: BATCH_CAP,
    coalesce_writes: COALESCE_WRITES_DEFAULT,
    max_send_buffer_size: 128 * 1024,
    initial_window_size: 1 << 20,
    initial_connection_window_size: 1 << 20,
    max_concurrent_streams: 256,
};

impl ConnectionSettings {
    pub const fn new() -> Self {
        DEFAULT_SETTINGS
    }

    pub fn with_batch_cap(mut self, cap: usize) -> Self {
        self.batch_cap = cap.max(1);
        self
    }

    pub fn with_coalesce_writes(mut self, on: bool) -> Self {
        self.coalesce_writes = on;
        self
    }

    pub fn with_max_send_buffer_size(mut self, n: usize) -> Self {
        self.max_send_buffer_size = n.max(4096);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_fair_gate() {
        assert_eq!(DEFAULT_SETTINGS.batch_cap, 16);
        assert!(!DEFAULT_SETTINGS.coalesce_writes);
        assert_eq!(DEFAULT_SETTINGS.max_send_buffer_size, 128 * 1024);
    }
}
