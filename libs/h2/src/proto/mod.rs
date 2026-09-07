//! Fork-like connection settings surface (fair-gate knobs).
//!
//! Upstream crates.io `h2` does not expose coalesce/batch internals; Crucible
//! mirrors the vendored-fork API here and wires values in `src/server/h2.rs`.

pub mod connection;

pub use connection::{ConnectionSettings, DEFAULT_SETTINGS};
