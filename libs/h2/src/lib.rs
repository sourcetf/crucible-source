//! Crucible HTTP/2 layer — crates.io `h2` 0.4 plus local framed_write knobs.
//!
//! A full source fork of `proto/connection` is not required for OpenBSD builds:
//! fair-gate knobs live in [`framed_write`] and are consumed by `src/server/h2.rs`
//! (`BATCH_CAP`, `max_send_buffer_size`, coalesce flag).
//!
//! # Fork-like surface
//! - [`BATCH_CAP`] — max frames coalesced per flush (default 16)
//! - [`coalesce_writes`] — construct a [`BatchWriter`] with coalesce on/off
//! - [`framed_write`] — local buffering module (not crates.io h2 internals)

pub mod framed_write;
pub mod proto;

pub use framed_write::{
    coalesce_writes, BatchWriter, BATCH_CAP, COALESCE_WRITES_DEFAULT,
};
pub use proto::connection::{ConnectionSettings, DEFAULT_SETTINGS};
pub use h2_crate::*;
