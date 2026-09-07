//! Crucible framed_write batching layer (fair-gate knobs).
//!
//! Mirrors vendored-fork framed_write behaviour: coalesce small writes up to
//! [`BATCH_CAP`] frames before flushing to the socket.
//!
//! # API
//! - [`BATCH_CAP`] — public constant (16)
//! - [`coalesce_writes`] — factory for a coalesce-enabled/disabled [`BatchWriter`]
//! - [`BatchWriter::write_frame`] — buffers frames when coalesce is on

use std::io::{self, Write};

/// Max frames coalesced per flush (h2o fair-gate default).
pub const BATCH_CAP: usize = 16;

/// Default coalesce_writes for static fair-gate experiments.
pub const COALESCE_WRITES_DEFAULT: bool = false;

/// Construct a [`BatchWriter`] with coalesce mode set (fork-like `coalesce_writes` API).
pub fn coalesce_writes<W>(inner: W, enabled: bool) -> BatchWriter<W> {
    BatchWriter::new(inner)
        .with_coalesce(enabled)
        .with_cap(BATCH_CAP)
}

/// Buffered frame writer used by the server accept loop.
#[derive(Debug)]
pub struct BatchWriter<W> {
    inner: W,
    pending_frames: usize,
    pending_bytes: usize,
    cap: usize,
    coalesce: bool,
    buf: Vec<u8>,
}

impl<W> BatchWriter<W> {
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            pending_frames: 0,
            pending_bytes: 0,
            cap: BATCH_CAP,
            coalesce: COALESCE_WRITES_DEFAULT,
            buf: Vec::with_capacity(16 * 1024),
        }
    }

    pub fn with_coalesce(mut self, coalesce: bool) -> Self {
        self.coalesce = coalesce;
        self
    }

    pub fn with_cap(mut self, cap: usize) -> Self {
        self.cap = cap.max(1);
        self
    }

    pub fn coalesce_enabled(&self) -> bool {
        self.coalesce
    }

    pub fn cap(&self) -> usize {
        self.cap
    }

    pub fn pending_frames(&self) -> usize {
        self.pending_frames
    }

    pub fn pending_bytes(&self) -> usize {
        self.pending_bytes
    }

    pub fn inner(&self) -> &W {
        &self.inner
    }

    pub fn inner_mut(&mut self) -> &mut W {
        &mut self.inner
    }

    /// Discard buffered frames without flushing (explicit escape hatch).
    pub fn into_inner_discarding(self) -> W {
        self.inner
    }

    pub fn reset_batch(&mut self) {
        self.pending_frames = 0;
        self.pending_bytes = 0;
        self.buf.clear();
    }
}

impl<W: Write> BatchWriter<W> {
    /// Queue one logical frame; flush when batch is full or coalesce disabled.
    pub fn write_frame(&mut self, frame: &[u8]) -> io::Result<()> {
        if !self.coalesce {
            self.inner.write_all(frame)?;
            return self.inner.flush();
        }
        self.buf.extend_from_slice(frame);
        self.pending_frames = self.pending_frames.saturating_add(1);
        self.pending_bytes = self.pending_bytes.saturating_add(frame.len());
        if self.pending_frames >= self.cap {
            self.flush_batch()?;
        }
        Ok(())
    }

    /// Legacy callback form used by older call sites.
    /// Legacy callback form. Always invokes `flush` so frames are never dropped
    /// when coalesce counting alone would skip the write (audit Medium).
    pub fn write_frame_with<F>(&mut self, nbytes: usize, flush: F) -> io::Result<()>
    where
        F: FnOnce(&mut W) -> io::Result<()>,
    {
        let _ = nbytes;
        flush(&mut self.inner)?;
        self.pending_frames = 0;
        self.pending_bytes = 0;
        Ok(())
    }

    pub fn flush_batch(&mut self) -> io::Result<()> {
        if !self.buf.is_empty() {
            self.inner.write_all(&self.buf)?;
            self.buf.clear();
        }
        self.inner.flush()?;
        self.pending_frames = 0;
        self.pending_bytes = 0;
        Ok(())
    }

    /// Flush any coalesced bytes before yielding the inner writer.
    pub fn into_inner(mut self) -> io::Result<W> {
        self.flush_batch()?;
        Ok(self.inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn coalesce_batches_until_cap() {
        let mut w = BatchWriter::new(Cursor::new(Vec::new()))
            .with_coalesce(true)
            .with_cap(3);
        w.write_frame(b"a").unwrap();
        w.write_frame(b"b").unwrap();
        assert_eq!(w.pending_frames(), 2);
        assert!(w.inner().get_ref().is_empty());
        w.write_frame(b"c").unwrap();
        assert_eq!(w.pending_frames(), 0);
        assert_eq!(w.inner().get_ref(), b"abc");
    }

    #[test]
    fn no_coalesce_flushes_immediately() {
        let mut w = BatchWriter::new(Cursor::new(Vec::new())).with_coalesce(false);
        w.write_frame(b"x").unwrap();
        assert_eq!(w.inner().get_ref(), b"x");
    }

    #[test]
    fn coalesce_writes_api() {
        let mut w = coalesce_writes(Cursor::new(Vec::new()), true);
        assert!(w.coalesce_enabled());
        assert_eq!(w.cap(), BATCH_CAP);
        w.write_frame(b"hi").unwrap();
        assert_eq!(w.pending_frames(), 1);
    }
}
