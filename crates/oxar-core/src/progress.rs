//! Progress reporting and cancellation.
//!
//! Progress events are emitted by worker threads. Implementations of
//! `ProgressSink` must be cheap and must not call back into Python; the
//! binding layer uses a channel sink and runs Python callbacks on the calling
//! thread only.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// The kind of a progress event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgressKind {
    /// The operation started. `entries_total` and `bytes_total` are set when
    /// the format and source allow knowing them in advance.
    Start,
    /// An entry was started.
    EntryStart,
    /// Bytes were produced for the current entry since the last event.
    Bytes,
    /// An entry finished successfully.
    EntryDone,
    /// The operation finished. Always delivered exactly once per run.
    Finished,
}

/// One progress observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgressEvent {
    /// Event kind.
    pub kind: ProgressKind,
    /// Entry path the event refers to, when the event is per entry.
    pub path: Option<String>,
    /// Entries completed so far.
    pub entries_done: u64,
    /// Entries known to exist in total, when known.
    pub entries_total: Option<u64>,
    /// Bytes produced so far in this run.
    pub bytes_done: u64,
    /// Bytes expected in total, when known.
    pub bytes_total: Option<u64>,
}

impl ProgressEvent {
    /// Build a run level event.
    #[must_use]
    pub fn run(kind: ProgressKind, entries_done: u64, bytes_done: u64) -> Self {
        Self {
            kind,
            path: None,
            entries_done,
            entries_total: None,
            bytes_done,
            bytes_total: None,
        }
    }

    /// Build an entry level event.
    #[must_use]
    pub fn entry(kind: ProgressKind, path: &str, entries_done: u64, bytes_done: u64) -> Self {
        Self {
            kind,
            path: Some(path.to_owned()),
            entries_done,
            entries_total: None,
            bytes_done,
            bytes_total: None,
        }
    }
}

/// Receives progress events. Implementations are called from worker threads
/// and must be `Send + Sync`. They must not block: the binding layer's sink
/// pushes into a bounded channel and drops events under back pressure.
pub trait ProgressSink: Send + Sync {
    /// Deliver one event.
    fn emit(&self, event: ProgressEvent);
}

/// Sink used when the caller passed no progress callback.
pub struct NullProgress;

impl ProgressSink for NullProgress {
    fn emit(&self, _event: ProgressEvent) {}
}

/// Cooperative cancellation flag shared with every worker.
#[derive(Debug, Clone, Default)]
pub struct CancelToken {
    flag: Arc<AtomicBool>,
}

impl CancelToken {
    /// A token in the cancelled=false state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Request cancellation. Safe to call from any thread, any number of times.
    pub fn cancel(&self) {
        self.flag.store(true, Ordering::Release);
    }

    /// Whether cancellation was requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::Acquire)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn cancel_is_visible_across_threads() {
        let token = CancelToken::new();
        let other = token.clone();
        let handle = std::thread::spawn(move || other.is_cancelled());
        token.cancel();
        assert!(handle.join().unwrap());
        assert!(token.is_cancelled());
    }
}
