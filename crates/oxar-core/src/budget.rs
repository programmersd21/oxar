//! Budget accounting: entries, produced bytes, consumed bytes and decoder
//! memory reservations, shared across worker threads.
//!
//! Limits are enforced on bytes actually produced, never on declared sizes.
//! Callers charge in chunks of at least 64 KiB so the atomics stay cold in
//! the hot path.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::{Error, Location, Result};
use crate::policy::Limits;
use crate::progress::CancelToken;

/// Minimum charge granularity; callers should not charge more often.
pub const CHARGE_CHUNK: u64 = 64 * 1024;

/// Run level ratio checks start only after this many produced bytes.
const TOTAL_RATIO_FLOOR: u64 = 1024 * 1024 * 1024;

#[derive(Debug)]
struct Inner {
    limits: Limits,
    entries: AtomicU64,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
    decoder_memory: AtomicU64,
    peak_decoder_memory: AtomicU64,
    cancel: CancelToken,
}

/// Shared, cloneable accounting state for one operation.
#[derive(Debug, Clone)]
pub struct Budget {
    inner: Arc<Inner>,
}

impl Budget {
    /// Create a budget for one run.
    #[must_use]
    pub fn new(limits: Limits, cancel: CancelToken) -> Self {
        Self {
            inner: Arc::new(Inner {
                limits,
                entries: AtomicU64::new(0),
                bytes_in: AtomicU64::new(0),
                bytes_out: AtomicU64::new(0),
                decoder_memory: AtomicU64::new(0),
                peak_decoder_memory: AtomicU64::new(0),
                cancel,
            }),
        }
    }

    /// The cancellation token of this run.
    #[must_use]
    pub fn cancel_token(&self) -> &CancelToken {
        &self.inner.cancel
    }

    /// The configured limits.
    #[must_use]
    pub fn limits(&self) -> &Limits {
        &self.inner.limits
    }

    /// Convert cancellation into an error. Called at chunk and entry
    /// boundaries so long operations stop promptly.
    pub fn check_cancel(&self) -> Result<()> {
        if self.inner.cancel.is_cancelled() {
            return Err(Error::Cancelled);
        }
        Ok(())
    }

    /// Account for one entry starting. Checks `max_entries`.
    pub fn start_entry(&self) -> Result<EntryScope> {
        let count = self
            .inner
            .entries
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        if let Some(limit) = self.inner.limits.max_entries
            && count > limit
        {
            return Err(Error::Bomb {
                limit: "max_entries",
                limit_value: limit,
                observed: count,
                loc: Location::new(),
            });
        }
        Ok(EntryScope {
            budget: self.clone(),
            entry_out: 0,
            entry_in: 0,
            ratio_checked: false,
        })
    }

    /// Account for input bytes consumed while no entry is active.
    pub fn charge_in(&self, bytes: u64) {
        self.inner.bytes_in.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Reserve decoder memory; the reservation is released on drop.
    pub fn reserve_decoder_memory(&self, bytes: u64) -> Result<DecoderReservation> {
        if let Some(limit) = self.inner.limits.max_decoder_memory {
            let previous = self
                .inner
                .decoder_memory
                .fetch_add(bytes, Ordering::Relaxed);
            let total = previous.saturating_add(bytes);
            if total > limit {
                self.inner
                    .decoder_memory
                    .fetch_sub(bytes, Ordering::Relaxed);
                return Err(Error::Bomb {
                    limit: "max_decoder_memory",
                    limit_value: limit,
                    observed: total,
                    loc: Location::new(),
                });
            }
            self.inner
                .peak_decoder_memory
                .fetch_max(total, Ordering::Relaxed);
        }
        Ok(DecoderReservation {
            budget: self.clone(),
            bytes,
        })
    }

    /// Peak decoder memory seen so far.
    #[must_use]
    pub fn peak_decoder_memory(&self) -> u64 {
        self.inner.peak_decoder_memory.load(Ordering::Relaxed)
    }

    /// Entries started so far.
    #[must_use]
    pub fn entries(&self) -> u64 {
        self.inner.entries.load(Ordering::Relaxed)
    }

    /// Output bytes produced so far.
    #[must_use]
    pub fn bytes_out(&self) -> u64 {
        self.inner.bytes_out.load(Ordering::Relaxed)
    }

    /// Input bytes consumed so far.
    #[must_use]
    pub fn bytes_in(&self) -> u64 {
        self.inner.bytes_in.load(Ordering::Relaxed)
    }

    #[allow(clippy::arithmetic_side_effects)] // all arithmetic saturating; divisors clamped to >= 1
    fn check_total(&self, extra_out: u64) -> Result<()> {
        let total = self
            .inner
            .bytes_out
            .load(Ordering::Relaxed)
            .saturating_add(extra_out);
        if let Some(limit) = self.inner.limits.max_total_size
            && total > limit
        {
            return Err(Error::Bomb {
                limit: "max_total_size",
                limit_value: limit,
                observed: total,
                loc: Location::new(),
            });
        }
        if let Some(ratio) = self.inner.limits.max_ratio
            && total >= TOTAL_RATIO_FLOOR
        {
            let input = self.inner.bytes_in.load(Ordering::Relaxed).max(1);
            if total / input > ratio {
                return Err(Error::Bomb {
                    limit: "max_ratio",
                    limit_value: ratio,
                    observed: total / input,
                    loc: Location::new(),
                });
            }
        }
        Ok(())
    }
}

/// Per entry accounting scope. Owned by the worker processing the entry; the
/// per entry counters are plain fields, the run totals are atomics.
#[derive(Debug)]
pub struct EntryScope {
    budget: Budget,
    entry_out: u64,
    entry_in: u64,
    ratio_checked: bool,
}

impl EntryScope {
    /// Account produced bytes for this entry.
    #[allow(clippy::arithmetic_side_effects)] // all arithmetic saturating; divisors clamped to >= 1
    pub fn charge_out(&mut self, bytes: u64) -> Result<()> {
        self.entry_out = self.entry_out.saturating_add(bytes);
        self.budget
            .inner
            .bytes_out
            .fetch_add(bytes, Ordering::Relaxed);
        if let Some(limit) = self.budget.inner.limits.max_entry_size
            && self.entry_out > limit
        {
            return Err(Error::Bomb {
                limit: "max_entry_size",
                limit_value: limit,
                observed: self.entry_out,
                loc: Location::new(),
            });
        }
        if let Some(ratio) = self.budget.inner.limits.max_ratio {
            let floor = self.budget.inner.limits.ratio_floor;
            if self.entry_out >= floor {
                self.ratio_checked = true;
                let input = self.entry_in.max(1);
                if self.entry_out / input > ratio {
                    return Err(Error::Bomb {
                        limit: "max_ratio",
                        limit_value: ratio,
                        observed: self.entry_out / input,
                        loc: Location::new(),
                    });
                }
            }
        }
        self.budget.check_total(0)
    }

    /// Account compressed bytes consumed for this entry. Charged by readers
    /// that can attribute source reads to the entry being produced.
    pub fn charge_in(&mut self, bytes: u64) {
        self.entry_in = self.entry_in.saturating_add(bytes);
        self.budget
            .inner
            .bytes_in
            .fetch_add(bytes, Ordering::Relaxed);
    }

    /// Bytes produced for this entry so far.
    #[must_use]
    pub fn produced(&self) -> u64 {
        self.entry_out
    }

    /// The underlying budget.
    #[must_use]
    pub fn budget(&self) -> &Budget {
        &self.budget
    }

    /// Cooperative cancellation check.
    pub fn check_cancel(&self) -> Result<()> {
        self.budget.check_cancel()
    }

    /// Whether the per entry ratio check already ran.
    #[must_use]
    pub fn ratio_checked(&self) -> bool {
        self.ratio_checked
    }

    /// Scope for an operation that is not yet attached to a run; counts
    /// towards a budget that the caller provides.
    #[allow(clippy::indexing_slicing)]
    pub fn detached(budget: Budget) -> Self {
        Self {
            budget,
            entry_out: 0,
            entry_in: 0,
            ratio_checked: false,
        }
    }
}

/// Holds a decoder memory reservation until dropped.
#[derive(Debug)]
pub struct DecoderReservation {
    budget: Budget,
    bytes: u64,
}

impl Drop for DecoderReservation {
    fn drop(&mut self) {
        self.budget
            .inner
            .decoder_memory
            .fetch_sub(self.bytes, Ordering::Relaxed);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn budget_with(limits: Limits) -> Budget {
        Budget::new(limits, CancelToken::new())
    }

    #[test]
    fn entry_limit_fires() {
        let limits = Limits {
            max_entry_size: Some(1024),
            ..Limits::default()
        };
        let budget = budget_with(limits);
        let mut scope = budget.start_entry().unwrap();
        scope.charge_out(1024).unwrap();
        let error = scope.charge_out(1).unwrap_err();
        assert!(matches!(error, Error::Bomb { limit, .. } if limit == "max_entry_size"));
    }

    #[test]
    fn total_limit_fires_across_entries() {
        let limits = Limits {
            max_total_size: Some(2048),
            ..Limits::default()
        };
        let budget = budget_with(limits);
        let mut first = budget.start_entry().unwrap();
        first.charge_out(2048).unwrap();
        let mut second = budget.start_entry().unwrap();
        let error = second.charge_out(1).unwrap_err();
        assert!(matches!(error, Error::Bomb { limit, .. } if limit == "max_total_size"));
    }

    #[test]
    fn ratio_limit_fires_on_zero_input() {
        let limits = Limits {
            ratio_floor: 1024,
            ..Limits::default()
        };
        let budget = budget_with(limits);
        let mut scope = budget.start_entry().unwrap();
        let error = scope.charge_out(4096).unwrap_err();
        assert!(matches!(error, Error::Bomb { limit, .. } if limit == "max_ratio"));
    }

    #[test]
    fn ratio_ok_with_enough_input() {
        let limits = Limits {
            ratio_floor: 1024,
            max_ratio: Some(10),
            ..Limits::default()
        };
        let budget = budget_with(limits);
        let mut scope = budget.start_entry().unwrap();
        scope.charge_in(1024);
        scope.charge_out(4096).unwrap();
    }

    #[test]
    fn decoder_memory_reserved_and_released() {
        let limits = Limits {
            max_decoder_memory: Some(1000),
            ..Limits::default()
        };
        let budget = budget_with(limits);
        let first = budget.reserve_decoder_memory(600).unwrap();
        let error = budget.reserve_decoder_memory(600).unwrap_err();
        assert!(matches!(error, Error::Bomb { limit, .. } if limit == "max_decoder_memory"));
        drop(first);
        budget.reserve_decoder_memory(600).unwrap();
    }

    #[test]
    fn concurrent_updates_keep_exact_counts() {
        let budget = budget_with(Limits::default());
        let mut handles = Vec::new();
        for _ in 0..16 {
            let budget = budget.clone();
            handles.push(std::thread::spawn(move || {
                for _ in 0..1000 {
                    let mut scope = budget.start_entry().unwrap();
                    scope.charge_out(CHARGE_CHUNK).unwrap();
                    scope.charge_in(CHARGE_CHUNK);
                }
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }
        assert_eq!(budget.entries(), 16_000);
        assert_eq!(budget.bytes_out(), 16_000 * CHARGE_CHUNK);
        assert_eq!(budget.bytes_in(), 16_000 * CHARGE_CHUNK);
    }

    #[test]
    fn disabled_limits_do_not_fire() {
        let limits = Limits {
            max_entry_size: None,
            max_total_size: None,
            max_ratio: None,
            ..Limits::default()
        };
        let budget = budget_with(limits);
        let mut scope = budget.start_entry().unwrap();
        scope.charge_out(u64::MAX).unwrap();
        scope.charge_out(u64::MAX).unwrap();
    }
}
