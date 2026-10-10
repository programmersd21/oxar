//! Extraction planner and executor. Processes entries as the reader yields
//! them, so sequential formats can be handled without repositioning.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;

use crate::budget::{Budget, EntryScope};
use crate::error::{Error, Location, Result};
use crate::format::{ArchiveReader, EntryKind, Format};
use crate::path::{SafePath, SeparatorRule, sanitize, validate_symlink_target};
use crate::policy::{Duplicates, LinkPolicy, ModePolicy, Policy, SpecialFilesPolicy};
use crate::progress::{ProgressEvent, ProgressKind, ProgressSink};
use crate::sink::{EntryExpect, FileAttrs, PutOutcome, Sink};

/// An entry the extractor chose not to write.
#[derive(Debug, Clone)]
pub struct Skipped {
    /// Display path of the skipped entry.
    pub path: String,
    /// Reason the entry was not written.
    pub reason: String,
}

/// Summary of one extraction run.
#[derive(Debug, Clone)]
pub struct ExtractReport {
    /// Number of entries visited.
    pub entries: u64,
    /// Total bytes written to the sink.
    pub bytes_written: u64,
    /// Entries skipped by policy.
    pub skipped: Vec<Skipped>,
    /// Non-fatal warnings raised during extraction.
    pub warnings: Vec<String>,
    /// Wall-clock duration, in seconds.
    pub elapsed: f64,
}

/// How names are interpreted, per container format.
#[derive(Debug, Clone, Copy)]
pub enum NameRule {
    /// zip and 7z semantics: backslashes are separators.
    ZipLike,
    /// tar semantics: backslashes are ordinary name characters.
    TarLike,
}

impl NameRule {
    /// Build a rule from a container format.
    pub fn from_format(format: Format) -> Self {
        match format {
            Format::Tar => NameRule::TarLike,
            Format::Zip | Format::SevenZ => NameRule::ZipLike,
        }
    }

    /// The matching separator rule.
    pub fn separator_rule(self) -> SeparatorRule {
        match self {
            NameRule::ZipLike => SeparatorRule::BackslashIsSeparator,
            NameRule::TarLike => SeparatorRule::BackslashIsLiteral,
        }
    }
}

/// Extract every entry of `reader` into `sink`, enforcing `policy`.
pub fn extract(
    reader: &mut dyn ArchiveReader,
    sink: Arc<dyn Sink>,
    policy: Policy,
    progress: Option<&dyn ProgressSink>,
    cancel: &crate::progress::CancelToken,
) -> Result<ExtractReport> {
    let start = Instant::now();
    let rule = NameRule::from_format(reader.format());
    let separator_rule = rule.separator_rule();
    let host_windows = cfg!(windows);
    let budget = Budget::new(policy.limits.clone(), cancel.clone());

    let mut entries_count = 0u64;
    let mut bytes_written = 0u64;
    let mut skipped = Vec::new();
    let mut warnings = Vec::new();
    let mut seen_raw: HashSet<Vec<u8>> = HashSet::new();
    let mut seen_keys: HashMap<String, String> = HashMap::new();

    if let Some(p) = progress {
        p.emit(ProgressEvent {
            kind: ProgressKind::Start,
            path: None,
            entries_done: 0,
            entries_total: None,
            bytes_done: 0,
            bytes_total: None,
        });
    }

    loop {
        if cancel.is_cancelled() {
            if policy.cleanup_on_error {
                let _ = sink.cleanup();
            }
            return Err(Error::Cancelled);
        }
        let entry = match reader.next_entry() {
            Ok(Some(e)) => e,
            Ok(None) => break,
            Err(e) => return Err(e),
        };
        entries_count = entries_count.saturating_add(1);
        if let Some(limit) = policy.limits.max_entries
            && entries_count > limit
        {
            if policy.cleanup_on_error {
                let _ = sink.cleanup();
            }
            return Err(Error::Bomb {
                limit: "max_entries",
                limit_value: limit,
                observed: entries_count,
                loc: Location::new(),
            });
        }

        let raw_name = entry.path_bytes.clone();
        let safe: SafePath = match sanitize(&raw_name, separator_rule, &policy, host_windows) {
            Ok(s) => s,
            Err(e) => {
                if policy.cleanup_on_error {
                    let _ = sink.cleanup();
                }
                return Err(e);
            }
        };

        if let Some(prev) = seen_keys.get(safe.collision_key()) {
            if prev != safe.display() {
                if policy.cleanup_on_error {
                    let _ = sink.cleanup();
                }
                return Err(Error::Duplicate {
                    detail: format!(
                        "name collision: {} normalizes with {}",
                        safe.display(),
                        prev
                    ),
                    loc: Location::new().with_entry(safe.display().to_owned()),
                });
            }
        } else {
            seen_keys.insert(safe.collision_key().to_owned(), safe.display().to_owned());
        }

        let is_exact_dup = !seen_raw.insert(safe.raw_bytes().to_vec());
        if is_exact_dup {
            match policy.duplicates {
                Duplicates::Reject => {
                    if policy.cleanup_on_error {
                        let _ = sink.cleanup();
                    }
                    return Err(Error::Duplicate {
                        detail: format!("entry {} repeats a previous name", safe.display()),
                        loc: Location::new().with_entry(safe.display().to_owned()),
                    });
                }
                Duplicates::First => {
                    skipped.push(Skipped {
                        path: safe.display().to_owned(),
                        reason: "duplicate".into(),
                    });
                    continue;
                }
                Duplicates::Last | Duplicates::Auto => {}
            }
        }

        if let Some(p) = progress {
            p.emit(ProgressEvent {
                kind: ProgressKind::EntryStart,
                path: Some(safe.display().to_owned()),
                entries_done: entries_count.saturating_sub(1),
                entries_total: None,
                bytes_done: bytes_written,
                bytes_total: None,
            });
        }

        let outcome: Result<PutOutcome> = match entry.kind {
            EntryKind::Dir => {
                let mode = mode_after_policy(&policy, entry.mode, true);
                sink.put_dir(
                    &safe,
                    &FileAttrs {
                        mode,
                        mtime_ns: entry.mtime_ns,
                    },
                )
            }
            EntryKind::Symlink => {
                if policy.symlinks == LinkPolicy::Reject {
                    if policy.cleanup_on_error {
                        let _ = sink.cleanup();
                    }
                    return Err(Error::UnsafeLink {
                        detail: "symlinks are rejected by policy".into(),
                        loc: Location::new().with_entry(safe.display().to_owned()),
                    });
                }
                if policy.symlinks == LinkPolicy::Skip {
                    skipped.push(Skipped {
                        path: safe.display().to_owned(),
                        reason: "symlink_skipped".into(),
                    });
                    continue;
                }
                let target = entry.link_target.as_deref().unwrap_or(&[]).to_vec();
                if let Err(e) =
                    validate_symlink_target(&target, safe.depth().saturating_sub(1), &policy)
                {
                    if policy.cleanup_on_error {
                        let _ = sink.cleanup();
                    }
                    return Err(e);
                }
                sink.put_symlink(
                    &safe,
                    &target,
                    &FileAttrs {
                        mode: None,
                        mtime_ns: entry.mtime_ns,
                    },
                )
            }
            EntryKind::Hardlink => {
                if policy.hardlinks == LinkPolicy::Reject {
                    if policy.cleanup_on_error {
                        let _ = sink.cleanup();
                    }
                    return Err(Error::UnsafeLink {
                        detail: "hardlinks are rejected by policy".into(),
                        loc: Location::new().with_entry(safe.display().to_owned()),
                    });
                }
                if policy.hardlinks == LinkPolicy::Skip {
                    skipped.push(Skipped {
                        path: safe.display().to_owned(),
                        reason: "hardlink_skipped".into(),
                    });
                    continue;
                }
                let target_bytes = entry.link_target.as_deref().unwrap_or(&[]).to_vec();
                let target_safe = sanitize(&target_bytes, separator_rule, &policy, host_windows)?;
                let mut scope: EntryScope = budget.start_entry()?;
                let r = sink.put_hardlink(&safe, &target_safe, &mut scope);
                if r.is_err() && policy.cleanup_on_error {
                    let _ = sink.cleanup();
                }
                r
            }
            EntryKind::Other(kind) => {
                if policy.special_files == SpecialFilesPolicy::Reject {
                    if policy.cleanup_on_error {
                        let _ = sink.cleanup();
                    }
                    return Err(Error::SpecialFile {
                        detail: kind.to_string(),
                        loc: Location::new().with_entry(safe.display().to_owned()),
                    });
                } else {
                    skipped.push(Skipped {
                        path: safe.display().to_owned(),
                        reason: "special_skipped".into(),
                    });
                    continue;
                }
            }
            EntryKind::File => {
                let expect = EntryExpect {
                    crc32: entry.crc32,
                    size: entry.size,
                };
                let mut scope: EntryScope = budget.start_entry()?;
                let mut open = reader.open_current()?;
                let r = sink.put_file(
                    &safe,
                    &FileAttrs {
                        mode: mode_after_policy(&policy, entry.mode, false),
                        mtime_ns: entry.mtime_ns,
                    },
                    &expect,
                    open.as_mut(),
                    &mut scope,
                );
                if r.is_err() && policy.cleanup_on_error {
                    let _ = sink.cleanup();
                }
                r
            }
        };

        match outcome {
            Ok(PutOutcome::Written(n)) => bytes_written = bytes_written.saturating_add(n),
            Ok(PutOutcome::Skipped(reason)) => {
                skipped.push(Skipped {
                    path: safe.display().to_owned(),
                    reason: reason.to_owned(),
                });
                continue;
            }
            Err(e) => {
                if policy.cleanup_on_error {
                    let _ = sink.cleanup();
                }
                return Err(e.attach(&Location::new().with_entry(safe.display().to_owned())));
            }
        }

        if let Some(p) = progress {
            p.emit(ProgressEvent {
                kind: ProgressKind::EntryDone,
                path: Some(safe.display().to_owned()),
                entries_done: entries_count,
                entries_total: None,
                bytes_done: bytes_written,
                bytes_total: None,
            });
        }
    }

    let sink_warnings = sink.finish().unwrap_or_default();
    warnings.extend(sink_warnings);
    Ok(ExtractReport {
        entries: entries_count,
        bytes_written,
        skipped,
        warnings,
        elapsed: start.elapsed().as_secs_f64(),
    })
}

fn mode_after_policy(policy: &Policy, stored: Option<u32>, is_dir: bool) -> Option<u32> {
    let _ = is_dir;
    let stored = stored?;
    match policy.modes {
        ModePolicy::None => None,
        ModePolicy::Safe => Some(stored & !0o7022),
        ModePolicy::Preserve => {
            if policy.allow_setid {
                Some(stored)
            } else {
                Some(stored & !0o6000)
            }
        }
    }
}
