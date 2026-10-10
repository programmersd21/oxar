//! Integrity testing of an archive without extraction. Every entry is read
//! fully in bounded chunks, every CRC32 present is verified and every
//! declared size is re-checked against produced bytes. Content problems are
//! collected into the report rather than raised.

use std::io::Read;
use std::time::Instant;

use crate::error::{Error, Result};
use crate::format::ArchiveReader;
use crate::policy::Policy;
use crate::progress::CancelToken;
use crate::progress::{ProgressEvent, ProgressKind, ProgressSink};

#[derive(Debug, Clone)]
/// One integrity problem found while reading an archive.
pub struct Problem {
    /// Archive path of the affected entry.
    pub path: String,
    /// Stable category such as `checksum`, `size`, `io` or `open`.
    pub kind: String,
    /// Human-readable detail without secret or destination information.
    pub detail: String,
    /// Input offset when the reader can identify it.
    pub offset: Option<u64>,
}

#[derive(Debug, Clone)]
/// Summary of a full archive integrity pass.
pub struct TestReport {
    /// True when no content problems were found.
    pub ok: bool,
    /// Number of entries visited.
    pub entries: u64,
    /// Uncompressed bytes read and checked.
    pub bytes_checked: u64,
    /// Content problems found while reading entries.
    pub problems: Vec<Problem>,
    /// Wall-clock time in seconds.
    pub elapsed: f64,
}

/// Read every entry and report data errors without writing to a filesystem.
pub fn test_archive(
    reader: &mut dyn ArchiveReader,
    progress: Option<&dyn ProgressSink>,
    cancel: &CancelToken,
    policy: &Policy,
) -> Result<TestReport> {
    let start = Instant::now();
    let mut entries = 0u64;
    let mut bytes_checked = 0u64;
    let mut problems = Vec::new();

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
            return Err(Error::Cancelled);
        }
        let entry = match reader.next_entry() {
            Ok(Some(e)) => e,
            Ok(None) => break,
            Err(e) => return Err(e),
        };
        entries = entries.saturating_add(1);
        if let Some(maximum) = policy.limits.max_entries
            && entries > maximum
        {
            return Err(Error::limit("max_entries", maximum, entries));
        }
        let entry_path = entry.path.clone();
        let mut hasher = crc32fast::Hasher::new();
        let mut produced: u64 = 0;
        let cap: u64 = policy.limits.max_entry_size.unwrap_or(u64::MAX);
        let result = reader.open_current();
        match result {
            Ok(mut data) => {
                let mut buffer = [0u8; 64 * 1024];
                loop {
                    let total_cap = policy.limits.max_total_size.unwrap_or(u64::MAX);
                    let remaining_entry = cap.saturating_sub(produced);
                    let remaining_total = total_cap.saturating_sub(bytes_checked);
                    let remaining = remaining_entry.min(remaining_total);
                    let want =
                        usize::try_from(remaining.saturating_add(1).min(buffer.len() as u64))
                            .unwrap_or(buffer.len());
                    let count = match data.read(&mut buffer[..want]) {
                        Ok(c) => c,
                        Err(e) => {
                            problems.push(Problem {
                                path: entry_path.clone(),
                                kind: "io".into(),
                                detail: e.to_string(),
                                offset: None,
                            });
                            break;
                        }
                    };
                    if count == 0 {
                        break;
                    }
                    if count as u64 > remaining {
                        problems.push(Problem {
                            path: entry_path.clone(),
                            kind: "size_limit".into(),
                            detail: "entry exceeded a configured output limit".into(),
                            offset: Some(produced),
                        });
                        break;
                    }
                    if cancel.is_cancelled() {
                        return Err(Error::Cancelled);
                    }
                    hasher.update(&buffer[..count]);
                    produced += count as u64;
                    bytes_checked += count as u64;
                }
            }
            Err(error) => {
                problems.push(Problem {
                    path: entry_path.clone(),
                    kind: "open".into(),
                    detail: error.to_string(),
                    offset: None,
                });
            }
        }
        if let Some(size) = entry.size
            && produced != size
        {
            problems.push(Problem {
                path: entry_path.clone(),
                kind: "size".into(),
                detail: format!("produced {produced} bytes, declared {size}"),
                offset: None,
            });
        }
        if let Some(expected) = entry.crc32
            && hasher.finalize() != expected
        {
            problems.push(Problem {
                path: entry_path,
                kind: "checksum".into(),
                detail: "CRC32 mismatch".to_owned(),
                offset: None,
            });
        }
    }
    let ok = problems.is_empty();
    let report = TestReport {
        ok,
        entries,
        bytes_checked,
        problems,
        elapsed: start.elapsed().as_secs_f64(),
    };
    Ok(report)
}

/// Test an archive using the policy's limits.
pub fn test_all(
    reader: &mut dyn ArchiveReader,
    policy: &Policy,
    progress: Option<&dyn ProgressSink>,
    cancel: &CancelToken,
) -> Result<TestReport> {
    test_archive(reader, progress, cancel, policy)
}
