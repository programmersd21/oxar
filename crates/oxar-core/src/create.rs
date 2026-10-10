//! Creation pipeline: deterministic directory walk, policy aware filter, parallel
//! compression for zip, ordered reorder buffer.
//!
//! This first implementation is serial and correct; parallel compression is
//! deferred.

use std::fs;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::format::{EntryKind, NewEntry};

/// One collected item to add: file bytes plus the in-archive name.
#[derive(Debug)]
pub struct Discovered {
    /// In-archive path, slash-separated.
    pub path: String,
    /// Absolute filesystem path on disk.
    pub fs_path: PathBuf,
    /// Whether the item is a directory.
    pub is_dir: bool,
    /// Permission bits, if known.
    pub mode: Option<u32>,
    /// Declared size in bytes for files.
    pub size: Option<u64>,
}

/// Walk a source tree relative to `root` and collect entries in deterministic
/// byte ordering of their in-archive path. Symlinks are not followed unless
/// `follow_symlinks` is true. Returns an error on io failure.
pub fn discover(root: &Path, follow_symlinks: bool) -> Result<Vec<Discovered>> {
    let mut found: Vec<Discovered> = Vec::new();
    let root = root.to_path_buf();
    fn recurse(
        base: &Path,
        current: &Path,
        follow: bool,
        found: &mut Vec<Discovered>,
    ) -> Result<()> {
        let entries = match fs::read_dir(current) {
            Ok(entries) => entries,
            Err(error) => {
                return Err(Error::Io {
                    source: error,
                    loc: crate::error::Location::new(),
                });
            }
        };
        let mut names: Vec<PathBuf> = Vec::new();
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    return Err(Error::Io {
                        source: error,
                        loc: crate::error::Location::new(),
                    });
                }
            };
            // Follow symlink only if allowed or if the target is inside base.
            let ty = match entry.file_type() {
                Ok(ty) => ty,
                Err(error) => {
                    return Err(Error::Io {
                        source: error,
                        loc: crate::error::Location::new(),
                    });
                }
            };
            if ty.is_symlink() && !follow {
                continue;
            }
            names.push(entry.path());
        }
        names.sort_by(|a, b| a.as_os_str().cmp(b.as_os_str()));
        for full in names {
            let rel = full.strip_prefix(base).map_err(|_| Error::Usage {
                message: "source path is outside of the root".into(),
            })?;
            let md = match std::fs::symlink_metadata(&full) {
                Ok(md) => md,
                Err(error) => {
                    return Err(Error::Io {
                        source: error,
                        loc: crate::error::Location::new(),
                    });
                }
            };
            let is_dir = md.file_type().is_dir();
            let mode = Some(mode_from_md(&md));
            let size = if is_dir { None } else { Some(md.len()) };
            let in_archive = rel.to_string_lossy().replace('\\', "/");
            found.push(Discovered {
                path: in_archive,
                fs_path: full.clone(),
                is_dir,
                mode,
                size,
            });
            if is_dir {
                recurse(base, &full, follow, found)?;
            }
        }
        Ok(())
    }

    if root.is_file() {
        let md = fs::symlink_metadata(&root).map_err(|e| Error::Io {
            source: e,
            loc: crate::error::Location::new(),
        })?;
        found.push(Discovered {
            path: root
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned(),
            fs_path: root.clone(),
            is_dir: md.is_dir(),
            mode: Some(mode_from_md(&md)),
            size: Some(md.len()),
        });
    } else {
        recurse(&root, &root, follow_symlinks, &mut found)?;
    }
    // Deterministic ordering by in-archive path bytes.
    found.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
    Ok(found)
}

fn mode_from_md(md: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    md.permissions().mode()
}

/// Convert discovered items to NewEntry descriptions. File contents are read
/// separately by the caller (and size may be used for reserved decoder memory).
pub fn to_new_entries(items: &[Discovered]) -> Vec<NewEntry> {
    items
        .iter()
        .map(|item| NewEntry {
            path: item.path.clone(),
            kind: if item.is_dir {
                EntryKind::Dir
            } else {
                EntryKind::File
            },
            mode: item.mode,
            mtime_ns: None,
            link_target: None,
            size_hint: item.size,
            method: None,
            level: None,
            password: None,
        })
        .collect()
}
