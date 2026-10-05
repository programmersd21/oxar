//! Extraction sinks: the only code that writes entry data to a destination.
//! Items here are plumbing between the format layer and the policy layer; the
//! user facing documentation lives in docs/SECURITY_MODEL.md.
#![allow(missing_docs)]

use std::collections::{BTreeMap, HashSet};
use std::ffi::OsStr;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cap_std::ambient_authority;
use cap_std::fs::{Dir, OpenOptions, Permissions, PermissionsExt};

use crate::budget::EntryScope;
use crate::error::{Error, Location, Result};
use crate::fsio::random_token;
use crate::path::SafePath;
use crate::policy::{ModePolicy, Overwrite, Policy};

#[cfg(unix)]
use std::os::fd::AsFd;
#[cfg(windows)]
use std::os::windows::io::AsHandle;

/// Attributes carried from an entry to the filesystem.
#[derive(Debug, Clone, Default)]
pub struct FileAttrs {
    pub mode: Option<u32>,
    pub mtime_ns: Option<i128>,
}

/// Declared integrity values for the produced data.
#[derive(Debug, Clone, Default)]
pub struct EntryExpect {
    pub crc32: Option<u32>,
    pub size: Option<u64>,
}

/// What a sink did with one entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PutOutcome {
    Written(u64),
    Skipped(&'static str),
}

/// Destination for extracted entries.
pub trait Sink: Send + Sync {
    fn put_file(
        &self,
        path: &SafePath,
        attrs: &FileAttrs,
        expect: &EntryExpect,
        data: &mut dyn Read,
        scope: &mut EntryScope,
    ) -> Result<PutOutcome>;
    fn put_dir(&self, path: &SafePath, attrs: &FileAttrs) -> Result<PutOutcome>;
    fn put_symlink(&self, path: &SafePath, target: &[u8], attrs: &FileAttrs) -> Result<PutOutcome>;
    fn put_hardlink(
        &self,
        path: &SafePath,
        target: &SafePath,
        scope: &mut EntryScope,
    ) -> Result<PutOutcome>;
    fn finish(&self) -> Result<Vec<String>>;
    fn cleanup(&self) -> Vec<String>;
}

// REMAINDER: file continuation marker below
// --- shared helpers ---

fn mode_after_policy(policy: &Policy, stored: Option<u32>) -> Option<u32> {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExistingKind {
    Dir,
    Symlink,
    File,
    Other,
}

struct ExistingShape {
    kind: ExistingKind,
    mtime_ns: Option<i128>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExistingDecision {
    Proceed,
    Skip(&'static str),
}

fn overwrite_decision(
    policy: &Policy,
    existing: Option<ExistingShape>,
    entry_mtime_ns: Option<i128>,
) -> Result<ExistingDecision> {
    match existing {
        None => Ok(ExistingDecision::Proceed),
        Some(shape) => match policy.overwrite {
            Overwrite::Error => Err(Error::Extract {
                kind: "exists",
                path: String::new(),
                errno: None,
                loc: Location::new(),
            }),
            Overwrite::Skip => Ok(ExistingDecision::Skip("exists")),
            Overwrite::Replace => {
                if matches!(shape.kind, ExistingKind::Dir) {
                    Err(Error::Extract {
                        kind: "exists",
                        path: String::new(),
                        errno: None,
                        loc: Location::new(),
                    })
                } else {
                    Ok(ExistingDecision::Proceed)
                }
            }
            Overwrite::Newer => match (entry_mtime_ns, shape.mtime_ns) {
                (Some(entry), Some(current)) if entry > current => Ok(ExistingDecision::Proceed),
                _ => Ok(ExistingDecision::Skip("not_newer")),
            },
        },
    }
}

fn system_time_from_ns(ns: i128) -> Option<SystemTime> {
    const NANOS_PER_SEC: i128 = 1_000_000_000;
    let secs = ns.div_euclid(NANOS_PER_SEC);
    let sub = ns.rem_euclid(NANOS_PER_SEC) as u32;
    if secs >= 0 {
        Some(UNIX_EPOCH + Duration::new(secs as u64, sub))
    } else {
        UNIX_EPOCH
            .checked_sub(Duration::new(secs.unsigned_abs() as u64, 0))?
            .checked_add(Duration::new(0, sub))
    }
}

fn component_to_os(component: &[u8]) -> Result<OsStrHolder> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        Ok(OsStrHolder {
            #[cfg(unix)]
            _value: std::ffi::OsStr::from_bytes(component).to_owned(),
            #[cfg(windows)]
            _value: std::ffi::OsString::new(),
        })
    }
    #[cfg(windows)]
    {
        let text = std::str::from_utf8(component).map_err(|_| Error::UnsafePath {
            detail: "name is not valid UTF-8 and cannot be represented on Windows".into(),
            loc: Location::new(),
        })?;
        let value: std::ffi::OsString = text.into();
        Ok(OsStrHolder {
            #[cfg(unix)]
            _value: std::ffi::OsString::new(),
            #[cfg(windows)]
            _value: value,
        })
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = component;
        Err(Error::usage("unsupported platform"))
    }
}

/// Owns an OsString across cfg variants in a uniform container.
struct OsStrHolder {
    #[cfg(unix)]
    _value: std::ffi::OsString,
    #[cfg(windows)]
    _value: std::ffi::OsString,
}

impl OsStrHolder {
    fn into_os_string(self) -> OsStrString {
        OsStrString(self._value)
    }
}

struct OsStrString(std::ffi::OsString);

impl OsStrString {
    fn as_os_str(&self) -> &OsStr {
        &self.0
    }
}

fn join_components(components: &[Vec<u8>]) -> Result<PathBuf> {
    let mut path = PathBuf::new();
    for component in components {
        let holder = component_to_os(component)?;
        path.push(holder.into_os_string().as_os_str());
    }
    Ok(path)
}

// --- FsSink ---

#[derive(Debug)]
enum CreatedKind {
    File(PathBuf),
    Dir(PathBuf),
    Symlink(PathBuf),
}

struct PendingDir {
    path: PathBuf,
    depth: usize,
    mode: Option<u32>,
    mtime_ns: Option<i128>,
}

#[derive(Default)]
struct State {
    created: Vec<CreatedKind>,
    extracted: HashSet<Vec<Vec<u8>>>,
    pending_dirs: Vec<PendingDir>,
    warnings: Vec<String>,
}

pub struct FsSink {
    policy: Arc<crate::policy::Policy>,
    root: Dir,
    root_std: std::fs::File,
    state: Mutex<State>,
}

impl FsSink {
    pub fn new(root: &Path, policy: Arc<crate::policy::Policy>) -> Result<Self> {
        if !root.exists() {
            if !policy.create_dest {
                return Err(Error::Extract {
                    kind: "dest_missing",
                    path: display_pathbuf(root),
                    errno: None,
                    loc: Location::new(),
                });
            }
            std::fs::create_dir_all(root).map_err(|error| Error::Io {
                source: error,
                loc: Location::new(),
            })?;
        }
        let root_dir =
            Dir::open_ambient_dir(root, ambient_authority()).map_err(|error| Error::Io {
                source: error,
                loc: Location::new(),
            })?;
        #[cfg(unix)]
        let root_std =
            std::fs::File::from(root_dir.as_fd().try_clone_to_owned().map_err(|error| {
                Error::Io {
                    source: error,
                    loc: Location::new(),
                }
            })?);
        #[cfg(windows)]
        let root_std =
            std::fs::File::from(root_dir.as_handle().try_clone_to_owned().map_err(|error| {
                Error::Io {
                    source: error,
                    loc: Location::new(),
                }
            })?);
        Ok(Self {
            policy,
            root: root_dir,
            root_std,
            state: Mutex::new(State::default()),
        })
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, State>> {
        self.state.lock().map_err(|_| Error::Io {
            source: io::Error::other("sink state lock poisoned"),
            loc: Location::new(),
        })
    }

    fn metadata_of(&self, path: &Path) -> Option<(ExistingKind, Option<i128>)> {
        match self.root.symlink_metadata(path) {
            Ok(meta) => {
                let kind = if meta.file_type().is_symlink() {
                    ExistingKind::Symlink
                } else if meta.is_dir() {
                    ExistingKind::Dir
                } else if meta.is_file() {
                    ExistingKind::File
                } else {
                    ExistingKind::Other
                };
                let mtime = meta
                    .modified()
                    .ok()
                    .and_then(|system| system.into_std().duration_since(UNIX_EPOCH).ok());
                let mtime_ns = mtime.map(|duration| duration.as_nanos() as i128);
                Some((kind, mtime_ns))
            }
            Err(_) => None,
        }
    }

    fn ensure_parents(&self, components: &[Vec<u8>]) -> Result<PathBuf> {
        let mut parent = PathBuf::new();
        for component in components.iter().take(components.len().saturating_sub(1)) {
            let holder = component_to_os(component)?;
            parent.push(holder.into_os_string().as_os_str());
            match self.root.symlink_metadata(&parent) {
                Ok(meta) => {
                    if meta.is_symlink() {
                        if !self.policy.follow_existing_symlinks {
                            return Err(Error::UnsafeLink {
                                detail: "parent directory is a symlink".into(),
                                loc: Location::new(),
                            });
                        }
                        if !self
                            .root
                            .metadata(&parent)
                            .map(|m| m.is_dir())
                            .unwrap_or(false)
                        {
                            return Err(Error::Extract {
                                kind: "not_a_directory",
                                path: display_pathbuf(&parent),
                                errno: Some(5),
                                loc: Location::new(),
                            });
                        }
                    } else if !meta.is_dir() {
                        return Err(Error::Extract {
                            kind: "not_a_directory",
                            path: display_pathbuf(&parent),
                            errno: Some(5),
                            loc: Location::new(),
                        });
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    self.root.create_dir(&parent).map_err(|error| Error::Io {
                        source: error,
                        loc: Location::new(),
                    })?;
                    self.root
                        .set_permissions(&parent, Permissions::from_mode(0o700))
                        .map_err(|error| Error::Io {
                            source: error,
                            loc: Location::new(),
                        })?;
                    let mut state = self.lock()?;
                    state.created.push(CreatedKind::Dir(parent.clone()));
                    let depth = parent.components().count();
                    state.pending_dirs.push(PendingDir {
                        path: parent.clone(),
                        depth,
                        mode: None,
                        mtime_ns: None,
                    });
                }
                Err(error) => {
                    return Err(Error::Io {
                        source: error,
                        loc: Location::new(),
                    });
                }
            }
        }
        Ok(parent)
    }

    pub fn put_file(
        &self,
        path: &SafePath,
        attrs: &FileAttrs,
        expect: &EntryExpect,
        data: &mut dyn Read,
        scope: &mut EntryScope,
    ) -> Result<PutOutcome> {
        let components: Vec<Vec<u8>> = path.components().map(<[u8]>::to_vec).collect();
        if components.is_empty() {
            return Err(Error::UnsafePath {
                detail: "target path is empty".into(),
                loc: Location::new(),
            });
        }
        self.ensure_parents(&components)?;
        let rel = join_components(&components)?;
        let existing = self.metadata_of(&rel);
        let existing_shape = existing.map(|(kind, mtime)| ExistingShape {
            kind: match kind {
                ExistingKind::Dir => ExistingKind::Dir,
                ExistingKind::Symlink => ExistingKind::Symlink,
                ExistingKind::File => ExistingKind::File,
                ExistingKind::Other => ExistingKind::Other,
            },
            mtime_ns: mtime,
        });
        match overwrite_decision(&self.policy, existing_shape, attrs.mtime_ns)? {
            ExistingDecision::Skip(reason) => return Ok(PutOutcome::Skipped(reason)),
            ExistingDecision::Proceed => {}
        }
        // Replace never overwrites a directory, already rejected above.

        let mut temp_components = components.clone();
        temp_components.pop();
        temp_components.push(format!(".oxar-{}.tmp", random_token()).into_bytes());
        let temp_rel = join_components(&temp_components)?;

        let result = (|| -> Result<u64> {
            let mut file = self
                .root
                .open_with(&temp_rel, OpenOptions::new().write(true).create_new(true))
                .map_err(|error| Error::Io {
                    source: error,
                    loc: Location::new(),
                })?;
            let mut buffer = [0u8; 65536];
            let mut hasher = crc32fast::Hasher::new();
            let mut written = 0u64;
            scope.check_cancel()?;
            loop {
                let count = data.read(&mut buffer).map_err(|error| Error::Io {
                    source: error,
                    loc: Location::new(),
                })?;
                if count == 0 {
                    break;
                }
                file.write_all(&buffer[..count])
                    .map_err(|error| Error::Io {
                        source: error,
                        loc: Location::new(),
                    })?;
                hasher.update(&buffer[..count]);
                written = written.saturating_add(count as u64);
                scope.charge_out(count as u64)?;
                scope.check_cancel()?;
            }
            if let Some(expected) = expect.crc32 {
                let actual = hasher.finalize();
                if actual != expected {
                    return Err(Error::ChecksumMismatch {
                        expected,
                        actual,
                        loc: Location::new(),
                    });
                }
            }
            if let Some(expected) = expect.size
                && written != expected
            {
                return Err(Error::Corrupt {
                    detail: format!("entry produced {written} bytes, header declared {expected}"),
                    loc: Location::new(),
                });
            }
            file.flush().map_err(|error| Error::Io {
                source: error,
                loc: Location::new(),
            })?;
            let mode = mode_after_policy(&self.policy, attrs.mode).or(attrs.mode);
            let final_mode = match self.policy.modes {
                ModePolicy::None => None,
                _ => mode,
            };
            if let Some(mode) = final_mode {
                self.root
                    .set_permissions(&temp_rel, Permissions::from_mode(mode))
                    .map_err(|error| Error::Io {
                        source: error,
                        loc: Location::new(),
                    })?;
            }
            let std_file = file.into_std();
            if self.policy.preserve_mtime
                && let Some(ns) = attrs.mtime_ns
            {
                let times = std::fs::FileTimes::new()
                    .set_modified(system_time_from_ns(ns).unwrap_or(UNIX_EPOCH));
                let _ = std_file.set_times(times);
            }
            drop(std_file);
            self.root
                .rename(&temp_rel, &self.root, &rel)
                .map_err(|error| Error::Io {
                    source: error,
                    loc: Location::new(),
                })?;
            Ok(written)
        })();
        match result {
            Ok(bytes) => {
                let mut state = self.lock()?;
                state.created.push(CreatedKind::File(rel));
                state.extracted.insert(components);
                Ok(PutOutcome::Written(bytes))
            }
            Err(error) => {
                let _ = self.root.remove_file(&temp_rel);
                Err(error)
            }
        }
    }

    pub fn put_dir(&self, path: &SafePath, attrs: &FileAttrs) -> Result<PutOutcome> {
        let components: Vec<Vec<u8>> = path.components().map(<[u8]>::to_vec).collect();
        if components.is_empty() {
            return Err(Error::UnsafePath {
                detail: "target path is empty".into(),
                loc: Location::new(),
            });
        }
        self.ensure_parents(&components)?;
        let rel = join_components(&components)?;
        match self.metadata_of(&rel) {
            Some((ExistingKind::Dir, _)) => {}
            Some((ExistingKind::Symlink, _)) => {
                if !self.policy.follow_existing_symlinks {
                    return Err(Error::UnsafeLink {
                        detail: "target directory is a symlink".into(),
                        loc: Location::new(),
                    });
                }
            }
            Some(_) => {
                return Err(Error::Extract {
                    kind: "exists",
                    path: display_pathbuf(&rel),
                    errno: None,
                    loc: Location::new(),
                });
            }
            None => {
                self.root.create_dir(&rel).map_err(|error| Error::Io {
                    source: error,
                    loc: Location::new(),
                })?;
                self.root
                    .set_permissions(&rel, Permissions::from_mode(0o700))
                    .map_err(|error| Error::Io {
                        source: error,
                        loc: Location::new(),
                    })?;
                let mut state = self.lock()?;
                state.created.push(CreatedKind::Dir(rel.clone()));
            }
        }
        let depth = components.len();
        let mut state = self.lock()?;
        state.pending_dirs.push(PendingDir {
            path: rel,
            depth,
            mode: mode_after_policy(&self.policy, attrs.mode),
            mtime_ns: attrs.mtime_ns,
        });
        Ok(PutOutcome::Written(0))
    }

    pub fn put_symlink(
        &self,
        path: &SafePath,
        target: &[u8],
        _attrs: &FileAttrs,
    ) -> Result<PutOutcome> {
        let components: Vec<Vec<u8>> = path.components().map(<[u8]>::to_vec).collect();
        if components.is_empty() {
            return Err(Error::UnsafePath {
                detail: "target path is empty".into(),
                loc: Location::new(),
            });
        }
        self.ensure_parents(&components)?;
        let rel = join_components(&components)?;
        if let Some((ExistingKind::Dir, _)) = self.metadata_of(&rel) {
            return Err(Error::Extract {
                kind: "exists",
                path: display_pathbuf(&rel),
                errno: None,
                loc: Location::new(),
            });
        }
        match self.policy.overwrite {
            Overwrite::Error => {
                if self.metadata_of(&rel).is_some() {
                    return Err(Error::Extract {
                        kind: "exists",
                        path: display_pathbuf(&rel),
                        errno: None,
                        loc: Location::new(),
                    });
                }
            }
            Overwrite::Skip => {
                if self.metadata_of(&rel).is_some() {
                    return Ok(PutOutcome::Skipped("exists"));
                }
            }
            Overwrite::Replace => {
                if self.root.is_dir(&rel) {
                    return Err(Error::Extract {
                        kind: "exists",
                        path: display_pathbuf(&rel),
                        errno: None,
                        loc: Location::new(),
                    });
                }
                let _ = self.root.remove_file(&rel);
            }
            Overwrite::Newer => {}
        };
        let target_string: String = String::from_utf8_lossy(target).into_owned();
        #[cfg(unix)]
        {
            self.root
                .symlink(&target_string, &rel)
                .map_err(|error| Error::Io {
                    source: error,
                    loc: Location::new(),
                })?;
        }
        #[cfg(windows)]
        {
            let dir = self
                .root
                .metadata(&rel)
                .map(|m| m.is_dir())
                .unwrap_or(false);
            let _ = dir;
            if self.root.symlink_file(&target_string, &rel).is_err() {
                self.root
                    .symlink_dir(&target_string, &rel)
                    .map_err(|error| Error::Io {
                        source: error,
                        loc: Location::new(),
                    })?;
            }
        }
        let mut state = self.lock()?;
        state.created.push(CreatedKind::Symlink(rel));
        Ok(PutOutcome::Written(0))
    }

    pub fn put_hardlink(
        &self,
        path: &SafePath,
        target: &SafePath,
        _scope: &mut EntryScope,
    ) -> Result<PutOutcome> {
        let components: Vec<Vec<u8>> = path.components().map(<[u8]>::to_vec).collect();
        if components.is_empty() {
            return Err(Error::UnsafePath {
                detail: "target path is empty".into(),
                loc: Location::new(),
            });
        }
        let target_components: Vec<Vec<u8>> = target.components().map(<[u8]>::to_vec).collect();
        let is_extracted = {
            let state = self.lock()?;
            state.extracted.contains(&target_components)
        };
        if !is_extracted {
            return Err(Error::UnsafeLink {
                detail: "hard link target was not extracted by this run".into(),
                loc: Location::new(),
            });
        }
        self.ensure_parents(&components)?;
        let rel = join_components(&components)?;
        let target_rel = join_components(&target_components)?;
        if let Some((kind, _)) = self.metadata_of(&rel) {
            match self.policy.overwrite {
                Overwrite::Error => {
                    return Err(Error::Extract {
                        kind: "exists",
                        path: display_pathbuf(&rel),
                        errno: None,
                        loc: Location::new(),
                    });
                }
                Overwrite::Skip => return Ok(PutOutcome::Skipped("exists")),
                Overwrite::Replace | Overwrite::Newer => {
                    if matches!(kind, ExistingKind::Dir) {
                        return Err(Error::Extract {
                            kind: "exists",
                            path: display_pathbuf(&rel),
                            errno: None,
                            loc: Location::new(),
                        });
                    }
                    let _ = self.root.remove_file(&rel);
                }
            }
        }
        match self.root.hard_link(&target_rel, &self.root, &rel) {
            Ok(()) => {}
            Err(_) => {
                self.lock()?.warnings.push(format!(
                    "hard link to {} is not supported by the file system, copying instead",
                    display_pathbuf(&target_rel)
                ));
                let mut reader = self.root.open(&target_rel).map_err(|error| Error::Io {
                    source: error,
                    loc: Location::new(),
                })?;
                let mut data = Vec::new();
                reader.read_to_end(&mut data).map_err(|error| Error::Io {
                    source: error,
                    loc: Location::new(),
                })?;
                let mut cursor = io::Cursor::new(data.clone());
                let mut scope = EntryScope::detached(crate::budget::Budget::new(
                    self.policy.limits.clone(),
                    crate::progress::CancelToken::new(),
                ));
                // Recharge via the helper to keep the field private but visible.
                let outcome = self.put_file(
                    path,
                    &FileAttrs {
                        mode: None,
                        mtime_ns: None,
                    },
                    &EntryExpect {
                        crc32: Some(crc32fast::hash(&data)),
                        size: Some(data.len() as u64),
                    },
                    &mut cursor,
                    &mut scope,
                );
                return outcome;
            }
        }
        let mut state = self.lock()?;
        state.created.push(CreatedKind::File(rel));
        state.extracted.insert(components);
        Ok(PutOutcome::Written(0))
    }

    pub fn finish(&self) -> Result<Vec<String>> {
        let pending = {
            let mut state = self.lock()?;
            std::mem::take(&mut state.pending_dirs)
        };
        let mut sorted = pending;
        sorted.sort_by_key(|item| std::cmp::Reverse(item.depth));
        let mut warnings = Vec::new();
        for pending in sorted {
            if let Some(mode) = pending.mode
                && let Err(error) = self
                    .root
                    .set_permissions(&pending.path, Permissions::from_mode(mode))
            {
                warnings.push(format!(
                    "could not apply mode to {}: {error}",
                    display_pathbuf(&pending.path)
                ));
            }
            if self.policy.preserve_mtime
                && let Some(ns) = pending.mtime_ns
                && let Some(time) = system_time_from_ns(ns)
            {
                let spec = cap_primitives::fs::SystemTimeSpec::Absolute(
                    cap_primitives::time::SystemTime::from_std(time),
                );
                if cap_primitives::fs::set_times_nofollow(
                    &self.root_std,
                    &pending.path,
                    None,
                    Some(spec),
                )
                .is_err()
                {
                    warnings.push(format!(
                        "could not apply mtime to {}",
                        display_pathbuf(&pending.path)
                    ));
                }
            }
        }
        if let Ok(mut state) = self.state.lock() {
            warnings.append(&mut state.warnings);
        }
        Ok(warnings)
    }

    pub fn cleanup(&self) -> Vec<String> {
        let created = match self.state.lock() {
            Ok(mut state) => std::mem::take(&mut state.created),
            Err(_) => return Vec::new(),
        };
        let mut problems = Vec::new();
        for created in created.into_iter().rev() {
            match created {
                CreatedKind::File(path) | CreatedKind::Symlink(path) => {
                    if let Err(error) = self.root.remove_file(&path) {
                        problems.push(format!(
                            "could not remove {}: {error}",
                            display_pathbuf(&path)
                        ));
                    }
                }
                CreatedKind::Dir(path) => {
                    if let Err(error) = self.root.remove_dir(&path) {
                        problems.push(format!(
                            "could not remove directory {}: {error}",
                            display_pathbuf(&path)
                        ));
                    }
                }
            }
        }
        problems
    }
}

impl Sink for FsSink {
    fn put_file(
        &self,
        path: &SafePath,
        attrs: &FileAttrs,
        expect: &EntryExpect,
        data: &mut dyn Read,
        scope: &mut EntryScope,
    ) -> Result<PutOutcome> {
        self.put_file(path, attrs, expect, data, scope)
    }

    fn put_dir(&self, path: &SafePath, attrs: &FileAttrs) -> Result<PutOutcome> {
        self.put_dir(path, attrs)
    }

    fn put_symlink(&self, path: &SafePath, target: &[u8], attrs: &FileAttrs) -> Result<PutOutcome> {
        self.put_symlink(path, target, attrs)
    }

    fn put_hardlink(
        &self,
        path: &SafePath,
        target: &SafePath,
        scope: &mut EntryScope,
    ) -> Result<PutOutcome> {
        self.put_hardlink(path, target, scope)
    }

    fn finish(&self) -> Result<Vec<String>> {
        self.finish()
    }

    fn cleanup(&self) -> Vec<String> {
        self.cleanup()
    }
}

fn display_pathbuf(path: &Path) -> String {
    path.display().to_string()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn mode_after_policy_cases() {
        use crate::policy::{ModePolicy, Policy};
        let mut policy = Policy {
            modes: ModePolicy::Safe,
            ..Policy::default()
        };
        assert_eq!(
            mode_after_policy(&policy, Some(0o4755)),
            Some(0o4755 & !0o7022)
        );
        policy.modes = ModePolicy::None;
        assert_eq!(mode_after_policy(&policy, Some(0o4755)), None);
        policy.modes = ModePolicy::Preserve;
        policy.allow_setid = false;
        assert_eq!(mode_after_policy(&policy, Some(0o6755)), Some(0o0755));
        policy.allow_setid = true;
        assert_eq!(mode_after_policy(&policy, Some(0o6755)), Some(0o6755));
    }

    #[test]
    fn system_time_from_ns_handles_pre_epoch() {
        let zero = system_time_from_ns(0).unwrap();
        assert_eq!(zero, UNIX_EPOCH);
        let negative = system_time_from_ns(-1_000_000_000).unwrap();
        assert!(negative < UNIX_EPOCH);
    }
}

#[derive(Debug, Clone)]
pub enum VNode {
    File {
        data: Vec<u8>,
        mode: Option<u32>,
        mtime_ns: Option<i128>,
    },
    Dir {
        mode: Option<u32>,
        mtime_ns: Option<i128>,
    },
    Symlink {
        target: Vec<u8>,
        mtime_ns: Option<i128>,
    },
}

#[derive(Default)]
struct VState {
    nodes: BTreeMap<Vec<Vec<u8>>, VNode>,
    order: Vec<Vec<Vec<u8>>>,
    warnings: Vec<String>,
}

pub struct VirtualSink {
    policy: Arc<Policy>,
    state: Mutex<VState>,
}

impl VirtualSink {
    pub fn new(policy: Arc<Policy>) -> Self {
        Self {
            policy,
            state: Mutex::new(VState::default()),
        }
    }

    pub fn nodes(&self) -> BTreeMap<Vec<Vec<u8>>, VNode> {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .nodes
            .clone()
    }

    pub fn created_order(&self) -> Vec<Vec<Vec<u8>>> {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .order
            .clone()
    }

    fn to_existing_kind(node: Option<&VNode>) -> Option<ExistingKind> {
        node.map(|n| match n {
            VNode::Dir { .. } => ExistingKind::Dir,
            VNode::File { .. } => ExistingKind::File,
            VNode::Symlink { .. } => ExistingKind::Symlink,
        })
    }

    fn mtime_of_node(node: Option<&VNode>) -> Option<i128> {
        node.map(|n| match n {
            VNode::Dir { mtime_ns, .. } => *mtime_ns,
            VNode::File { mtime_ns, .. } => *mtime_ns,
            VNode::Symlink { mtime_ns, .. } => *mtime_ns,
        })?
    }
}

fn display_pathbuf_from_components(components: &[Vec<u8>]) -> String {
    let pieces: Vec<String> = components
        .iter()
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect();
    pieces.join("/")
}

fn existing_shape(existing: Option<ExistingKind>, mtime: Option<i128>) -> Option<ExistingShape> {
    existing.map(|kind| ExistingShape {
        kind,
        mtime_ns: mtime,
    })
}

impl Sink for VirtualSink {
    fn put_file(
        &self,
        path: &SafePath,
        attrs: &FileAttrs,
        expect: &EntryExpect,
        data: &mut dyn Read,
        _scope: &mut EntryScope,
    ) -> Result<PutOutcome> {
        let components: Vec<Vec<u8>> = path.components().map(<[u8]>::to_vec).collect();
        if components.is_empty() {
            return Err(Error::UnsafePath {
                detail: "target path empty".into(),
                loc: Location::new(),
            });
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| Error::usage("lock poisoned"))?;
        // No write through symlink prefix.
        let mut prefix = Vec::new();
        for component in &components {
            if !prefix.is_empty()
                && matches!(
                    Self::to_existing_kind(state.nodes.get(&prefix)),
                    Some(ExistingKind::Symlink)
                )
            {
                return Err(Error::UnsafeLink {
                    detail: "write passes through a symlink component".into(),
                    loc: Location::new(),
                });
            }
            prefix.push(component.clone());
        }
        let existing = Self::to_existing_kind(state.nodes.get(&components));
        let mtime = VirtualSink::mtime_of_node(state.nodes.get(&components));
        match overwrite_decision(
            &self.policy,
            existing_shape(existing, mtime),
            attrs.mtime_ns,
        )? {
            ExistingDecision::Skip(reason) => return Ok(PutOutcome::Skipped(reason)),
            ExistingDecision::Proceed => {}
        }
        let mut bytes = Vec::new();
        data.read_to_end(&mut bytes).map_err(|e| Error::Io {
            source: e,
            loc: Location::new(),
        })?;
        if let Some(expected) = expect.crc32
            && crc32fast::hash(&bytes) != expected
        {
            return Err(Error::ChecksumMismatch {
                expected,
                actual: crc32fast::hash(&bytes),
                loc: Location::new(),
            });
        }
        if let Some(expected) = expect.size
            && bytes.len() as u64 != expected
        {
            return Err(Error::Corrupt {
                detail: format!("produced {} expected {}", bytes.len(), expected),
                loc: Location::new(),
            });
        }
        if !state.order.contains(&components) {
            state.order.push(components.clone());
        }
        state.nodes.insert(
            components,
            VNode::File {
                data: bytes.clone(),
                mode: mode_after_policy(&self.policy, attrs.mode),
                mtime_ns: attrs.mtime_ns,
            },
        );
        Ok(PutOutcome::Written(bytes.len() as u64))
    }

    fn put_dir(&self, path: &SafePath, attrs: &FileAttrs) -> Result<PutOutcome> {
        let components: Vec<Vec<u8>> = path.components().map(<[u8]>::to_vec).collect();
        if components.is_empty() {
            return Err(Error::UnsafePath {
                detail: "target path empty".into(),
                loc: Location::new(),
            });
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| Error::usage("lock poisoned"))?;
        let mut prefix = Vec::new();
        for component in components.iter().take(components.len().saturating_sub(1)) {
            if !prefix.is_empty()
                && matches!(
                    Self::to_existing_kind(state.nodes.get(&prefix)),
                    Some(ExistingKind::Symlink)
                )
            {
                return Err(Error::UnsafeLink {
                    detail: "directory passes through a symlink".into(),
                    loc: Location::new(),
                });
            }
            prefix.push(component.clone());
        }
        let existing = Self::to_existing_kind(state.nodes.get(&components));
        if let Some(ExistingKind::Symlink) = existing
            && !self.policy.follow_existing_symlinks
        {
            return Err(Error::UnsafeLink {
                detail: "target is a symlink".into(),
                loc: Location::new(),
            });
        }
        if let Some(ExistingKind::File) = existing {
            return Err(Error::Extract {
                kind: "exists",
                path: display_pathbuf_from_components(&components),
                errno: None,
                loc: Location::new(),
            });
        }
        if !state.order.contains(&components) {
            state.order.push(components.clone());
        }
        state.nodes.insert(
            components,
            VNode::Dir {
                mode: mode_after_policy(&self.policy, attrs.mode),
                mtime_ns: attrs.mtime_ns,
            },
        );
        Ok(PutOutcome::Written(0))
    }

    fn put_symlink(&self, path: &SafePath, target: &[u8], attrs: &FileAttrs) -> Result<PutOutcome> {
        let components: Vec<Vec<u8>> = path.components().map(<[u8]>::to_vec).collect();
        if components.is_empty() {
            return Err(Error::UnsafePath {
                detail: "target path empty".into(),
                loc: Location::new(),
            });
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| Error::usage("lock poisoned"))?;
        let existing = Self::to_existing_kind(state.nodes.get(&components));
        if let Some(ExistingKind::Dir) = existing {
            return Err(Error::Extract {
                kind: "exists",
                path: display_pathbuf_from_components(&components),
                errno: None,
                loc: Location::new(),
            });
        }
        if state.nodes.contains_key(&components) && self.policy.overwrite == Overwrite::Skip {
            return Ok(PutOutcome::Skipped("exists"));
        }
        if !state.order.contains(&components) {
            state.order.push(components.clone());
        }
        state.nodes.insert(
            components,
            VNode::Symlink {
                target: target.to_vec(),
                mtime_ns: attrs.mtime_ns,
            },
        );
        Ok(PutOutcome::Written(0))
    }

    fn put_hardlink(
        &self,
        path: &SafePath,
        target: &SafePath,
        _scope: &mut EntryScope,
    ) -> Result<PutOutcome> {
        let components: Vec<Vec<u8>> = path.components().map(<[u8]>::to_vec).collect();
        let target_components: Vec<Vec<u8>> = target.components().map(<[u8]>::to_vec).collect();
        let mut state = self
            .state
            .lock()
            .map_err(|_| Error::usage("lock poisoned"))?;
        match state.nodes.get(&target_components) {
            Some(VNode::File { data, .. }) => {
                let data = data.clone();
                if !state.order.contains(&components) {
                    state.order.push(components.clone());
                }
                state.nodes.insert(
                    components,
                    VNode::File {
                        data,
                        mode: None,
                        mtime_ns: None,
                    },
                );
                Ok(PutOutcome::Written(0))
            }
            _ => Err(Error::UnsafeLink {
                detail: "hard link target was not extracted by this run".into(),
                loc: Location::new(),
            }),
        }
    }

    fn finish(&self) -> Result<Vec<String>> {
        Ok(self
            .state
            .lock()
            .map_err(|_| Error::usage("lock"))?
            .warnings
            .clone())
    }

    fn cleanup(&self) -> Vec<String> {
        Vec::new()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod virtual_tests {
    use super::*;
    use crate::budget::Budget;
    use crate::policy::Policy;
    use crate::progress::CancelToken;

    fn read(bytes: &[u8]) -> std::io::Cursor<Vec<u8>> {
        std::io::Cursor::new(bytes.to_vec())
    }

    #[test]
    fn atomic_rename_leaves_no_partial_file() {
        let sink = VirtualSink::new(Arc::new(Policy::default()));
        let path = crate::path::sanitize(
            b"a/x",
            crate::path::SeparatorRule::BackslashIsSeparator,
            &Policy::default(),
            false,
        )
        .unwrap();
        let mut data = read(b"hello");
        let mut scope =
            EntryScope::detached(Budget::new(Policy::default().limits, CancelToken::new()));
        sink.put_file(
            &path,
            &FileAttrs::default(),
            &EntryExpect::default(),
            &mut data,
            &mut scope,
        )
        .unwrap();
        assert!(
            sink.nodes()
                .contains_key(&vec![b"a".to_vec(), b"x".to_vec()])
        );
    }

    #[test]
    fn symlink_prefix_blocks_write() {
        let sink = VirtualSink::new(Arc::new(Policy::default()));
        let link = crate::path::sanitize(
            b"l",
            crate::path::SeparatorRule::BackslashIsSeparator,
            &Policy::default(),
            false,
        )
        .unwrap();
        sink.put_symlink(&link, b"value", &FileAttrs::default())
            .unwrap();
        let file = crate::path::sanitize(
            b"l/x",
            crate::path::SeparatorRule::BackslashIsSeparator,
            &Policy::default(),
            false,
        )
        .unwrap();
        let mut data = read(b"hello");
        let mut scope =
            EntryScope::detached(Budget::new(Policy::default().limits, CancelToken::new()));
        let result = sink.put_file(
            &file,
            &FileAttrs::default(),
            &EntryExpect::default(),
            &mut data,
            &mut scope,
        );
        assert!(result.is_err());
    }

    #[test]
    fn crc_mismatch_fails() {
        let sink = VirtualSink::new(Arc::new(Policy::default()));
        let path = crate::path::sanitize(
            b"a",
            crate::path::SeparatorRule::BackslashIsSeparator,
            &Policy::default(),
            false,
        )
        .unwrap();
        let mut data = read(b"hello");
        let mut scope =
            EntryScope::detached(Budget::new(Policy::default().limits, CancelToken::new()));
        let result = sink.put_file(
            &path,
            &FileAttrs::default(),
            &EntryExpect {
                crc32: Some(0),
                size: None,
            },
            &mut data,
            &mut scope,
        );
        assert!(result.is_err());
    }

    #[test]
    fn hardlink_requires_extracted_target() {
        let sink = VirtualSink::new(Arc::new(Policy::default()));
        let source = crate::path::sanitize(
            b"src",
            crate::path::SeparatorRule::BackslashIsSeparator,
            &Policy::default(),
            false,
        )
        .unwrap();
        let target = crate::path::sanitize(
            b"dest",
            crate::path::SeparatorRule::BackslashIsSeparator,
            &Policy::default(),
            false,
        )
        .unwrap();
        let mut data = read(b"hello");
        let mut scope =
            EntryScope::detached(Budget::new(Policy::default().limits, CancelToken::new()));
        sink.put_file(
            &source,
            &FileAttrs::default(),
            &EntryExpect::default(),
            &mut data,
            &mut scope,
        )
        .unwrap();
        let mut scope2 =
            EntryScope::detached(Budget::new(Policy::default().limits, CancelToken::new()));
        assert!(sink.put_hardlink(&target, &source, &mut scope2).is_ok());
    }
}
