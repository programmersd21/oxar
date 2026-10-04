//! Extraction policy: every safety relevant decision in one immutable object.
//!
//! The core rules cannot be disabled by any field of this struct: rejecting
//! `..` components, absolute names, drive letters, UNC paths and NUL bytes,
//! never writing through a symlink component, the capability confinement of
//! the destination, and checksum verification when the archive stores one.
//! There is no master switch that turns the checks off; individual limits may
//! be set to `None` for trusted input.

/// What to do with symbolic link entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LinkPolicy {
    /// Create the link when its target stays inside the destination.
    #[default]
    Contained,
    /// Do not create the link; record it as skipped.
    Skip,
    /// Fail the run.
    Reject,
}

/// What to do with device, fifo and socket entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SpecialFilesPolicy {
    /// Fail the run.
    #[default]
    Reject,
    /// Do not create them; record them as skipped.
    Skip,
}

/// How stored permission bits are applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ModePolicy {
    /// Strip setuid, setgid and sticky bits, clear group and other write,
    /// keep the owner execute bit.
    #[default]
    Safe,
    /// Ignore stored modes entirely.
    None,
    /// Keep stored bits, except setuid and setgid unless `allow_setid`.
    Preserve,
}

/// What to do when the destination already contains the target name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Overwrite {
    /// Raise `ExtractionError` with kind `exists`.
    #[default]
    Error,
    /// Leave the existing object untouched and record a skip.
    Skip,
    /// Replace the existing regular file or symlink.
    Replace,
    /// Replace only when the entry mtime is newer than the existing mtime.
    Newer,
}

/// How duplicate entry names inside one archive are resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Duplicates {
    /// Tar: the last entry wins. Zip and 7z: reject.
    #[default]
    Auto,
    /// Reject any repeat of a name.
    Reject,
    /// The last entry wins.
    Last,
    /// The first entry wins, later ones are skipped.
    First,
}

/// When Windows name rules are enforced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WindowsNames {
    /// Enforce the rules when the host is Windows.
    #[default]
    Auto,
    /// Always enforce.
    Reject,
    /// Never enforce.
    Allow,
}

/// Size, count, ratio and memory limits for one operation. `None` disables a
/// limit; the default is the secure value everywhere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    /// Maximum number of entries read from one archive.
    pub max_entries: Option<u64>,
    /// Maximum bytes produced per entry.
    pub max_entry_size: Option<u64>,
    /// Maximum bytes produced per run, across all entries.
    pub max_total_size: Option<u64>,
    /// Maximum output divided by input ratio for one entry and for the run.
    pub max_ratio: Option<u64>,
    /// Output bytes an entry must reach before the ratio is checked.
    pub ratio_floor: u64,
    /// Maximum bytes per full path, after separator normalisation.
    pub max_path_bytes: Option<usize>,
    /// Maximum bytes per path component.
    pub max_component_bytes: Option<usize>,
    /// Maximum number of path components.
    pub max_depth: Option<usize>,
    /// Maximum memory a single decoder instance may reserve.
    pub max_decoder_memory: Option<u64>,
    /// Maximum bytes of one PAX extended header record set.
    pub max_pax_header_bytes: Option<u64>,
    /// Maximum bytes of zip extra fields for one entry.
    pub max_extra_bytes: Option<u64>,
    /// Maximum number of sparse regions decoded for one entry.
    pub max_sparse_regions: Option<u64>,
    /// Maximum uncompressed bytes of one 7z solid block.
    pub max_solid_block_bytes: Option<u64>,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_entries: Some(1_000_000),
            max_entry_size: Some(8 * 1024 * 1024 * 1024),
            max_total_size: Some(32 * 1024 * 1024 * 1024),
            max_ratio: Some(1000),
            ratio_floor: 64 * 1024 * 1024,
            max_path_bytes: Some(4096),
            max_component_bytes: Some(255),
            max_depth: Some(128),
            max_decoder_memory: Some(512 * 1024 * 1024),
            max_pax_header_bytes: Some(1024 * 1024),
            max_extra_bytes: Some(65535),
            max_sparse_regions: Some(100_000),
            max_solid_block_bytes: Some(1024 * 1024 * 1024),
        }
    }
}

/// Immutable extraction policy. Construct with `Default::default()` for the
/// secure configuration and modify through `replace`-style helpers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    /// Symbolic link handling.
    pub symlinks: LinkPolicy,
    /// Hard link handling.
    pub hardlinks: LinkPolicy,
    /// Device, fifo and socket handling.
    pub special_files: SpecialFilesPolicy,
    /// Stored mode application.
    pub modes: ModePolicy,
    /// Allow setuid and setgid bits when `modes` is `Preserve`.
    pub allow_setid: bool,
    /// Existing destination name handling.
    pub overwrite: Overwrite,
    /// Duplicate name handling.
    pub duplicates: Duplicates,
    /// Windows name rule enforcement.
    pub windows_names: WindowsNames,
    /// Apply stored mtimes to extracted files and directories.
    pub preserve_mtime: bool,
    /// Remove files and directories this run created when it fails.
    pub cleanup_on_error: bool,
    /// Cross check the zip central directory against local headers and
    /// validate every declared range before reading anything.
    pub strict: bool,
    /// Permit zip reading from a non-seekable source using local headers only.
    pub allow_streaming_zip: bool,
    /// Follow symlinks that already existed in the destination. The
    /// capability confinement still applies.
    pub follow_existing_symlinks: bool,
    /// Create the destination directory when missing.
    pub create_dest: bool,
    /// fsync files and directories before rename when finishing archives.
    pub durable: bool,
    /// Limits.
    pub limits: Limits,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            symlinks: LinkPolicy::default(),
            hardlinks: LinkPolicy::default(),
            special_files: SpecialFilesPolicy::default(),
            modes: ModePolicy::default(),
            allow_setid: false,
            overwrite: Overwrite::default(),
            duplicates: Duplicates::default(),
            windows_names: WindowsNames::default(),
            preserve_mtime: true,
            cleanup_on_error: true,
            strict: true,
            allow_streaming_zip: false,
            follow_existing_symlinks: false,
            create_dest: true,
            durable: false,
            limits: Limits::default(),
        }
    }
}

impl Policy {
    /// Whether Windows name rules apply on this host and per configuration.
    #[must_use]
    pub fn windows_names_active(&self) -> bool {
        match self.windows_names {
            WindowsNames::Auto => cfg!(windows),
            WindowsNames::Reject => true,
            WindowsNames::Allow => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Policy;

    #[test]
    fn defaults_match_the_secure_policy() {
        let policy = Policy::default();
        assert!(policy.preserve_mtime);
        assert!(policy.cleanup_on_error);
        assert!(policy.strict);
        assert!(policy.create_dest);
        assert!(!policy.allow_setid);
        assert!(!policy.allow_streaming_zip);
        assert!(!policy.follow_existing_symlinks);
        assert!(!policy.durable);
        assert_eq!(policy.limits.max_entries, Some(1_000_000));
    }
}
