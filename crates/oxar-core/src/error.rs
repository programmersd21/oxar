//! Error type shared by every oxar layer.

use std::fmt;
use std::io;

use crate::format::Format;

/// Machine readable position attached to an error when the failure has a
/// location inside a specific archive. Rendered as context in parentheses at
/// the end of the message, as in `(entry "a/b", format zip)`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Location {
    /// Archive format the failure belongs to.
    format: Option<Format>,
    /// Entry path the failure belongs to.
    entry: Option<String>,
    /// Byte offset inside the archive.
    offset: Option<u64>,
}

impl Location {
    #[must_use]
    /// An empty location.
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    /// Set the archive format.
    pub fn with_format(mut self, format: Format) -> Self {
        self.format = Some(format);
        self
    }

    #[must_use]
    /// Set the entry path.
    pub fn with_entry(mut self, entry: impl Into<String>) -> Self {
        self.entry = Some(entry.into());
        self
    }

    #[must_use]
    /// Set the byte offset.
    pub fn with_offset(mut self, offset: u64) -> Self {
        self.offset = Some(offset);
        self
    }

    /// Archive format the failure belongs to, when known.
    #[must_use]
    pub fn format(&self) -> Option<Format> {
        self.format
    }

    /// Entry path the failure belongs to, when known.
    #[must_use]
    pub fn entry(&self) -> Option<&str> {
        self.entry.as_deref()
    }

    /// Byte offset inside the archive, when known.
    #[must_use]
    pub fn offset(&self) -> Option<u64> {
        self.offset
    }

    /// Fill unset fields from `other`; fields already present win.
    /// Copy fields from `other` that are not already set here.
    pub fn merge(&mut self, other: &Self) {
        if self.format.is_none() {
            self.format = other.format;
        }
        if self.entry.is_none() {
            self.entry.clone_from(&other.entry);
        }
        if self.offset.is_none() {
            self.offset = other.offset;
        }
    }
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut sep = "";
        if self.format.is_none() && self.entry.is_none() && self.offset.is_none() {
            return Ok(());
        }
        write!(f, " (")?;
        if let Some(entry) = &self.entry {
            write!(f, "{sep}entry {entry:?}")?;
            sep = ", ";
        }
        if let Some(format) = self.format {
            write!(f, "{sep}format {format}")?;
            sep = ", ";
        }
        if let Some(offset) = self.offset {
            write!(f, "{sep}offset {offset}")?;
        }
        write!(f, ")")
    }
}

/// Result alias for fallible oxar operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Every failure oxar reports. Variants map to the Python exception hierarchy
/// documented in the API contract; `loc` carries the same context attributes.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// An argument or option value is invalid, or a combination is not allowed.
    #[error("invalid usage: {message}")]
    Usage {
        /// Human readable explanation naming the offending value.
        message: String,
    },

    /// Content did not match any supported container format.
    #[error("unknown archive format{loc}")]
    UnknownFormat {
        /// Where the detection happened, when it happened inside an archive.
        loc: Location,
    },

    /// The archive structure is invalid.
    #[error("corrupt archive: {detail}{loc}")]
    Corrupt {
        /// What structural invariant failed.
        detail: String,
        /// Position of the failure.
        loc: Location,
    },

    /// The archive ends before the declared end.
    #[error("archive is truncated: {detail}{loc}")]
    Truncated {
        /// What the structure declared and where the bytes ran out.
        detail: String,
        /// Position of the failure.
        loc: Location,
    },

    /// A stored checksum does not match the produced data.
    #[error("checksum mismatch: expected {expected:#010x}, got {actual:#010x}{loc}")]
    ChecksumMismatch {
        /// Checksum stored in the archive.
        expected: u32,
        /// Checksum computed from the produced bytes.
        actual: u32,
        /// Position of the entry.
        loc: Location,
    },

    /// The operation is valid but not implemented for this format or mode.
    #[error("unsupported feature: {feature}")]
    Unsupported {
        /// The feature name as documented in FORMAT_SUPPORT.md.
        feature: String,
    },

    /// The archive is encrypted and no password was supplied.
    #[error("password required{loc}")]
    PasswordRequired {
        /// Location of the encrypted entry or header.
        loc: Location,
    },

    /// A password was supplied and rejected.
    #[error("wrong password{loc}")]
    WrongPassword {
        /// Location where verification failed.
        loc: Location,
    },

    /// An entry name is unsafe to materialise.
    #[error("refusing to extract entry: {detail}{loc}")]
    UnsafePath {
        /// The rule that rejected the name.
        detail: String,
        /// Location of the entry.
        loc: Location,
    },

    /// A link entry is unsafe to create.
    #[error("refusing to create link: {detail}{loc}")]
    UnsafeLink {
        /// The rule that rejected the link.
        detail: String,
        /// Location of the entry.
        loc: Location,
    },

    /// A device, fifo or socket entry was encountered.
    #[error("refusing to extract special file: {detail}{loc}")]
    SpecialFile {
        /// The entry type as stored.
        detail: String,
        /// Location of the entry.
        loc: Location,
    },

    /// Two entries collide, either by the same name or by a collision key.
    #[error("duplicate entry: {detail}{loc}")]
    Duplicate {
        /// Which entry collides and by which rule.
        detail: String,
        /// Location of the later entry.
        loc: Location,
    },

    /// Zip entry byte ranges overlap.
    #[error("overlapping archive entries: {detail}{loc}")]
    Overlapping {
        /// The two ranges that overlap.
        detail: String,
        /// Where the overlap was found.
        loc: Location,
    },

    /// A configured limit was exceeded; the run is cancelled.
    #[error("limit exceeded: {limit} limit is {limit_value}, observed {observed}{loc}")]
    Bomb {
        /// Name of the limit, as it appears in the Policy constructor.
        limit: &'static str,
        /// The configured value.
        limit_value: u64,
        /// The value that was actually observed.
        observed: u64,
        /// Position of the failure.
        loc: Location,
    },

    /// Writing an entry to the filesystem failed.
    #[error("extraction failed: {kind} for {path}{loc}")]
    Extract {
        /// Short machine readable reason, for example `exists`.
        kind: &'static str,
        /// Destination relative path being written.
        path: String,
        /// OS error number when the failure came from the operating system.
        errno: Option<i32>,
        /// Position of the entry in the archive.
        loc: Location,
    },

    /// An OS or Python file object operation failed.
    #[error("i/o error: {source}")]
    Io {
        /// Underlying error.
        #[source]
        source: io::Error,
        /// Position in the archive, when known.
        loc: Location,
    },

    /// The caller cancelled the operation, or a signal requested it.
    #[error("operation cancelled")]
    Cancelled,
}

impl Error {
    /// Build a usage error.
    pub fn usage(message: impl Into<String>) -> Self {
        Self::Usage {
            message: message.into(),
        }
    }

    /// Build an unsupported feature error.
    pub fn unsupported(feature: impl Into<String>) -> Self {
        Self::Unsupported {
            feature: feature.into(),
        }
    }

    /// Build a corrupt archive error.
    pub fn corrupt(detail: impl Into<String>) -> Self {
        Self::Corrupt {
            detail: detail.into(),
            loc: Location::new(),
        }
    }

    /// Build a configured limit exceeded error.
    pub fn limit(limit: &'static str, limit_value: u64, observed: u64) -> Self {
        Self::Bomb {
            limit,
            limit_value,
            observed,
            loc: Location::new(),
        }
    }

    /// Build a security error for an unsafe name.
    pub fn unsafe_path(detail: impl Into<String>) -> Self {
        Self::UnsafePath {
            detail: detail.into(),
            loc: Location::new(),
        }
    }

    /// The location attached to this error, when it has one.
    #[must_use]
    pub fn loc(&self) -> Option<&Location> {
        match self {
            Self::UnknownFormat { loc }
            | Self::Corrupt { loc, .. }
            | Self::Truncated { loc, .. }
            | Self::ChecksumMismatch { loc, .. }
            | Self::PasswordRequired { loc }
            | Self::WrongPassword { loc }
            | Self::UnsafePath { loc, .. }
            | Self::UnsafeLink { loc, .. }
            | Self::SpecialFile { loc, .. }
            | Self::Duplicate { loc, .. }
            | Self::Overlapping { loc, .. }
            | Self::Bomb { loc, .. }
            | Self::Extract { loc, .. }
            | Self::Io { loc, .. } => Some(loc),
            Self::Usage { .. } | Self::Unsupported { .. } | Self::Cancelled => None,
        }
    }

    /// Mutable access to the location, when the variant has one.
    pub fn loc_mut(&mut self) -> Option<&mut Location> {
        match self {
            Self::UnknownFormat { loc }
            | Self::Corrupt { loc, .. }
            | Self::Truncated { loc, .. }
            | Self::ChecksumMismatch { loc, .. }
            | Self::PasswordRequired { loc }
            | Self::WrongPassword { loc }
            | Self::UnsafePath { loc, .. }
            | Self::UnsafeLink { loc, .. }
            | Self::SpecialFile { loc, .. }
            | Self::Duplicate { loc, .. }
            | Self::Overlapping { loc, .. }
            | Self::Bomb { loc, .. }
            | Self::Extract { loc, .. }
            | Self::Io { loc, .. } => Some(loc),
            Self::Usage { .. } | Self::Unsupported { .. } | Self::Cancelled => None,
        }
    }

    /// Attach context that is not already present. Used when errors cross
    /// pipeline stages and a later stage knows more about the entry.
    #[must_use]
    pub fn attach(mut self, loc: &Location) -> Self {
        if let Some(own) = self.loc_mut() {
            own.merge(loc);
        }
        self
    }
}

impl From<io::Error> for Error {
    fn from(source: io::Error) -> Self {
        Self::Io {
            source,
            loc: Location::new(),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn location_renders_context() {
        let loc = Location::new().with_entry("a/b").with_format(Format::Zip);
        assert_eq!(loc.to_string(), " (entry \"a/b\", format zip)");
        assert_eq!(Location::new().to_string(), "");
    }

    #[test]
    fn merge_keeps_present_fields() {
        let mut first = Location::new().with_entry("x");
        first.merge(&Location::new().with_entry("y").with_format(Format::Tar));
        assert_eq!(first.entry(), Some("x"));
        assert_eq!(first.format(), Some(Format::Tar));
    }

    #[test]
    fn messages_follow_the_style_rules() {
        let error = Error::Corrupt {
            detail: "central directory offset points outside the file".into(),
            loc: Location::new().with_format(Format::Zip).with_offset(42),
        };
        assert_eq!(
            error.to_string(),
            "corrupt archive: central directory offset points outside the file (format zip, offset 42)"
        );
    }
}
