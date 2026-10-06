//! Container format vocabulary: kinds, entry descriptions, reader and writer
//! traits. Format implementations live in the submodules; this module has no
//! dependency on any of them.

use std::fmt;
use std::io;
use std::str::FromStr;

use crate::error::{Error, Result};
use crate::secret::Secret;

/// Container formats supported by oxar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Format {
    /// Zip, including zip64 and self-extracting prefixes.
    Zip,
    /// Tar, plain or behind an outer compression stream.
    Tar,
    /// 7z.
    SevenZ,
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Zip => "zip",
            Self::Tar => "tar",
            Self::SevenZ => "7z",
        })
    }
}

impl FromStr for Format {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "zip" => Ok(Self::Zip),
            "tar" => Ok(Self::Tar),
            "7z" => Ok(Self::SevenZ),
            other => Err(Error::usage(format!(
                "unknown format {other:?}, expected \"zip\", \"tar\" or \"7z\""
            ))),
        }
    }
}

/// Outer compression of a tar archive. Zip and 7z carry per-entry methods
/// instead and use `Compression::None` as the archive level default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Compression {
    /// No outer stream.
    #[default]
    None,
    /// gzip.
    Gzip,
    /// bzip2.
    Bzip2,
    /// xz.
    Xz,
    /// zstd.
    Zstd,
    /// lz4 frame.
    Lz4,
}

impl fmt::Display for Compression {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::None => "none",
            Self::Gzip => "gzip",
            Self::Bzip2 => "bzip2",
            Self::Xz => "xz",
            Self::Zstd => "zstd",
            Self::Lz4 => "lz4",
        })
    }
}

impl Compression {
    /// Map this compression to its underlying codec, if a stream codec exists.
    #[must_use]
    pub fn to_codec(self) -> Option<Codec> {
        match self {
            Self::None => None,
            Self::Gzip => Some(Codec::Gzip),
            Self::Bzip2 => Some(Codec::Bzip2),
            Self::Xz => Some(Codec::Xz),
            Self::Zstd => Some(Codec::Zstd),
            Self::Lz4 => Some(Codec::Lz4),
        }
    }
}

impl FromStr for Compression {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "none" => Ok(Self::None),
            "gzip" => Ok(Self::Gzip),
            "bzip2" => Ok(Self::Bzip2),
            "xz" => Ok(Self::Xz),
            "zstd" => Ok(Self::Zstd),
            "lz4" => Ok(Self::Lz4),
            other => Err(Error::usage(format!(
                "unknown compression {other:?}, expected \"none\", \"gzip\", \"bzip2\", \"xz\", \"zstd\" or \"lz4\""
            ))),
        }
    }
}

/// Raw stream codecs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Codec {
    /// gzip container.
    Gzip,
    /// zlib container.
    Zlib,
    /// Raw deflate stream.
    Deflate,
    /// bzip2.
    Bzip2,
    /// xz container.
    Xz,
    /// lzma alone container.
    Lzma,
    /// zstd.
    Zstd,
    /// lz4 frame.
    Lz4,
    /// brotli.
    Brotli,
    /// snappy framed.
    Snappy,
}

impl fmt::Display for Codec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Gzip => "gzip",
            Self::Zlib => "zlib",
            Self::Deflate => "deflate",
            Self::Bzip2 => "bzip2",
            Self::Xz => "xz",
            Self::Lzma => "lzma",
            Self::Zstd => "zstd",
            Self::Lz4 => "lz4",
            Self::Brotli => "brotli",
            Self::Snappy => "snappy",
        })
    }
}

impl FromStr for Codec {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "gzip" => Ok(Self::Gzip),
            "zlib" => Ok(Self::Zlib),
            "deflate" => Ok(Self::Deflate),
            "bzip2" => Ok(Self::Bzip2),
            "xz" => Ok(Self::Xz),
            "lzma" => Ok(Self::Lzma),
            "zstd" => Ok(Self::Zstd),
            "lz4" => Ok(Self::Lz4),
            "brotli" => Ok(Self::Brotli),
            "snappy" => Ok(Self::Snappy),
            other => Err(Error::usage(format!(
                "unknown codec {other:?}, expected one of \"gzip\", \"zlib\", \"deflate\", \"bzip2\", \"xz\", \"lzma\", \"zstd\", \"lz4\", \"brotli\", \"snappy\""
            ))),
        }
    }
}

/// Kind of a special entry stored in an archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OtherKind {
    /// Character device.
    CharDevice,
    /// Block device.
    BlockDevice,
    /// Fifo.
    Fifo,
    /// Socket.
    Socket,
    /// A type this build does not recognise.
    Unknown,
}

impl fmt::Display for OtherKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::CharDevice => "char device",
            Self::BlockDevice => "block device",
            Self::Fifo => "fifo",
            Self::Socket => "socket",
            Self::Unknown => "unknown type",
        })
    }
}

/// Kind of an archive entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum EntryKind {
    /// Regular file.
    #[default]
    File,
    /// Directory.
    Dir,
    /// Symbolic link; the target is in `Entry::link_target`.
    Symlink,
    /// Hard link; the target is in `Entry::link_target`.
    Hardlink,
    /// Device, fifo, socket or unrecognised type.
    Other(OtherKind),
}

impl fmt::Display for EntryKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::File => f.write_str("file"),
            Self::Dir => f.write_str("dir"),
            Self::Symlink => f.write_str("symlink"),
            Self::Hardlink => f.write_str("hardlink"),
            Self::Other(kind) => write!(f, "{kind}"),
        }
    }
}

/// Compression method stored for one entry, when the container has one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Method {
    /// No compression.
    Stored,
    /// Deflate.
    Deflate,
    /// Deflate64 (read only).
    Deflate64,
    /// bzip2.
    Bzip2,
    /// LZMA.
    Lzma,
    /// LZMA2.
    Lzma2,
    /// PPMd (read only).
    Ppmd,
    /// zstd.
    Zstd,
    /// Any method variant this build does not name.
    Unknown,
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Stored => "stored",
            Self::Deflate => "deflate",
            Self::Deflate64 => "deflate64",
            Self::Bzip2 => "bzip2",
            Self::Lzma => "lzma",
            Self::Lzma2 => "lzma2",
            Self::Ppmd => "ppmd",
            Self::Zstd => "zstd",
            Self::Unknown => "unknown",
        })
    }
}

/// One entry as read from an archive. All fields are what the container
/// declared; declared sizes are hints and are never trusted for limits.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Entry {
    /// Position in the archive, stable within one open archive.
    pub index: u64,
    /// Raw name bytes as stored, after the format's charset rules.
    pub path_bytes: Vec<u8>,
    /// Display form, `/` separated.
    pub path: String,
    /// Entry kind.
    pub kind: EntryKind,
    /// Declared uncompressed size.
    pub size: Option<u64>,
    /// Declared compressed size.
    pub compressed_size: Option<u64>,
    /// Stored permission bits including the file type bits on Unix formats.
    pub mode: Option<u32>,
    /// Numeric owner id.
    pub uid: Option<u64>,
    /// Numeric group id.
    pub gid: Option<u64>,
    /// Owner name.
    pub uname: Option<String>,
    /// Group name.
    pub gname: Option<String>,
    /// Modification time in nanoseconds since the Unix epoch, UTC.
    pub mtime_ns: Option<i128>,
    /// Stored CRC32, when the container has one.
    pub crc32: Option<u32>,
    /// Link target bytes for symlinks and hard links.
    pub link_target: Option<Vec<u8>>,
    /// Whether the entry data is encrypted.
    pub encrypted: bool,
    /// Stored compression method, when known.
    pub method: Option<Method>,
    /// Per entry comment, when the container has one.
    pub comment: Option<String>,
}

impl Entry {
    /// An empty entry at `index`; readers fill the fields they know.
    #[must_use]
    pub fn new(index: u64) -> Self {
        Self {
            index,
            kind: EntryKind::File,
            ..Self::default()
        }
    }

    /// Whether this is a regular file.
    #[must_use]
    pub fn is_file(&self) -> bool {
        matches!(self.kind, EntryKind::File)
    }

    /// Whether this is a directory.
    #[must_use]
    pub fn is_dir(&self) -> bool {
        matches!(self.kind, EntryKind::Dir)
    }

    /// Whether this is a symbolic link.
    #[must_use]
    pub fn is_symlink(&self) -> bool {
        matches!(self.kind, EntryKind::Symlink)
    }

    /// Whether this is a hard link.
    #[must_use]
    pub fn is_hardlink(&self) -> bool {
        matches!(self.kind, EntryKind::Hardlink)
    }
}

/// Description of an entry to write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewEntry {
    /// Name to store, already validated for the destination format.
    pub path: String,
    /// Entry kind.
    pub kind: EntryKind,
    /// Permission bits.
    pub mode: Option<u32>,
    /// Modification time in nanoseconds since the Unix epoch.
    pub mtime_ns: Option<i128>,
    /// Link target for symlinks and hard links.
    pub link_target: Option<Vec<u8>>,
    /// Declared size, when known before streaming.
    pub size_hint: Option<u64>,
    /// Per entry method override.
    pub method: Option<Method>,
    /// Per entry compression level override.
    pub level: Option<i32>,
    /// Per entry password override.
    pub password: Option<Secret>,
}

/// Reader for one entry's data.
pub trait EntryRead: io::Read + Send {
    /// Whether backward seeks are possible on this stream.
    fn seekable(&self) -> bool {
        false
    }
}

impl EntryRead for io::Empty {}
impl EntryRead for io::Cursor<Vec<u8>> {
    fn seekable(&self) -> bool {
        true
    }
}

/// Iterator over entries; lazy, finite and validated as it advances.
pub type EntryIter<'a> = Box<dyn Iterator<Item = Result<Entry>> + 'a>;

/// Read side of a container format.
///
/// Entries are consumed through `next_entry` in archive order and their data
/// through `open_current`, which works for every format including one pass
/// streams. `open_entry` additionally opens an arbitrary entry by index and
/// is only available when `is_random_access` returns true; sequential formats
/// return `Unsupported`.
///
/// Data readers borrow the archive, so the caller must drop the reader before
/// asking for the next entry. This is what makes one pass decoding sound.
pub trait ArchiveReader: Send {
    /// The format this reader implements.
    fn format(&self) -> Format;

    /// Advance to the next entry, or return `None` at the end.
    fn next_entry(&mut self) -> Result<Option<Entry>>;

    /// Open the data of the entry most recently returned by `next_entry`.
    /// Calling it twice for the same entry is allowed for random access
    /// formats and returns a fresh reader.
    fn open_current(&mut self) -> Result<Box<dyn EntryRead + '_>>;

    /// Open one entry's data by index.
    fn open_entry(&mut self, entry: &Entry) -> Result<Box<dyn EntryRead + '_>> {
        let _ = entry;
        Err(Error::unsupported(
            "random access reads on a sequential source",
        ))
    }

    /// Whether entries can be opened in any order on this source.
    fn is_random_access(&self) -> bool;
}

/// Write side of a container format.
pub trait ArchiveWriter: Send {
    /// Append one entry. `data` is read to the end for files.
    fn add(&mut self, entry: &NewEntry, data: &mut dyn io::Read) -> Result<()>;

    /// Finish the archive, writing trailers and directory structures.
    fn finish(self: Box<Self>) -> Result<()>;
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn format_names_round_trip() {
        for name in ["zip", "tar", "7z"] {
            assert_eq!(Format::from_str(name).unwrap().to_string(), name);
        }
        assert!(Format::from_str("rar").is_err());
    }

    #[test]
    fn codec_names_round_trip() {
        for name in [
            "gzip", "zlib", "deflate", "bzip2", "xz", "lzma", "zstd", "lz4", "brotli", "snappy",
        ] {
            assert_eq!(Codec::from_str(name).unwrap().to_string(), name);
        }
        assert!(Codec::from_str("lzo").is_err());
    }
}

