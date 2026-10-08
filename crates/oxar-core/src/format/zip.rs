//! Zip container: entry metadata, streaming reads and streaming writes on top
//! of the `zip` crate.
//!
//! The reader surfaces metadata and the per-entry stream; extraction to the
//! filesystem happens in the sink layer. Nothing in this module buffers a
//! whole entry: `open_current` and `open_entry` hand out the decoder itself
//! and the caller drives `io::copy`. The writer also consumes entry data from
//! any `Read` in one pass and never materialises it in memory.
//!
//! Name decoding follows the zip specification: the UTF-8 flag (bit 11) wins,
//! the Info-ZIP unicode path extra field (0x7075) is applied by the underlying
//! parser when its CRC checks out, then the configured encoding override is
//! used, defaulting to CP437. The stored name bytes stay available in
//! [`Entry::path_bytes`].

use std::fmt;
use std::io::{Read, Seek, Write};
use std::str::FromStr;

use zip::read::{ZipFile, ZipFileEntry};
use zip::result::ZipError;
use zip::write::FullFileOptions;
use zip::{AesMode, CompressionMethod, DateTime, System, ZipArchive};

use crate::error::{Error, Location, Result};
use crate::format::{
    ArchiveReader, ArchiveWriter, Entry, EntryKind, EntryRead, Format, Method, NewEntry,
};
use crate::fsio::{PositionedReader, RandomSource};
use crate::policy::Policy;
use crate::secret::Secret;

/// General purpose flag bit 11: the name and comment are UTF-8.
const UTF8_NAME_FLAG: u16 = 1 << 11;

/// Unix `S_IFLNK` file type bits, set in the external attributes of symlink
/// entries.
const S_IFLNK: u32 = 0o120_000;

/// Largest symlink target read while listing an archive, in bytes. The
/// target is stored as entry data, so it has to be read once; the bound keeps
/// a malicious entry from acting as an unbounded read.
const MAX_SYMLINK_TARGET: u64 = 64 * 1024;

/// Charset used for zip entry names that are not flagged as UTF-8.
///
/// The UTF-8 flag and a valid unicode path extra field always win; this only
/// selects the fallback for legacy archives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum NameEncoding {
    /// Specification behaviour: CP437 unless the archive says otherwise.
    #[default]
    Spec,
    /// CP437, stated explicitly; identical to `Spec` for decoding.
    Cp437,
    /// ISO-8859-1 / Latin-1.
    Latin1,
    /// Force UTF-8 for names without the UTF-8 flag.
    Utf8,
}

impl fmt::Display for NameEncoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Spec => "auto",
            Self::Cp437 => "cp437",
            Self::Latin1 => "latin1",
            Self::Utf8 => "utf-8",
        })
    }
}

impl FromStr for NameEncoding {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "auto" | "spec" | "default" => Ok(Self::Spec),
            "utf-8" | "utf8" => Ok(Self::Utf8),
            "cp437" | "ibm437" | "437" => Ok(Self::Cp437),
            "latin1" | "latin-1" | "iso-8859-1" | "iso8859-1" => Ok(Self::Latin1),
            other => Err(Error::usage(format!(
                "unknown zip name encoding {other:?}, expected \"auto\", \"utf-8\", \"cp437\" or \"latin1\""
            ))),
        }
    }
}

/// Decode one zip entry name.
///
/// `utf8_flag` is the state of general purpose bit 11. When it is set the
/// bytes are UTF-8; a malformed archive that says UTF-8 but does not contain
/// it falls back to the configured encoding instead of failing the listing.
/// Without the flag the override (or CP437) is used.
#[must_use]
pub fn decode_zip_name(raw: &[u8], utf8_flag: bool, encoding: NameEncoding) -> String {
    if (utf8_flag || encoding == NameEncoding::Utf8)
        && let Ok(text) = std::str::from_utf8(raw)
    {
        return text.to_owned();
    }
    match encoding {
        NameEncoding::Latin1 => raw.iter().map(|&byte| char::from(byte)).collect(),
        _ => decode_cp437(raw),
    }
}

/// Decode bytes as IBM code page 437. Every byte maps to a character.
#[must_use]
pub fn decode_cp437(raw: &[u8]) -> String {
    raw.iter()
        .map(|&byte| {
            if byte < 0x80 {
                char::from(byte)
            } else {
                CP437_HIGH[usize::from(byte - 0x80)]
            }
        })
        .collect()
}

/// The upper half of code page 437, code points `0x80..=0xFF`.
const CP437_HIGH: [char; 128] = [
    '\u{00c7}', '\u{00fc}', '\u{00e9}', '\u{00e2}', '\u{00e4}', '\u{00e0}', '\u{00e5}', '\u{00e7}',
    '\u{00ea}', '\u{00eb}', '\u{00e8}', '\u{00ef}', '\u{00ee}', '\u{00ec}', '\u{00c4}', '\u{00c5}',
    '\u{00c9}', '\u{00e6}', '\u{00c6}', '\u{00f4}', '\u{00f6}', '\u{00f2}', '\u{00fb}', '\u{00f9}',
    '\u{00ff}', '\u{00d6}', '\u{00dc}', '\u{00a2}', '\u{00a3}', '\u{00a5}', '\u{20a7}', '\u{0192}',
    '\u{00e1}', '\u{00ed}', '\u{00f3}', '\u{00fa}', '\u{00f1}', '\u{00d1}', '\u{00aa}', '\u{00ba}',
    '\u{00bf}', '\u{2310}', '\u{00ac}', '\u{00bd}', '\u{00bc}', '\u{00a1}', '\u{00ab}', '\u{00bb}',
    '\u{2591}', '\u{2592}', '\u{2593}', '\u{2502}', '\u{2524}', '\u{2561}', '\u{2562}', '\u{2556}',
    '\u{2555}', '\u{2563}', '\u{2551}', '\u{2557}', '\u{255d}', '\u{255c}', '\u{255b}', '\u{2510}',
    '\u{2514}', '\u{2534}', '\u{252c}', '\u{251c}', '\u{2500}', '\u{253c}', '\u{255e}', '\u{255f}',
    '\u{255a}', '\u{2554}', '\u{2569}', '\u{2566}', '\u{2560}', '\u{2550}', '\u{256c}', '\u{2567}',
    '\u{2568}', '\u{2564}', '\u{2565}', '\u{2559}', '\u{2558}', '\u{2552}', '\u{2553}', '\u{256b}',
    '\u{256a}', '\u{2518}', '\u{250c}', '\u{2588}', '\u{2584}', '\u{258c}', '\u{2590}', '\u{2580}',
    '\u{03b1}', '\u{00df}', '\u{0393}', '\u{03c0}', '\u{03a3}', '\u{03c3}', '\u{00b5}', '\u{03c4}',
    '\u{03a6}', '\u{0398}', '\u{03a9}', '\u{03b4}', '\u{221e}', '\u{03c6}', '\u{03b5}', '\u{2229}',
    '\u{2261}', '\u{00b1}', '\u{2265}', '\u{2264}', '\u{2320}', '\u{2321}', '\u{00f7}', '\u{2248}',
    '\u{00b0}', '\u{2219}', '\u{00b7}', '\u{221a}', '\u{207f}', '\u{00b2}', '\u{25a0}', '\u{00a0}',
];

/// Convert a DOS date/time as decoded by the zip crate into nanoseconds since
/// the Unix epoch. The stored local time is treated as UTC because the DOS
/// fields carry no zone information.
#[must_use]
pub fn datetime_to_ns(stamp: &DateTime) -> i128 {
    let days = days_from_civil(
        i64::from(stamp.year()),
        i64::from(stamp.month()),
        i64::from(stamp.day()),
    );
    let seconds = days * 86_400
        + i64::from(stamp.hour()) * 3_600
        + i64::from(stamp.minute()) * 60
        + i64::from(stamp.second());
    i128::from(seconds) * 1_000_000_000
}

/// Convert nanoseconds since the Unix epoch into a DOS date/time, when the
/// value fits the zip range (1980..=2107) and 2 second resolution.
#[must_use]
pub fn ns_to_datetime(ns: i128) -> Option<DateTime> {
    let seconds = ns.div_euclid(1_000_000_000);
    let day_seconds = seconds.rem_euclid(86_400);
    let days = i64::try_from(seconds.div_euclid(86_400)).ok()?;
    let (year, month, day) = civil_from_days(days);
    if !(1980..=2107).contains(&year) {
        return None;
    }
    let hour = u8::try_from(day_seconds / 3_600).ok()?;
    let minute = u8::try_from((day_seconds % 3_600) / 60).ok()?;
    let second = u8::try_from(day_seconds % 60).ok()?;
    DateTime::from_date_and_time(
        u16::try_from(year).ok()?,
        u8::try_from(month).ok()?,
        u8::try_from(day).ok()?,
        hour,
        minute,
        second,
    )
    .ok()
}

/// Days since `1970-01-01` for a civil date (Howard Hinnant's algorithm).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let shifted_month = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * shifted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// Civil date for days since `1970-01-01` (Howard Hinnant's algorithm).
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    (year + i64::from(month <= 2), month, day)
}

/// Map a `zip` crate error onto the shared oxar error type.
fn map_error(error: ZipError) -> Error {
    let loc = Location::new().with_format(Format::Zip);
    match error {
        ZipError::Io(source) => Error::Io { source, loc },
        ZipError::InvalidArchive(detail) => Error::Corrupt {
            detail: detail.into_owned(),
            loc,
        },
        ZipError::UnsupportedArchive(message) if message == ZipError::PASSWORD_REQUIRED => {
            Error::PasswordRequired { loc }
        }
        ZipError::UnsupportedArchive(feature) => Error::Unsupported {
            feature: feature.to_owned(),
        },
        ZipError::FileNotFound => Error::Corrupt {
            detail: "entry not found in zip archive".into(),
            loc,
        },
        ZipError::InvalidPassword => Error::WrongPassword { loc },
        ZipError::CompressionMethodNotSupported(id) => Error::Unsupported {
            feature: format!("zip compression method {id}"),
        },
        other => Error::Corrupt {
            detail: other.to_string(),
            loc,
        },
    }
}

/// Map an entry compression method from the `zip` crate vocabulary.
fn method_from_zip(method: CompressionMethod) -> Method {
    match method {
        CompressionMethod::Stored => Method::Stored,
        CompressionMethod::Deflated => Method::Deflate,
        CompressionMethod::Deflate64 => Method::Deflate64,
        CompressionMethod::Bzip2 => Method::Bzip2,
        CompressionMethod::Lzma => Method::Lzma,
        CompressionMethod::Zstd => Method::Zstd,
        _ => Method::Unknown,
    }
}

/// Map an entry compression method onto the `zip` crate vocabulary. `None`
/// selects deflate, the portable zip default.
fn method_to_zip(method: Option<Method>) -> Result<CompressionMethod> {
    Ok(match method.unwrap_or(Method::Deflate) {
        Method::Stored => CompressionMethod::Stored,
        Method::Deflate => CompressionMethod::Deflated,
        Method::Bzip2 => CompressionMethod::Bzip2,
        Method::Lzma => CompressionMethod::Lzma,
        Method::Zstd => CompressionMethod::Zstd,
        Method::Deflate64 => {
            return Err(Error::unsupported("writing zip entries with deflate64"));
        }
        Method::Lzma2 => {
            return Err(Error::unsupported("writing zip entries with lzma2"));
        }
        Method::Ppmd => {
            return Err(Error::unsupported("writing zip entries with ppmd"));
        }
        Method::Unknown => {
            return Err(Error::unsupported(
                "writing zip entries with an unknown method",
            ));
        }
    })
}

/// Build one [`Entry`] from zip metadata. The name is decoded with the
/// specification rules and the stored bytes are kept verbatim.
fn entry_from_meta(index: u64, info: &ZipFileEntry<'_>, encoding: NameEncoding) -> Entry {
    let raw = info.name_raw();
    let utf8_flag = info.flags().as_u16() & UTF8_NAME_FLAG != 0;
    let mut entry = Entry::new(index);
    entry.path_bytes = raw.to_vec();
    entry.path = decode_zip_name(raw, utf8_flag, encoding);
    entry.kind = if info.is_dir() {
        EntryKind::Dir
    } else if info.is_symlink() {
        EntryKind::Symlink
    } else {
        EntryKind::File
    };
    entry.size = Some(info.size());
    entry.compressed_size = Some(info.compressed_size());
    entry.mode = info.unix_mode();
    entry.mtime_ns = info.last_modified().map(|stamp| datetime_to_ns(&stamp));
    entry.crc32 = Some(info.crc32());
    entry.encrypted = info.encrypted();
    entry.method = Some(method_from_zip(info.compression()));
    let comment = info.comment();
    entry.comment = (!comment.is_empty()).then(|| comment.to_owned());
    entry
}

/// Open one entry by index, decrypting with `password` when one is given.
fn open_at<'a, R: Read + Seek>(
    archive: &'a mut ZipArchive<R>,
    index: usize,
    password: Option<&[u8]>,
) -> Result<ZipFile<'a, R>> {
    match password {
        Some(password) => archive.by_index_decrypt(index, password),
        None => archive.by_index(index),
    }
    .map_err(map_error)
}

/// Read a symlink target from entry data. The target is small by nature; a
/// larger payload is reported as corruption rather than read without bound.
fn read_symlink_target<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    index: usize,
    password: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let file = open_at(archive, index, password)?;
    let mut target = Vec::new();
    let mut limited = file.take(MAX_SYMLINK_TARGET.saturating_add(1));
    limited
        .read_to_end(&mut target)
        .map_err(|source| Error::Io {
            source,
            loc: Location::new().with_format(Format::Zip),
        })?;
    if target.len() as u64 > MAX_SYMLINK_TARGET {
        return Err(Error::corrupt(format!(
            "symlink target exceeds {MAX_SYMLINK_TARGET} bytes"
        )));
    }
    Ok(target)
}

/// List the metadata of every entry, reading the target of symlink entries
/// (which is stored as their data) and verifying `password` against every
/// encrypted entry so that a wrong one is reported before any data is used.
fn list_entries<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    encoding: NameEncoding,
    password: Option<&[u8]>,
) -> Result<Vec<Entry>> {
    let count = archive.len();
    let mut entries = Vec::with_capacity(count);
    for index in 0..count {
        let mut entry = {
            let info = archive.by_index_data(index).map_err(map_error)?;
            entry_from_meta(index as u64, &info, encoding)
        };
        match entry.kind {
            EntryKind::Symlink => {
                entry.link_target = Some(read_symlink_target(archive, index, password)?);
            }
            _ if entry.encrypted && password.is_some() => {
                let _probe = open_at(archive, index, password)?;
            }
            _ => {}
        }
        entries.push(entry);
    }
    Ok(entries)
}

/// Streaming reader over a random access zip source.
///
/// Entry listing happens once, on open; `next_entry` walks the recorded
/// metadata and `open_current`/`open_entry` create a fresh decoder for one
/// entry, so entries can be opened in any order and a caller that drops a
/// half-read stream can still continue with the next entry.
pub struct ZipReader {
    archive: ZipArchive<PositionedReader>,
    entries: Vec<Entry>,
    pos: usize,
    password: Option<Secret>,
}

impl ZipReader {
    /// Open with the default secure policy, no password and no encoding
    /// override.
    pub fn new(source: RandomSource) -> Result<Self> {
        Self::open(source, &Policy::default(), None, NameEncoding::default())
    }

    /// Open with an explicit policy, password and name encoding.
    ///
    /// When `policy.strict` is set the archive is first cross-checked by the
    /// independent validator in [`crate::format::zip_validate`]; a failure
    /// there rejects the archive before the `zip` crate sees it.
    pub fn open(
        source: RandomSource,
        policy: &Policy,
        password: Option<Secret>,
        encoding: NameEncoding,
    ) -> Result<Self> {
        if policy.strict {
            let mut probe = source.reader();
            crate::format::zip_validate::validate(&mut probe, true)?;
        }
        let mut archive = ZipArchive::new(source.reader()).map_err(map_error)?;
        let entries = list_entries(
            &mut archive,
            encoding,
            password.as_ref().map(Secret::expose),
        )?;
        Ok(Self {
            archive,
            entries,
            pos: 0,
            password,
        })
    }

    /// The archive level comment, as raw bytes.
    #[must_use]
    pub fn comment(&self) -> &[u8] {
        self.archive.comment()
    }

    /// The entry metadata listed on open.
    #[must_use]
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Open one entry by index.
    fn open_index(&mut self, index: usize) -> Result<Box<dyn EntryRead + '_>> {
        let file = open_at(
            &mut self.archive,
            index,
            self.password.as_ref().map(Secret::expose),
        )?;
        Ok(Box::new(file))
    }

    /// Read one entry completely by name without populating full entry list.
    pub fn read_single_entry(
        source: RandomSource,
        name: &str,
        password: Option<Secret>,
        cap: u64,
    ) -> Result<Vec<u8>> {
        let mut archive = ZipArchive::new(source.reader()).map_err(map_error)?;
        let zip_file = match password.as_ref().map(Secret::expose) {
            Some(pw) => archive.by_name_decrypt(name, pw),
            None => archive.by_name(name),
        }
        .map_err(|e| match e {
            ZipError::FileNotFound => Error::usage(format!("entry not found: {name}")),
            other => map_error(other),
        })?;
        if zip_file.size() > cap {
            return Err(Error::usage("entry exceeds max_size"));
        }
        let reservation = usize::try_from(zip_file.size().min(cap)).unwrap_or(0);
        let mut data = Vec::with_capacity(reservation);
        zip_file
            .take(cap.saturating_add(1))
            .read_to_end(&mut data)
            .map_err(|source| Error::Io {
                source,
                loc: Location::new().with_format(Format::Zip),
            })?;
        Ok(data)
    }
}

impl EntryRead for ZipFile<'_, PositionedReader> {}

impl ArchiveReader for ZipReader {
    fn format(&self) -> Format {
        Format::Zip
    }

    fn next_entry(&mut self) -> Result<Option<Entry>> {
        if self.pos >= self.entries.len() {
            return Ok(None);
        }
        let entry = self.entries[self.pos].clone();
        self.pos += 1;
        Ok(Some(entry))
    }

    fn open_current(&mut self) -> Result<Box<dyn EntryRead + '_>> {
        if self.pos == 0 {
            return Err(Error::usage(
                "no current zip entry; call next_entry before open_current",
            ));
        }
        let index = self.pos - 1;
        self.open_index(index)
    }

    fn open_entry(&mut self, entry: &Entry) -> Result<Box<dyn EntryRead + '_>> {
        let index = usize::try_from(entry.index)
            .map_err(|_| Error::usage("zip entry index does not fit this platform"))?;
        self.open_index(index)
    }

    fn is_random_access(&self) -> bool {
        true
    }
}

/// Streaming writer producing a zip archive.
///
/// The writer is generic over the destination and never sees more than the
/// current buffer. Entries add with stored, deflate, bzip2, lzma or zstd
/// compression; a password turns files into AES-256 (WinZip AE-2) entries.
/// Symbolic links are stored the unix way, with the target as entry data and
/// `S_IFLNK` in the external attributes.
pub struct ZipWriter<W: Write + Seek> {
    inner: zip::ZipWriter<W>,
    password: Option<Secret>,
}

impl<W: Write + Seek> ZipWriter<W> {
    /// Wrap a seekable destination.
    pub fn new(writer: W) -> Self {
        Self {
            inner: zip::ZipWriter::new(writer),
            password: None,
        }
    }

    /// Wrap a seekable destination and use `password` for entries that do not
    /// carry their own. A password enables AES-256 encryption.
    pub fn with_password(writer: W, password: Option<Secret>) -> Self {
        Self {
            inner: zip::ZipWriter::new(writer),
            password,
        }
    }

    /// Set the archive level comment.
    pub fn set_comment(&mut self, comment: &str) -> Result<()> {
        self.inner.set_comment(comment).map_err(map_error)
    }

    /// Remove an entry from the central directory of an append-mode writer.
    ///
    /// The entry's local bytes remain in the archive as unreachable data.
    pub fn hide_file(&mut self, name: &str) -> Result<()> {
        self.inner.hide_file(name).map_err(map_error)
    }

    /// Set the archive level comment from raw bytes.
    pub fn set_raw_comment(&mut self, comment: Box<[u8]>) -> Result<()> {
        self.inner.set_raw_comment(comment).map_err(map_error)
    }

    /// Whether a writer level password is configured.
    #[must_use]
    pub fn has_password(&self) -> bool {
        self.password.is_some()
    }

    /// Append one entry, reading file data to the end. Directories and
    /// symlinks take their content from the entry description.
    pub fn add(&mut self, entry: &NewEntry, data: &mut dyn Read) -> Result<()> {
        self.add_with_comment(entry, None, data)
    }

    /// Append one entry with a per entry comment.
    pub fn add_with_comment(
        &mut self,
        entry: &NewEntry,
        comment: Option<&str>,
        data: &mut dyn Read,
    ) -> Result<()> {
        if entry.path.is_empty() {
            return Err(Error::usage("zip entry names must not be empty"));
        }
        let password = entry.password.as_ref().or(self.password.as_ref());
        let large_file = match entry.kind {
            EntryKind::Dir => false,
            EntryKind::Symlink => entry
                .link_target
                .as_ref()
                .is_some_and(|target| target.len() as u64 >= zip::ZIP64_BYTES_THR),
            _ => entry
                .size_hint
                .is_none_or(|size| size >= zip::ZIP64_BYTES_THR),
        };
        let mut options = FullFileOptions::default()
            .compression_method(method_to_zip(entry.method)?)
            .large_file(large_file);
        if let Some(level) = entry.level {
            options = options.compression_level(Some(i64::from(level)));
        }
        if let Some(mtime_ns) = entry.mtime_ns
            && let Some(stamp) = ns_to_datetime(mtime_ns)
        {
            options = options.last_modified_time(stamp);
        }
        if let Some(mode) = entry.mode {
            options = options.unix_permissions(mode);
        }
        if let Some(comment) = comment {
            options = options.with_file_comment(comment);
        }
        if let Some(secret) = password {
            options = options.with_aes_encryption_bytes(AesMode::Aes256, secret.expose());
        }
        match entry.kind {
            EntryKind::Dir => {
                self.inner
                    .add_directory(entry.path.as_str(), options)
                    .map_err(map_error)?;
            }
            EntryKind::Symlink => {
                let mut target = entry.link_target.as_deref().unwrap_or_default();
                let permissions = entry.mode.map_or(0o777, |mode| mode & 0o777);
                options = options
                    .compression_method(CompressionMethod::Stored)
                    .external_attributes((S_IFLNK | permissions) << 16)
                    .system(System::Unix);
                self.inner
                    .start_file(entry.path.as_str(), options)
                    .map_err(map_error)?;
                self.write_stream(&mut target)?;
            }
            EntryKind::File => {
                self.inner
                    .start_file(entry.path.as_str(), options)
                    .map_err(map_error)?;
                self.write_stream(data)?;
            }
            EntryKind::Hardlink => {
                return Err(Error::unsupported("zip archives cannot store hard links"));
            }
            EntryKind::Other(kind) => {
                return Err(Error::unsupported(format!(
                    "zip archives cannot store {kind} entries"
                )));
            }
        }
        Ok(())
    }

    /// Copy one entry's data into the archive. The buffer is the standard
    /// 8 KiB `io::copy` chunk; entries are never collected. The entry is
    /// closed by the next `add` call or by `finish`, which is where the zip
    /// crate validates the written size against the declared one.
    fn write_stream(&mut self, data: &mut dyn Read) -> Result<()> {
        if let Err(source) = std::io::copy(data, &mut self.inner) {
            let _ = self.inner.abort_file();
            return Err(Error::Io {
                source,
                loc: Location::new().with_format(Format::Zip),
            });
        }
        Ok(())
    }

    /// Finish the archive: write the central directory and return the
    /// destination.
    pub fn finish(self) -> Result<W> {
        self.inner.finish().map_err(map_error)
    }
}

impl<W: Read + Write + Seek> ZipWriter<W> {
    /// Open an existing ZIP archive for appending entries.
    ///
    /// The caller owns transactional replacement of the backing stream. This
    /// constructor delegates central directory parsing to the pinned `zip`
    /// implementation and does not extract or rewrite existing entry bytes.
    pub fn append(writer: W) -> Result<Self> {
        let inner = zip::ZipWriter::new_append(writer).map_err(map_error)?;
        Ok(Self {
            inner,
            password: None,
        })
    }
}

impl<W: Write + Seek + Send> ArchiveWriter for ZipWriter<W> {
    fn add(&mut self, entry: &NewEntry, data: &mut dyn Read) -> Result<()> {
        self.add_with_comment(entry, None, data)
    }

    fn finish(self: Box<Self>) -> Result<()> {
        let this = *self;
        let _destination = this.finish()?;
        Ok(())
    }
}

/// Read the metadata of every entry in a seekable zip source.
///
/// This is the convenience listing path; it never reads entry data except a
/// symlink target. A supplied password is verified against encrypted entries.
pub fn read_zip_entries<R: Read + Seek>(source: R, password: Option<&[u8]>) -> Result<Vec<Entry>> {
    let mut archive = ZipArchive::new(source).map_err(map_error)?;
    list_entries(&mut archive, NameEncoding::Spec, password)
}

/// Write a zip archive from in-memory items. The password, when provided,
/// writes AES-256 entries. Thin wrapper over [`ZipWriter`] kept for tests and
/// simple callers.
pub fn write_zip<W: Write + Seek>(
    writer: W,
    items: &[(NewEntry, Vec<u8>)],
    archive_comment: Option<&str>,
    password: Option<&[u8]>,
) -> Result<()> {
    let mut zip = ZipWriter::with_password(writer, password.map(Secret::new));
    if let Some(comment) = archive_comment {
        zip.set_comment(comment)?;
    }
    for (entry, data) in items {
        let mut cursor = std::io::Cursor::new(data.as_slice());
        zip.add(entry, &mut cursor)?;
    }
    zip.finish().map(|_destination| ())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
mod tests {
    use std::sync::Arc;

    use super::*;

    fn entry(path: &str, kind: EntryKind) -> NewEntry {
        NewEntry {
            path: path.into(),
            kind,
            mode: Some(0o644),
            mtime_ns: Some(1_700_000_000_000_000_000),
            link_target: None,
            size_hint: None,
            method: None,
            level: None,
            password: None,
        }
    }

    fn source_of(bytes: Vec<u8>) -> RandomSource {
        RandomSource::from_bytes(Arc::from(bytes.into_boxed_slice()))
    }

    fn write_archive(
        items: &[(NewEntry, Vec<u8>)],
        comment: Option<&str>,
        password: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut buffer = Vec::new();
        {
            let cursor = std::io::Cursor::new(&mut buffer);
            write_zip(cursor, items, comment, password).unwrap();
        }
        buffer
    }

    #[test]
    fn name_decoding_follows_the_spec_rules() {
        assert_eq!(
            decode_zip_name(b"hello.txt", false, NameEncoding::Spec),
            "hello.txt"
        );
        // CP437 fallback: 0x82 is 'é'.
        assert_eq!(
            decode_zip_name(b"caf\x82", false, NameEncoding::Spec),
            "café"
        );
        // Bit 11 wins over the override.
        assert_eq!(
            decode_zip_name("café".as_bytes(), true, NameEncoding::Cp437),
            "café"
        );
        // A broken UTF-8 claim degrades to the configured encoding.
        assert_eq!(
            decode_zip_name(b"caf\x82", true, NameEncoding::Spec),
            "café"
        );
        // Latin-1 maps bytes straight through.
        assert_eq!(
            decode_zip_name(b"caf\xe9", false, NameEncoding::Latin1),
            "café"
        );
        assert_eq!(
            "cp437".parse::<NameEncoding>().unwrap(),
            NameEncoding::Cp437
        );
        assert!("klingon".parse::<NameEncoding>().is_err());
    }

    #[test]
    fn mtime_conversion_round_trips_within_two_seconds() {
        let ns = 1_709_531_168_000_000_000i128;
        let stamp = ns_to_datetime(ns).unwrap();
        let back = datetime_to_ns(&stamp);
        assert!((back - ns).abs() < 2_000_000_000);
        assert_eq!(stamp.year(), 2024);
        assert_eq!(stamp.month(), 3);
    }

    #[test]
    fn every_writable_method_round_trips_streaming() {
        let payload = b"oxar zip layer payload ".repeat(64);
        for method in [Method::Stored, Method::Deflate, Method::Zstd, Method::Bzip2] {
            let mut item = entry("data.bin", EntryKind::File);
            item.method = Some(method);
            let bytes = write_archive(&[(item, payload.clone())], None, None);
            let mut reader = ZipReader::new(source_of(bytes)).unwrap();
            let listed = reader.next_entry().unwrap().unwrap();
            assert_eq!(listed.method, Some(method), "method {method}");
            let mut got = Vec::new();
            reader
                .open_current()
                .unwrap()
                .read_to_end(&mut got)
                .unwrap();
            assert_eq!(got, payload, "method {method}");
            assert!(reader.next_entry().unwrap().is_none());
        }
    }

    #[test]
    fn dirs_symlinks_and_comments_round_trip() {
        let dir = entry("dir", EntryKind::Dir);
        let file = entry("dir/file.txt", EntryKind::File);
        let mut link = entry("link", EntryKind::Symlink);
        link.link_target = Some(b"dir/file.txt".to_vec());
        link.size_hint = Some(12);
        let mut commented = entry("note.txt", EntryKind::File);
        commented.size_hint = Some(2);

        let mut buffer = Vec::new();
        {
            let cursor = std::io::Cursor::new(&mut buffer);
            let mut writer = ZipWriter::new(cursor);
            writer.set_comment("archive note").unwrap();
            writer.add(&dir, &mut std::io::empty()).unwrap();
            writer.add(&file, &mut b"payload".as_slice()).unwrap();
            writer.add(&link, &mut std::io::empty()).unwrap();
            writer
                .add_with_comment(&commented, Some("entry note"), &mut b"ok".as_slice())
                .unwrap();
            writer.finish().unwrap();
        }

        let mut reader = ZipReader::new(source_of(buffer)).unwrap();
        assert_eq!(reader.comment(), b"archive note");
        let mut seen = Vec::new();
        while let Some(listed) = reader.next_entry().unwrap() {
            seen.push((listed.path.clone(), listed.kind));
            match listed.kind {
                EntryKind::Symlink => {
                    assert_eq!(
                        listed.link_target.as_deref(),
                        Some(b"dir/file.txt".as_slice())
                    );
                    assert!(listed.mode.unwrap() & S_IFLNK == S_IFLNK);
                }
                EntryKind::File => {
                    let mut got = Vec::new();
                    reader
                        .open_current()
                        .unwrap()
                        .read_to_end(&mut got)
                        .unwrap();
                    assert!(got == b"payload" || got == b"ok", "got {:?}", got);
                    if listed.path == "note.txt" {
                        assert_eq!(listed.comment.as_deref(), Some("entry note"));
                    }
                }
                _ => {}
            }
        }
        assert_eq!(
            seen,
            vec![
                ("dir/".to_string(), EntryKind::Dir),
                ("dir/file.txt".to_string(), EntryKind::File),
                ("link".to_string(), EntryKind::Symlink),
                ("note.txt".to_string(), EntryKind::File),
            ]
        );
    }

    #[test]
    fn password_selects_aes_and_missing_or_wrong_passwords_are_reported() {
        let mut item = entry("secret.txt", EntryKind::File);
        item.size_hint = Some(10);
        let payload = b"top secret".to_vec();
        let bytes = write_archive(&[(item, payload.clone())], None, Some(b"hunter2"));

        let mut reader = ZipReader::open(
            source_of(bytes.clone()),
            &Policy::default(),
            Some(Secret::from("hunter2")),
            NameEncoding::default(),
        )
        .unwrap();
        let listed = reader.next_entry().unwrap().unwrap();
        assert!(listed.encrypted);
        let mut got = Vec::new();
        reader
            .open_current()
            .unwrap()
            .read_to_end(&mut got)
            .unwrap();
        assert_eq!(got, payload);

        let wrong = ZipReader::open(
            source_of(bytes.clone()),
            &Policy::default(),
            Some(Secret::from("nope")),
            NameEncoding::default(),
        );
        assert!(matches!(wrong, Err(Error::WrongPassword { .. })));

        let mut reader = ZipReader::new(source_of(bytes)).unwrap();
        assert!(reader.next_entry().unwrap().unwrap().encrypted);
        match reader.open_current() {
            Err(Error::PasswordRequired { .. }) => {}
            other => panic!(
                "expected PasswordRequired, got {other:?}",
                other = other.err()
            ),
        }
    }

    #[test]
    fn strict_validation_rejects_tampered_local_headers() {
        let mut item = entry("strict.txt", EntryKind::File);
        item.method = Some(Method::Stored);
        let mut bytes = write_archive(&[(item, b"strict payload".to_vec())], None, None);
        let local = bytes
            .windows(4)
            .position(|window| window == b"PK\x03\x04")
            .unwrap();
        bytes[local + 14] ^= 0xff;
        let policy = Policy {
            strict: true,
            ..Policy::default()
        };
        let mut probe = source_of(bytes.clone()).reader();
        let _ = crate::format::zip_validate::validate(&mut probe, true);
        let rejected = ZipReader::open(
            source_of(bytes.clone()),
            &policy,
            None,
            NameEncoding::default(),
        );
        match &rejected {
            Ok(_) => panic!("validate accepted tamper (Ok)"),
            Err(e) => eprintln!("rejected = {}", e),
        }
        assert!(matches!(rejected, Err(Error::Corrupt { .. })));
        // An explicitly lenient policy still lists the entry.
        let lenient = Policy {
            strict: false,
            ..Policy::default()
        };
        let mut reader =
            ZipReader::open(source_of(bytes), &lenient, None, NameEncoding::default()).unwrap();
        assert!(reader.next_entry().unwrap().is_some());
    }

    #[test]
    fn unknown_size_sets_the_zip64_large_file_flag() {
        let mut streaming = entry("big.bin", EntryKind::File);
        streaming.size_hint = None;
        let mut known = entry("small.bin", EntryKind::File);
        known.size_hint = Some(3);
        let zip64 = write_archive(&[(streaming, b"abc".to_vec())], None, None);
        let plain = write_archive(&[(known, b"abc".to_vec())], None, None);
        assert!(zip64.windows(4).any(|window| window == b"\x01\x00\x10\x00"));
        assert!(!plain.windows(4).any(|window| window == b"\x01\x00\x10\x00"));
        // The zip64 archive still reads back.
        let mut reader = ZipReader::new(source_of(zip64.clone())).unwrap();
        let listed = reader.next_entry().unwrap().unwrap();
        assert_eq!(listed.size, Some(3));
        let mut got = Vec::new();
        reader
            .open_current()
            .unwrap()
            .read_to_end(&mut got)
            .unwrap();
        assert_eq!(got, b"abc");

        let mut tampered = zip64;
        let local = tampered
            .windows(4)
            .position(|window| window == b"PK\x03\x04")
            .unwrap();
        let name_len = usize::from(u16::from_le_bytes([
            tampered[local + 26],
            tampered[local + 27],
        ]));
        let zip64_data = local + 30 + name_len + 4;
        tampered[zip64_data + 8] ^= 1;
        assert!(ZipReader::new(source_of(tampered)).is_err());
    }

    #[test]
    fn unicode_extra_field_names_decode_as_utf8() {
        // Hand-build a store-only zip whose primary name is CP437 but that
        // carries a valid Info-ZIP unicode path extra field.
        let raw_name = b"caf\x82.txt".to_vec();
        let mut bytes = Vec::new();
        let utf8_name = "café.txt".as_bytes();
        let crc = crc32fast::hash(&raw_name);
        let mut extra = Vec::new();
        extra.extend_from_slice(&0x7075u16.to_le_bytes());
        extra.extend_from_slice(&((5 + utf8_name.len()) as u16).to_le_bytes());
        extra.push(1);
        extra.extend_from_slice(&crc.to_le_bytes());
        extra.extend_from_slice(utf8_name);
        let data = b"body".to_vec();
        let crc_data = crc32fast::hash(&data);
        let name_len = raw_name.len() as u16;
        let local_offset = bytes.len() as u32;
        bytes.extend_from_slice(b"PK\x03\x04");
        bytes.extend_from_slice(&20u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&crc_data.to_le_bytes());
        bytes.extend_from_slice(&(data.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&(data.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&name_len.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&raw_name);
        bytes.extend_from_slice(&data);
        let cd_offset = bytes.len() as u32;
        bytes.extend_from_slice(b"PK\x01\x02");
        bytes.extend_from_slice(&20u16.to_le_bytes());
        bytes.extend_from_slice(&20u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&crc_data.to_le_bytes());
        bytes.extend_from_slice(&(data.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&(data.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&name_len.to_le_bytes());
        bytes.extend_from_slice(&(extra.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&local_offset.to_le_bytes());
        bytes.extend_from_slice(&raw_name);
        bytes.extend_from_slice(&extra);
        let cd_size = bytes.len() as u32 - cd_offset;
        bytes.extend_from_slice(b"PK\x05\x06");
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&cd_size.to_le_bytes());
        bytes.extend_from_slice(&cd_offset.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());

        let mut reader = ZipReader::new(source_of(bytes)).unwrap();
        let listed = reader.next_entry().unwrap().unwrap();
        assert_eq!(listed.path, "café.txt");
        assert_eq!(listed.path_bytes, "café.txt".as_bytes());
        let mut got = Vec::new();
        reader
            .open_current()
            .unwrap()
            .read_to_end(&mut got)
            .unwrap();
        assert_eq!(got, b"body");
    }

    #[test]
    fn debug_dump_layout() {
        let dir = entry("dir", EntryKind::Dir);
        let file = entry("dir/file.txt", EntryKind::File);
        let mut link = entry("link", EntryKind::Symlink);
        link.link_target = Some(b"dir/file.txt".to_vec());
        link.size_hint = Some(12);
        let mut commented = entry("note.txt", EntryKind::File);
        commented.size_hint = Some(2);

        let mut buffer = Vec::new();
        {
            let cursor = std::io::Cursor::new(&mut buffer);
            let mut writer = ZipWriter::new(cursor);
            writer.set_comment("archive note").unwrap();
            writer.add(&dir, &mut std::io::empty()).unwrap();
            writer.add(&file, &mut b"payload".as_slice()).unwrap();
            writer.add(&link, &mut std::io::empty()).unwrap();
            writer
                .add_with_comment(&commented, Some("entry note"), &mut b"ok".as_slice())
                .unwrap();
            writer.finish().unwrap();
        }
        eprintln!("total len {}", buffer.len());
        let mut pos = 0usize;
        while let Some(found) = buffer[pos..].windows(4).position(|w| w == b"PK\x03\x04") {
            let at = pos + found;
            let method = u16::from_le_bytes([buffer[at + 8], buffer[at + 9]]);
            let flags = u16::from_le_bytes([buffer[at + 6], buffer[at + 7]]);
            let crc = u32::from_le_bytes([
                buffer[at + 14],
                buffer[at + 15],
                buffer[at + 16],
                buffer[at + 17],
            ]);
            let comp = u32::from_le_bytes([
                buffer[at + 18],
                buffer[at + 19],
                buffer[at + 20],
                buffer[at + 21],
            ]);
            let uncomp = u32::from_le_bytes([
                buffer[at + 22],
                buffer[at + 23],
                buffer[at + 24],
                buffer[at + 25],
            ]);
            let nlen = u16::from_le_bytes([buffer[at + 26], buffer[at + 27]]);
            let elen = u16::from_le_bytes([buffer[at + 28], buffer[at + 29]]);
            let name =
                String::from_utf8_lossy(&buffer[at + 30..at + 30 + nlen as usize]).into_owned();
            eprintln!(
                "local at {at} method {method} flags {flags:#x} crc {crc:#x} comp {comp} uncomp {uncomp} name {name:?} data{:?}",
                String::from_utf8_lossy(
                    &buffer[at + 30 + nlen as usize + elen as usize
                        ..(at + 30 + nlen as usize + elen as usize + 20).min(buffer.len())]
                )
            );
            pos = at + 4;
        }
        let mut reaches = 0usize;
        let mut reader = ZipReader::new(source_of(buffer)).unwrap();
        while let Some(listed) = reader.next_entry().unwrap() {
            let mut got = Vec::new();
            if listed.is_file() {
                reader
                    .open_current()
                    .unwrap()
                    .read_to_end(&mut got)
                    .unwrap();
            }
            eprintln!(
                "entry {} {:?} kind {:?} size {:?} got {:?}",
                listed.index,
                listed.path,
                listed.kind,
                listed.size,
                String::from_utf8_lossy(&got)
            );
            reaches += 1;
        }
        assert!(reaches > 0);
    }

    #[test]
    fn debug_strict_tamper() {
        let mut item = entry("strict.txt", EntryKind::File);
        item.method = Some(Method::Stored);
        let mut bytes = write_archive(&[(item, b"strict payload".to_vec())], None, None);
        eprintln!("flags {:?}", u16::from_le_bytes([bytes[6], bytes[7]]));
        eprintln!("local crc {:02x?}", &bytes[14..18]);
        // central header crc
        let cd = bytes.windows(4).position(|w| w == b"PK\x01\x02").unwrap();
        eprintln!("central crc {:02x?}", &bytes[cd + 16..cd + 20]);
        let local = bytes
            .windows(4)
            .position(|window| window == b"PK\x03\x04")
            .unwrap();
        bytes[local + 14] ^= 0xff;
        let mut probe = source_of(bytes.clone()).reader();
        let out = crate::format::zip_validate::validate(&mut probe, true);
        eprintln!("validate after tamper: {out:?}");
        let policy = Policy {
            strict: true,
            ..Policy::default()
        };
        let rejected = ZipReader::open(source_of(bytes), &policy, None, NameEncoding::default());
        eprintln!("open after tamper: {:?}", rejected.err());
    }

    #[test]
    fn open_entry_works_in_arbitrary_order() {
        let first = entry("first.txt", EntryKind::File);
        let second = entry("second.txt", EntryKind::File);
        let bytes = write_archive(
            &[(first, b"one".to_vec()), (second, b"two".to_vec())],
            None,
            None,
        );
        let mut reader = ZipReader::new(source_of(bytes)).unwrap();
        let listed: Vec<Entry> = std::iter::from_fn(|| reader.next_entry().unwrap()).collect();
        assert_eq!(listed.len(), 2);
        let mut got = Vec::new();
        reader
            .open_entry(&listed[1])
            .unwrap()
            .read_to_end(&mut got)
            .unwrap();
        assert_eq!(got, b"two");
        let mut got = Vec::new();
        reader
            .open_entry(&listed[0])
            .unwrap()
            .read_to_end(&mut got)
            .unwrap();
        assert_eq!(got, b"one");
    }
}
