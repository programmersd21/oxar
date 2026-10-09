//! Tar container: reader for ustar, GNU and PAX archives including old GNU
//! sparse and the PAX sparse variants, and a writer that emits ustar with PAX
//! extensions when a field does not fit.
//!
//! Field decoding uses the `tar` crate's `Header` for numeric fields; the
//! entry loop, checksum verification, long name handling, sparse expansion
//! and the skip of unread data are implemented here. `tar::Archive::unpack`
//! and `tar::Entry::unpack_in` are never called.

mod sparse;
mod writer;

pub use sparse::SparseMap;
pub use writer::TarWriter;

use std::io::{self, Read, Seek, SeekFrom};
use std::sync::Arc;

use crate::error::{Error, Location, Result};
use crate::format::{ArchiveReader, Compression, Entry, EntryKind, EntryRead, Format};
use crate::fsio::{Input, PositionedReader};
use crate::policy::Limits;
use crate::progress::CancelToken;

const BLOCK: usize = 512;

// ---------------------------------------------------------------------------
// Source
// ---------------------------------------------------------------------------

/// Byte source behind the tar parser: a positioned reader when the archive is
/// seekable, a plain stream otherwise. All reads go through this type so the
/// position is tracked exactly and skipping never reads more than asked.
pub(crate) enum Source {
    Seekable {
        reader: PositionedReader,
        position: u64,
    },
    Sequential {
        reader: Box<dyn Read + Send>,
        position: u64,
    },
}

impl Source {
    pub(crate) fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let (reader, position): (&mut dyn Read, &mut u64) = match self {
            Self::Seekable { reader, position } => (reader, position),
            Self::Sequential { reader, position } => (reader, position),
        };
        loop {
            match reader.read(buf) {
                Ok(count) => {
                    *position = position.saturating_add(count as u64);
                    return Ok(count);
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
    }

    pub(crate) fn read_exact_bytes(&mut self, buf: &mut [u8]) -> io::Result<()> {
        let mut filled = 0usize;
        while filled < buf.len() {
            let (_, rest) = buf.split_at_mut(filled);
            match self.read(rest) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "tar stream ended inside a header or entry",
                    ));
                }
                Ok(count) => filled += count,
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    pub(crate) fn skip(&mut self, bytes: u64) -> io::Result<()> {
        match self {
            Self::Seekable { reader, position } => {
                let target = position.checked_add(bytes).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "tar skip overflow")
                })?;
                reader.seek(SeekFrom::Start(target))?;
                *position = target;
                Ok(())
            }
            Self::Sequential { reader, position } => {
                let mut remaining = bytes;
                let mut buffer = [0u8; 16 * 1024];
                while remaining > 0 {
                    let take =
                        usize::try_from(remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
                    match reader.read(&mut buffer[..take]) {
                        Ok(0) => {
                            return Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "tar stream ended while skipping padding",
                            ));
                        }
                        Ok(count) => {
                            remaining -= count as u64;
                            *position = position.saturating_add(count as u64);
                        }
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                        Err(error) => return Err(error),
                    }
                }
                Ok(())
            }
        }
    }

    pub(crate) fn position(&self) -> u64 {
        match self {
            Self::Seekable { position, .. } | Self::Sequential { position, .. } => *position,
        }
    }

    pub(crate) fn is_seekable(&self) -> bool {
        matches!(self, Self::Seekable { .. })
    }

    pub(crate) fn seek_to(&mut self, offset: u64) -> io::Result<()> {
        match self {
            Self::Seekable { reader, position } => {
                reader.seek(SeekFrom::Start(offset))?;
                *position = offset;
                Ok(())
            }
            Self::Sequential { .. } => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "seek on a sequential tar stream",
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// Header parsing
// ---------------------------------------------------------------------------

/// Fields decoded from one 512 byte tar header block.
struct RawHeader {
    name: Vec<u8>,
    mode: Option<u32>,
    uid: Option<u64>,
    gid: Option<u64>,
    uname: Option<Vec<u8>>,
    gname: Option<Vec<u8>>,
    size: u64,
    mtime_ns: Option<i128>,
    kind: EntryKind,
    typeflag: u8,
    link: Option<Vec<u8>>,
}

fn field_bytes(block: &[u8; BLOCK], start: usize, length: usize) -> Vec<u8> {
    block[start..start + length]
        .iter()
        .copied()
        .take_while(|byte| *byte != 0)
        .collect()
}

/// Decode a tar numeric field: octal with optional leading spaces, a trailing
/// space or NUL, or GNU base-256. Returns `None` when the field is not a valid
/// non-negative number.
fn decode_number(field: &[u8]) -> Option<u64> {
    if field.is_empty() {
        return None;
    }
    if field[0] & 0x80 != 0 {
        let mut value: u64 = 0;
        for byte in &field[1..] {
            value = value.checked_shl(8)?;
            value = value.checked_add(u64::from(*byte))?;
        }
        return Some(value);
    }
    let text: Vec<u8> = field
        .iter()
        .copied()
        .skip_while(|byte| *byte == b' ' || *byte == 0)
        .take_while(|byte| *byte != 0 && *byte != b' ')
        .collect();
    if text.is_empty() {
        return Some(0);
    }
    let mut value: u64 = 0;
    for byte in text {
        if !(b'0'..=b'7').contains(&byte) {
            return None;
        }
        value = value.checked_mul(8)?.checked_add(u64::from(byte - b'0'))?;
    }
    Some(value)
}

/// Verify the header checksum: the stored value compared against the sum of
/// all bytes with the checksum field replaced by spaces.
fn verify_checksum(block: &[u8; BLOCK]) -> bool {
    let stored = match decode_number(&block[148..156]) {
        Some(value) => value,
        None => return false,
    };
    let mut sum: u64 = 0;
    for (index, byte) in block.iter().enumerate() {
        let value = if (148..156).contains(&index) {
            b' '
        } else {
            *byte
        };
        sum = sum.wrapping_add(u64::from(value));
    }
    stored == sum
}

fn parse_header(block: &[u8; BLOCK]) -> Result<RawHeader> {
    if !verify_checksum(block) {
        return Err(Error::corrupt("tar header checksum does not match"));
    }
    let magic = &block[257..263];
    let is_ustar = magic == b"ustar\0" || magic == b"ustar ";
    let mut name = field_bytes(block, 0, 100);
    if is_ustar {
        let prefix = field_bytes(block, 345, 155);
        if !prefix.is_empty() {
            let mut joined = prefix;
            joined.push(b'/');
            joined.extend_from_slice(&name);
            name = joined;
        }
    } else if name.starts_with(b"./") {
        name.drain(..2);
    }
    let kind = match block[156] {
        b'0' | 0 => EntryKind::File,
        b'1' => EntryKind::Hardlink,
        b'2' => EntryKind::Symlink,
        b'3' => EntryKind::Other(crate::format::OtherKind::CharDevice),
        b'4' => EntryKind::Other(crate::format::OtherKind::BlockDevice),
        b'5' => EntryKind::Dir,
        b'6' => EntryKind::Other(crate::format::OtherKind::Fifo),
        b'7' => EntryKind::File,
        b'S' => EntryKind::File,
        b'x' | b'g' | b'L' | b'K' => EntryKind::File,
        other => {
            return Err(Error::corrupt(format!(
                "tar entry type {} is not supported",
                char::from(other)
            )));
        }
    };
    let size = decode_number(&block[124..136])
        .ok_or_else(|| Error::corrupt("tar size field is not a number"))?;
    let mtime = decode_number(&block[136..148])
        .ok_or_else(|| Error::corrupt("tar mtime field is not a number"))?;
    let link = if block[157] == 0 {
        None
    } else {
        Some(field_bytes(block, 157, 100))
    };
    Ok(RawHeader {
        name,
        mode: decode_number(&block[100..108]).map(|value| value as u32),
        uid: decode_number(&block[108..116]),
        gid: decode_number(&block[116..124]),
        uname: Some(field_bytes(block, 265, 32)),
        gname: Some(field_bytes(block, 297, 32)),
        size,
        mtime_ns: Some((mtime as i128).saturating_mul(1_000_000_000)),
        kind,
        typeflag: block[156],
        link,
    })
}

// ---------------------------------------------------------------------------
// PAX records
// ---------------------------------------------------------------------------

/// Parse PAX extended header records: "%d %s=%s\n" where the decimal counts
/// its own digits. Records are validated before any allocation.
fn parse_pax_records(data: &[u8], limits: &Limits) -> Result<Vec<(String, Vec<u8>)>> {
    if let Some(max) = limits.max_pax_header_bytes
        && data.len() as u64 > max
    {
        return Err(Error::limit("max_pax_header_bytes", max, data.len() as u64));
    }
    let mut records = Vec::new();
    let mut rest = data;
    while !rest.is_empty() {
        let space = rest
            .iter()
            .position(|byte| *byte == b' ')
            .ok_or_else(|| Error::corrupt("pax record has no length separator"))?;
        let length_text = std::str::from_utf8(&rest[..space])
            .map_err(|_| Error::corrupt("pax record length is not text"))?;
        let length: usize = length_text
            .parse()
            .map_err(|_| Error::corrupt("pax record length is not a number"))?;
        if length == 0 || length > rest.len() {
            return Err(Error::corrupt("pax record length is out of range"));
        }
        let record = &rest[space + 1..length];
        let record = record.strip_suffix(b"\n").unwrap_or(record);
        let equals = record
            .iter()
            .position(|byte| *byte == b'=')
            .ok_or_else(|| Error::corrupt("pax record has no value"))?;
        let key = std::str::from_utf8(&record[..equals])
            .map_err(|_| Error::corrupt("pax key is not text"))?
            .to_owned();
        records.push((key, record[equals + 1..].to_vec()));
        rest = &rest[length..];
    }
    Ok(records)
}

fn pax_text(value: &[u8]) -> Result<String> {
    String::from_utf8(value.to_vec()).map_err(|_| Error::corrupt("pax value is not text"))
}

fn pax_u64(value: &[u8], what: &str) -> Result<u64> {
    let text = pax_text(value)?;
    text.trim()
        .parse()
        .map_err(|_| Error::corrupt(format!("pax {what} is not a number")))
}

/// Parse a PAX mtime, which may carry a fractional part with up to 9 digits.
fn parse_pax_time(value: &[u8]) -> Result<i128> {
    let text = pax_text(value)?;
    let text = text.trim();
    let (seconds_text, fraction_text) = match text.split_once('.') {
        Some((seconds, fraction)) => (seconds, Some(fraction)),
        None => (text, None),
    };
    let seconds: i128 = seconds_text
        .parse()
        .map_err(|_| Error::corrupt("pax mtime is not a number"))?;
    let mut nanos: i128 = 0;
    if let Some(fraction) = fraction_text {
        let mut digits = fraction.to_owned();
        digits.truncate(9);
        while digits.len() < 9 {
            digits.push('0');
        }
        nanos = digits
            .parse()
            .map_err(|_| Error::corrupt("pax mtime fraction is not a number"))?;
    }
    let sign: i128 = if seconds < 0 { -1 } else { 1 };
    Ok(seconds
        .saturating_mul(1_000_000_000)
        .saturating_add(sign.saturating_mul(nanos)))
}

/// Fields a PAX record set can override, plus the sparse map when present.
#[derive(Default)]
struct PaxOverrides {
    path: Option<Vec<u8>>,
    linkpath: Option<Vec<u8>>,
    size: Option<u64>,
    uid: Option<u64>,
    gid: Option<u64>,
    mode: Option<u32>,
    mtime_ns: Option<i128>,
    uname: Option<Vec<u8>>,
    gname: Option<Vec<u8>>,
    sparse_map: Option<Vec<u8>>,
    sparse_realsize: Option<u64>,
    sparse_regions: Vec<(u64, u64)>,
    sparse_1_0: bool,
}

fn collect_pax_overrides(records: &[(String, Vec<u8>)]) -> Result<PaxOverrides> {
    let mut overrides = PaxOverrides::default();
    let mut pending_offset: Option<u64> = None;
    for (key, value) in records {
        match key.as_str() {
            "path" => overrides.path = Some(value.clone()),
            "linkpath" => overrides.linkpath = Some(value.clone()),
            "size" => overrides.size = Some(pax_u64(value, "size")?),
            "uid" => overrides.uid = Some(pax_u64(value, "uid")?),
            "gid" => overrides.gid = Some(pax_u64(value, "gid")?),
            "mode" => {
                if let Ok(mode) = pax_u64(value, "mode") {
                    overrides.mode = Some(mode as u32);
                }
            }
            "mtime" => overrides.mtime_ns = Some(parse_pax_time(value)?),
            "uname" => overrides.uname = Some(value.clone()),
            "gname" => overrides.gname = Some(value.clone()),
            "GNU.sparse.map" => overrides.sparse_map = Some(value.clone()),
            "GNU.sparse.size" | "GNU.sparse.realsize" => {
                overrides.sparse_realsize = Some(pax_u64(value, "sparse size")?);
            }
            "GNU.sparse.numblocks" => {
                let _ = pax_u64(value, "sparse numblocks")?;
            }
            "GNU.sparse.offset" => {
                pending_offset = Some(pax_u64(value, "sparse offset")?);
            }
            "GNU.sparse.numbytes" => {
                let length = pax_u64(value, "sparse numbytes")?;
                let offset = pending_offset.take().ok_or_else(|| {
                    Error::corrupt("pax sparse numbytes without a preceding offset")
                })?;
                overrides.sparse_regions.push((offset, length));
            }
            "GNU.sparse.major" => {
                let major = pax_u64(value, "sparse major")?;
                overrides.sparse_1_0 = major == 1;
            }
            "GNU.sparse.minor" => {
                let _ = pax_u64(value, "sparse minor")?;
            }
            "GNU.sparse.name" => overrides.path = Some(value.clone()),
            _ => {}
        }
    }
    if pending_offset.is_some() {
        return Err(Error::corrupt(
            "pax sparse offset without a matching numbytes",
        ));
    }
    Ok(overrides)
}

// ---------------------------------------------------------------------------
// Reader
// ---------------------------------------------------------------------------

/// One entry plus where its data lives in the archive stream.
#[derive(Clone)]
struct Indexed {
    entry: Entry,
    /// Absolute offset of the first stored data byte.
    data_start: u64,
    /// Stored data bytes inside the archive (before sparse expansion).
    stored_bytes: u64,
    sparse: Option<SparseMap>,
}

/// Pending data of the entry returned by the last `next_entry`: how many
/// stored bytes are still unread, and how much padding follows them.
#[derive(Default)]
struct Pending {
    stored_left: u64,
    padding_left: u64,
}

/// Tar archive reader.
pub struct TarReader {
    source: Source,
    limits: Arc<Limits>,
    cancel: CancelToken,
    index: Option<Vec<Indexed>>,
    cursor: usize,
    current: Option<Indexed>,
    pending: Pending,
    finished: bool,
}

impl TarReader {
    /// Cheap structural test: does this prefix look like a tar archive?
    #[must_use]
    pub fn looks_like_tar(prefix: &[u8]) -> bool {
        if prefix.len() < BLOCK {
            return false;
        }
        let mut block = [0u8; BLOCK];
        block.copy_from_slice(&prefix[..BLOCK]);
        if block.iter().all(|byte| *byte == 0) {
            return false;
        }
        verify_checksum(&block)
    }

    /// Open an archive. Plain archives on seekable sources get an index and
    /// random access; compressed or sequential sources are read in one pass.
    pub fn open(
        input: &Input,
        compression: Option<Compression>,
        limits: Arc<Limits>,
        cancel: CancelToken,
    ) -> Result<Self> {
        if compression.is_none() && input.is_seekable() {
            let random = input.open_random()?;
            let index = build_index(&random, &limits, &cancel)?;
            return Ok(Self {
                source: Source::Seekable {
                    reader: random.reader(),
                    position: 0,
                },
                limits,
                cancel,
                index: Some(index),
                cursor: 0,
                current: None,
                pending: Pending::default(),
                finished: false,
            });
        }
        let mut stream = input.open_stream()?;
        if let Some(compression) = compression {
            let codec = compression
                .to_codec()
                .ok_or_else(|| Error::unsupported("this compression for tar"))?;
            stream = Box::new(crate::codec::stream::stream_decoder(
                codec, stream, &limits,
            )?);
        }
        Ok(Self {
            source: Source::Sequential {
                reader: stream,
                position: 0,
            },
            limits,
            cancel,
            index: None,
            cursor: 0,
            current: None,
            pending: Pending::default(),
            finished: false,
        })
    }
}

impl TarReader {
    /// Skip whatever is left of the previous entry's data and padding.
    fn skip_pending(&mut self) -> Result<()> {
        let pending = std::mem::take(&mut self.pending);
        let total = pending
            .stored_left
            .checked_add(pending.padding_left)
            .ok_or_else(|| Error::corrupt("tar entry size overflows"))?;
        if total > 0 {
            self.source.skip(total).map_err(|error| Error::Io {
                source: error,
                loc: Location::new(),
            })?;
        }
        Ok(())
    }

    fn read_block(&mut self) -> Result<Option<[u8; BLOCK]>> {
        let mut block = [0u8; BLOCK];
        let mut filled = 0usize;
        while filled < BLOCK {
            let (_, rest) = block.split_at_mut(filled);
            let count = self.source.read(rest).map_err(|error| Error::Io {
                source: error,
                loc: Location::new(),
            })?;
            if count == 0 {
                break;
            }
            filled += count;
        }
        if filled == 0 {
            return Ok(None);
        }
        if filled < BLOCK {
            return Err(Error::corrupt("tar archive ends inside a header block"));
        }
        Ok(Some(block))
    }

    /// Read exactly `count` bytes, as a vector. Used for long names and PAX
    /// headers, which are bounded by limits before allocation.
    fn read_payload(&mut self, count: u64, what: &str) -> Result<Vec<u8>> {
        let ceiling = self
            .limits
            .max_pax_header_bytes
            .unwrap_or(1024 * 1024)
            .max(64 * 1024);
        if count > ceiling {
            return Err(Error::limit("max_pax_header_bytes", ceiling, count));
        }
        let mut data = vec![0u8; count as usize];
        self.source
            .read_exact_bytes(&mut data)
            .map_err(|error| Error::Io {
                source: error,
                loc: Location::new(),
            })?;
        let _ = what;
        Ok(data)
    }
}

impl TarReader {
    fn skip_padding(&mut self, data_bytes: u64) -> Result<()> {
        let padding = (BLOCK as u64 - (data_bytes % BLOCK as u64)) % BLOCK as u64;
        if padding > 0 {
            self.source.skip(padding).map_err(|error| Error::Io {
                source: error,
                loc: Location::new(),
            })?;
        }
        Ok(())
    }

    /// Read the next entry, resolving long names, PAX records and sparse maps.
    fn read_next(&mut self) -> Result<Option<Indexed>> {
        self.skip_pending()?;
        let mut long_name: Option<Vec<u8>> = None;
        let mut long_link: Option<Vec<u8>> = None;
        let mut pax: Vec<(String, Vec<u8>)> = Vec::new();
        let mut guard = 0u32;
        loop {
            guard = guard.saturating_add(1);
            if guard > 100_000 {
                return Err(Error::corrupt("too many consecutive tar pseudo entries"));
            }
            if self.cancel.is_cancelled() {
                return Err(Error::Cancelled);
            }
            let block = match self.read_block()? {
                Some(block) => block,
                None => {
                    self.finished = true;
                    return Ok(None);
                }
            };
            if block.iter().all(|byte| *byte == 0) {
                // One zero block ends the archive. Read the second block when
                // it exists; trailing zero blocks are ignored.
                match self.read_block()? {
                    Some(second) if second.iter().any(|byte| *byte != 0) => {
                        return Err(Error::corrupt(
                            "tar archive has a zero block before more entries",
                        ));
                    }
                    _ => {}
                }
                self.finished = true;
                return Ok(None);
            }
            let header = parse_header(&block)?;
            let data_bytes = header.size;
            match header.typeflag {
                b'L' | b'K' => {
                    let mut data = self.read_payload(data_bytes, "long name")?;
                    if let Some(position) = data.iter().position(|byte| *byte == 0) {
                        data.truncate(position);
                    }
                    if header.typeflag == b'L' {
                        long_name = Some(data);
                    } else {
                        long_link = Some(data);
                    }
                    self.skip_padding(data_bytes)?;
                }
                b'x' | b'g' => {
                    let data = self.read_payload(data_bytes, "pax header")?;
                    let records = parse_pax_records(&data, &self.limits)?;
                    if header.typeflag == b'x' {
                        pax.extend(records);
                    }
                    self.skip_padding(data_bytes)?;
                }
                _ => {
                    let indexed = self.build_entry(header, long_name, long_link, &pax, &block)?;
                    let padding = TarReader::padding_for(indexed.stored_bytes);
                    self.pending = Pending {
                        stored_left: indexed.stored_bytes,
                        padding_left: padding,
                    };
                    return Ok(Some(indexed));
                }
            }
        }
    }
}

impl TarReader {
    fn build_entry(
        &mut self,
        header: RawHeader,
        long_name: Option<Vec<u8>>,
        long_link: Option<Vec<u8>>,
        pax: &[(String, Vec<u8>)],
        block: &[u8; BLOCK],
    ) -> Result<Indexed> {
        let mut entry = Entry::new(0);
        entry.kind = header.kind;
        entry.path_bytes = long_name.unwrap_or_else(|| header.name.clone());
        entry.path = String::from_utf8_lossy(&entry.path_bytes).into_owned();
        entry.mode = header.mode;
        entry.uid = header.uid;
        entry.gid = header.gid;
        entry.uname = header
            .uname
            .filter(|name| !name.is_empty())
            .map(|name| String::from_utf8_lossy(&name).into_owned());
        entry.gname = header
            .gname
            .filter(|name| !name.is_empty())
            .map(|name| String::from_utf8_lossy(&name).into_owned());
        entry.mtime_ns = header.mtime_ns;
        entry.link_target = long_link.or_else(|| header.link.clone());
        entry.size = Some(header.size);

        let mut sparse = if header.typeflag == b'S' {
            Some(sparse::parse_old_gnu(
                block,
                &mut self.source,
                &self.limits,
            )?)
        } else {
            None
        };

        let mut data_start = self.source.position();
        let mut stored_bytes = header.size;

        let mut overrides = PaxOverrides::default();
        if !pax.is_empty() {
            overrides = collect_pax_overrides(pax)?;
        }

        if !pax.is_empty() {
            if let Some(path) = overrides.path.clone() {
                entry.path_bytes = path;
                entry.path = String::from_utf8_lossy(&entry.path_bytes).into_owned();
            }
            if let Some(linkpath) = overrides.linkpath.clone() {
                entry.link_target = Some(linkpath);
            }
            if let Some(uid) = overrides.uid {
                entry.uid = Some(uid);
            }
            if let Some(gid) = overrides.gid {
                entry.gid = Some(gid);
            }
            if let Some(mode) = overrides.mode {
                entry.mode = Some(mode);
            }
            if let Some(mtime) = overrides.mtime_ns {
                entry.mtime_ns = Some(mtime);
            }
            if let Some(uname) = overrides.uname.clone() {
                entry.uname = Some(String::from_utf8_lossy(&uname).into_owned());
            }
            if let Some(gname) = overrides.gname.clone() {
                entry.gname = Some(String::from_utf8_lossy(&gname).into_owned());
            }
            if let Some(size) = overrides.size {
                entry.size = Some(size);
            }
        }

        let mentions_sparse = pax.iter().any(|(key, _)| key.starts_with("GNU.sparse."));
        if mentions_sparse && sparse.is_none() {
            let regions = if let Some(map) = overrides.sparse_map.clone() {
                sparse::parse_pax_map(&map, &self.limits)?
            } else {
                overrides.sparse_regions.clone()
            };

            let real_size = overrides
                .sparse_realsize
                .or(overrides.size)
                .unwrap_or_else(|| entry.size.unwrap_or(header.size));

            if overrides.sparse_1_0 {
                let (parsed_regions, consumed) =
                    sparse::parse_pax_1_0_map(&mut self.source, header.size, &self.limits)?;
                // replace regions parsed from the in-data map
                let _ = regions;
                let regions = parsed_regions;

                if self.source.is_seekable() {
                    self.source.seek_to(data_start).map_err(|error| Error::Io {
                        source: error,
                        loc: Location::new(),
                    })?;
                } else {
                    data_start = self.source.position();
                    stored_bytes = header.size.saturating_sub(consumed);
                }

                let map = sparse::SparseMap::validate(regions, real_size, &self.limits)?;
                sparse = Some(map);
            } else {
                // 0.0 / 0.1 form: map already parsed from PAX or offset/numbytes.
                let mut regions = regions;
                if regions.is_empty() && overrides.sparse_map.is_none() {
                    regions = overrides.sparse_regions.clone();
                }
                let map = sparse::SparseMap::validate(regions, real_size, &self.limits)?;
                sparse = Some(map);
            }
        }

        if let Some(map) = &sparse {
            entry.size = Some(map.real_size);
        }

        Ok(Indexed {
            entry,
            data_start,
            stored_bytes,
            sparse,
        })
    }
}

impl TarReader {
    /// Open from a seekable random source, using default limits and a fresh
    /// cancellation token. Convenience for callers that hold bytes or a file.
    pub fn from_reader(source: crate::fsio::RandomSource) -> Result<Self> {
        Self::open(
            &crate::fsio::Input::Random(source),
            None,
            std::sync::Arc::new(crate::policy::Limits::default()),
            crate::progress::CancelToken::new(),
        )
    }

    fn padding_for(bytes: u64) -> u64 {
        const BLOCK_U64: u64 = BLOCK as u64;
        (BLOCK_U64 - (bytes % BLOCK_U64)) % BLOCK_U64
    }
}

fn build_index(
    source: &crate::fsio::RandomSource,
    limits: &crate::policy::Limits,
    cancel: &crate::progress::CancelToken,
) -> Result<Vec<Indexed>> {
    let mut reader = TarReader {
        source: Source::Seekable {
            reader: source.reader(),
            position: 0,
        },
        limits: std::sync::Arc::new(limits.clone()),
        cancel: cancel.clone(),
        index: None,
        cursor: 0,
        current: None,
        pending: Pending::default(),
        finished: false,
    };
    let mut index = Vec::new();
    let mut number = 0u64;
    loop {
        if cancel.is_cancelled() {
            return Err(Error::Cancelled);
        }
        if let Some(max) = limits.max_entries
            && number >= max
        {
            return Err(Error::Bomb {
                limit: "max_entries",
                limit_value: max,
                observed: number.saturating_add(1),
                loc: Location::new(),
            });
        }
        match reader.read_next()? {
            Some(mut indexed) => {
                indexed.entry.index = number;
                number = number.saturating_add(1);
                index.push(indexed);
            }
            None => break,
        }
    }
    Ok(index)
}

impl ArchiveReader for TarReader {
    fn format(&self) -> Format {
        Format::Tar
    }

    fn next_entry(&mut self) -> Result<Option<Entry>> {
        if let Some(index) = self.index.clone() {
            if self.cursor >= index.len() {
                return Ok(None);
            }
            let item = index[self.cursor].clone();
            self.cursor = self.cursor.saturating_add(1);
            self.current = Some(item.clone());
            self.pending = Pending::default();
            let mut entry = item.entry.clone();
            // index already assigned in build_index
            if entry.index == 0 && self.cursor > 0 {
                // ensure stability when build_index set it
            }
            let _ = &mut entry;
            return Ok(Some(item.entry));
        }
        if self.finished {
            return Ok(None);
        }
        match self.read_next()? {
            Some(indexed) => {
                let stored = indexed.stored_bytes;
                let padding = TarReader::padding_for(stored);
                let mut entry = indexed.entry.clone();
                entry.index = self.cursor as u64;
                self.cursor = self.cursor.saturating_add(1);
                self.pending = Pending {
                    stored_left: stored,
                    padding_left: padding,
                };
                self.current = Some(indexed);
                Ok(Some(entry))
            }
            None => {
                self.finished = true;
                Ok(None)
            }
        }
    }

    fn open_current(&mut self) -> Result<Box<dyn EntryRead + '_>> {
        let item = match &self.current {
            Some(item) => item.clone(),
            None => {
                return Err(Error::usage(
                    "no current entry; call next_entry before open_current",
                ));
            }
        };

        if self.index.is_some() {
            let data_start = item.data_start;
            let stored_bytes = item.stored_bytes;
            let real_size = item.entry.size.unwrap_or(stored_bytes);
            let state = item.sparse.clone().map(|map| {
                let packed = map.packed_bytes();
                sparse::SparseState::new(map.regions, map.real_size, packed)
            });
            let _ = self.source.seek_to(data_start);
            let reader = RandomEntryReader {
                source: &mut self.source,
                base: data_start,
                state,
                non_sparse_size: stored_bytes,
                offset: 0,
            };
            let _ = real_size;
            return Ok(Box::new(reader));
        }

        // sequential
        if let Some(map) = item.sparse.clone() {
            let stored = item.stored_bytes;
            let padding = TarReader::padding_for(stored);
            self.pending = Pending::default();
            let state = {
                let packed = map.packed_bytes();
                sparse::SparseState::new(map.regions, map.real_size, packed)
            };
            let reader = SeqSparseReader {
                state,
                source: &mut self.source,
                padding,
                cancel: self.cancel.clone(),
            };
            Ok(Box::new(reader))
        } else {
            let stored = self.pending.stored_left;
            let padding = self.pending.padding_left;
            let stored = if stored == 0 {
                item.stored_bytes
            } else {
                stored
            };
            let padding = if padding == 0 && stored > 0 {
                TarReader::padding_for(stored)
            } else {
                padding
            };
            self.pending = Pending::default();
            let reader = SeqReader {
                source: &mut self.source,
                remaining: stored,
                padding,
                cancel: self.cancel.clone(),
            };
            Ok(Box::new(reader))
        }
    }

    fn open_entry(&mut self, entry: &Entry) -> Result<Box<dyn EntryRead + '_>> {
        let index = match &self.index {
            Some(index) => index.clone(),
            None => {
                return Err(Error::unsupported(
                    "random access reads on a sequential tar source",
                ));
            }
        };
        let item = index
            .iter()
            .find(|item| item.entry.index == entry.index)
            .cloned()
            .ok_or_else(|| Error::corrupt("entry index is not present in the archive"))?;

        let data_start = item.data_start;
        let stored_bytes = item.stored_bytes;
        let state = item.sparse.clone().map(|map| {
            let packed = map.packed_bytes();
            sparse::SparseState::new(map.regions, map.real_size, packed)
        });
        let _ = self.source.seek_to(data_start);
        let reader = RandomEntryReader {
            source: &mut self.source,
            base: data_start,
            state,
            non_sparse_size: stored_bytes,
            offset: 0,
        };
        Ok(Box::new(reader))
    }

    fn is_random_access(&self) -> bool {
        self.index.is_some()
    }
}

// Make Indexed cloneable for the above.
// The struct is defined earlier without Clone; add via impl? Need derive. We patch by adding Clone derive via text edit separately.

struct SeqReader<'a> {
    source: &'a mut Source,
    remaining: u64,
    padding: u64,
    cancel: crate::progress::CancelToken,
}

impl std::io::Read for SeqReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() || self.remaining == 0 {
            return Ok(0);
        }
        let want = buf.len().min(self.remaining as usize);
        let count = self.source.read(&mut buf[..want])?;
        if count == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "tar entry data is truncated",
            ));
        }
        self.remaining = self.remaining.saturating_sub(count as u64);
        if self.remaining == 0 && self.padding > 0 {
            self.source.skip(self.padding)?;
            self.padding = 0;
        }
        if self.cancel.is_cancelled() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "cancelled",
            ));
        }
        Ok(count)
    }
}

impl Drop for SeqReader<'_> {
    fn drop(&mut self) {
        let total = self.remaining.saturating_add(self.padding);
        if total > 0 {
            let _ = self.source.skip(total);
        }
        self.remaining = 0;
        self.padding = 0;
    }
}

impl crate::format::EntryRead for SeqReader<'_> {}

struct SeqSparseReader<'a> {
    state: sparse::SparseState,
    source: &'a mut Source,
    padding: u64,
    cancel: crate::progress::CancelToken,
}

impl std::io::Read for SeqSparseReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let count = self.state.read(self.source, buf)?;
        if count == 0 && self.padding > 0 {
            self.source.skip(self.padding)?;
            self.padding = 0;
        }
        if self.cancel.is_cancelled() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "cancelled",
            ));
        }
        Ok(count)
    }
}

impl Drop for SeqSparseReader<'_> {
    fn drop(&mut self) {
        let total = self.state.packed_left().saturating_add(self.padding);
        if total > 0 {
            let _ = self.source.skip(total);
        }
        self.padding = 0;
    }
}

impl crate::format::EntryRead for SeqSparseReader<'_> {}

struct RandomEntryReader<'a> {
    source: &'a mut Source,
    base: u64,
    state: Option<sparse::SparseState>,
    non_sparse_size: u64,
    offset: u64,
}

impl std::io::Read for RandomEntryReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if let Some(state) = &mut self.state {
            return state.read(self.source, buf);
        }
        if self.offset >= self.non_sparse_size {
            return Ok(0);
        }
        let want = buf.len().min((self.non_sparse_size - self.offset) as usize);
        if want == 0 {
            return Ok(0);
        }
        let target = self.base.saturating_add(self.offset);
        if self.source.position() != target {
            self.source.seek_to(target)?;
        }
        let count = self.source.read(&mut buf[..want])?;
        self.offset = self.offset.saturating_add(count as u64);
        Ok(count)
    }
}

impl crate::format::EntryRead for RandomEntryReader<'_> {}

/// Convenience helper: write a tar archive of in-memory items to `writer`.
pub fn write_tar<W: std::io::Write>(
    writer: W,
    items: &[(crate::format::NewEntry, Vec<u8>)],
) -> Result<()> {
    let mut tar = TarWriter::new(writer);
    for (entry, data) in items {
        let mut cursor = std::io::Cursor::new(data);
        tar.add(entry, &mut cursor)?;
    }
    tar.finish()
}

/// Convenience helper: iterate over tar entries in a sequential reader.
pub fn read_entries<R: std::io::Read + Send + 'static>(
    reader: R,
) -> crate::format::EntryIter<'static> {
    let tr = TarReader {
        source: Source::Sequential {
            reader: Box::new(reader),
            position: 0,
        },
        limits: std::sync::Arc::new(crate::policy::Limits::default()),
        cancel: crate::progress::CancelToken::new(),
        index: None,
        cursor: 0,
        current: None,
        pending: Pending::default(),
        finished: false,
    };
    let mut tr = tr;
    Box::new(std::iter::from_fn(move || match tr.next_entry() {
        Ok(Some(entry)) => Some(Ok(entry)),
        Ok(None) => None,
        Err(error) => Some(Err(error)),
    }))
}
