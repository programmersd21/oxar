//! Tar writer: ustar header emission with PAX extensions when a field does
//! not fit, implementing both the inherent `TarWriter` API and `ArchiveWriter`.

use std::io::{self, Read, Write};

use tar::{EntryType, Header};

use crate::error::{Error, Location, Result};
use crate::format::{ArchiveWriter, EntryKind, NewEntry};

const BLOCK: usize = 512;

fn io_err(source: io::Error) -> Error {
    Error::Io {
        source,
        loc: Location::new(),
    }
}

/// Writer for plain (uncompressed) tar archives. Outer compression, if any, is
/// applied by the caller on the underlying writer.
pub struct TarWriter<W> {
    writer: W,
    used_entries: u64,
    finished: bool,
}

impl<W: Write> TarWriter<W> {
    /// Wrap an output stream.
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            used_entries: 0,
            finished: false,
        }
    }

    /// Number of entries written so far.
    pub fn entries_written(&self) -> u64 {
        self.used_entries
    }

    /// Append one entry; `data` is read to the end for regular files.
    pub fn add(&mut self, entry: &NewEntry, data: &mut dyn Read) -> Result<()> {
        // Determine the exact size, buffering only when no hint was given.
        let (size, buffered) = if let Some(hint) = entry.size_hint {
            (hint, None)
        } else {
            let mut buf = Vec::new();
            data.read_to_end(&mut buf).map_err(io_err)?;
            (buf.len() as u64, Some(buf))
        };

        let kind = entry.kind;
        if matches!(kind, EntryKind::Other(_)) {
            return Err(Error::unsupported(
                "writing device, fifo and socket entries to tar",
            ));
        }

        let name = entry.path.as_bytes().to_vec();
        let mut pax_records: Vec<(String, Vec<u8>)> = Vec::new();

        if name.len() > 100 {
            pax_records.push(("path".to_owned(), name.clone()));
        }
        if !name.is_ascii() {
            pax_records.push(("path".to_owned(), name.clone()));
        }

        let mut truncated_name = name.clone();
        if truncated_name.len() > 100 {
            truncated_name.truncate(100);
        }

        let mut header = Header::new_gnu();

        let truncated_str = String::from_utf8_lossy(&truncated_name);
        header
            .set_path(truncated_str.as_ref())
            .map_err(|error| Error::Io {
                source: io::Error::other(error.to_string()),
                loc: Location::new(),
            })?;

        header.set_size(size);
        header.set_mode(
            entry
                .mode
                .unwrap_or(if kind == EntryKind::Dir { 0o755 } else { 0o644 }),
        );

        let seconds = entry
            .mtime_ns
            .map(|ns| ns.div_euclid(1_000_000_000) as u64)
            .unwrap_or(0);
        header.set_mtime(seconds);
        header.set_uid(0);
        header.set_gid(0);

        header.set_entry_type(match kind {
            EntryKind::File => EntryType::Regular,
            EntryKind::Dir => EntryType::Directory,
            EntryKind::Symlink => EntryType::Symlink,
            EntryKind::Hardlink => EntryType::Link,
            EntryKind::Other(_) => EntryType::Regular, // unreachable
        });

        if let Some(target) = &entry.link_target {
            if target.len() > 100 {
                pax_records.push(("linkpath".to_owned(), target.clone()));
                let t = &target[..100.min(target.len())];
                header.set_link_name_literal(t).map_err(|error| Error::Io {
                    source: io::Error::other(error.to_string()),
                    loc: Location::new(),
                })?;
            } else {
                header
                    .set_link_name_literal(target)
                    .map_err(|error| Error::Io {
                        source: io::Error::other(error.to_string()),
                        loc: Location::new(),
                    })?;
            }
        }

        if size > 8 * 1024 * 1024 * 1024 {
            pax_records.push(("size".to_owned(), size.to_string().into_bytes()));
        }

        if let Some(ns) = entry.mtime_ns {
            let subsecond = ns.rem_euclid(1_000_000_000);
            if subsecond != 0 {
                let seconds = ns.div_euclid(1_000_000_000);
                pax_records.push((
                    "mtime".to_owned(),
                    format!("{seconds}.{subsecond:09}").into_bytes(),
                ));
            }
        }

        if !pax_records.is_empty() {
            self.write_pax(&pax_records, &entry.path)?;
        }

        header.set_cksum();
        self.writer.write_all(header.as_bytes()).map_err(io_err)?;

        if kind == EntryKind::File {
            if let Some(buf) = buffered {
                self.writer.write_all(&buf).map_err(io_err)?;
            } else {
                let mut remaining = size;
                let mut buffer = vec![0u8; 128 * 1024];
                while remaining > 0 {
                    let want =
                        usize::try_from(remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
                    data.read_exact(&mut buffer[..want]).map_err(io_err)?;
                    self.writer.write_all(&buffer[..want]).map_err(io_err)?;
                    remaining = remaining.saturating_sub(want as u64);
                }
            }
        }

        let padding = (BLOCK as u64 - (size % BLOCK as u64)) % BLOCK as u64;
        if padding > 0 {
            let zeros = [0u8; BLOCK];
            self.writer
                .write_all(&zeros[..padding as usize])
                .map_err(io_err)?;
        }

        self.used_entries = self.used_entries.saturating_add(1);
        Ok(())
    }

    fn write_pax(&mut self, records: &[(String, Vec<u8>)], name: &str) -> Result<()> {
        let mut body: Vec<u8> = Vec::new();
        for (key, value) in records {
            let base = key.len() + value.len() + 3;
            let mut length = base + 1;
            loop {
                let digits = length.to_string().len();
                if base + digits == length {
                    break;
                }
                length = base + digits;
            }
            body.extend_from_slice(length.to_string().as_bytes());
            body.push(b' ');
            body.extend_from_slice(key.as_bytes());
            body.push(b'=');
            body.extend_from_slice(value);
            body.push(b'\n');
        }

        let mut header = Header::new_gnu();
        let pax_name = format!("PaxHeaders/{}", &name[..name.len().min(60)]);
        header
            .set_path(pax_name.as_str())
            .map_err(|error| Error::Io {
                source: io::Error::other(error.to_string()),
                loc: Location::new(),
            })?;
        header.set_size(body.len() as u64);
        header.set_mode(0o644);
        header.set_mtime(0);
        header.set_uid(0);
        header.set_gid(0);
        header.set_entry_type(EntryType::XHeader);
        header.set_cksum();

        self.writer.write_all(header.as_bytes()).map_err(io_err)?;
        self.writer.write_all(&body).map_err(io_err)?;

        let padding = (BLOCK as u64 - (body.len() as u64 % BLOCK as u64)) % BLOCK as u64;
        if padding > 0 {
            let zeros = [0u8; BLOCK];
            self.writer
                .write_all(&zeros[..padding as usize])
                .map_err(io_err)?;
        }
        Ok(())
    }

    /// Finish the archive, writing two zero blocks.
    pub fn finish(mut self) -> Result<()> {
        if !self.finished {
            let zeros = [0u8; BLOCK * 2];
            self.writer.write_all(&zeros).map_err(io_err)?;
            self.writer.flush().map_err(io_err)?;
            self.finished = true;
        }
        Ok(())
    }
}

impl<W: Write + Send> ArchiveWriter for TarWriter<W> {
    fn add(&mut self, entry: &NewEntry, data: &mut dyn Read) -> Result<()> {
        TarWriter::add(self, entry, data)
    }

    fn finish(self: Box<Self>) -> Result<()> {
        let writer = *self;
        writer.finish()
    }
}
