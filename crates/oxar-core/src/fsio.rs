//! Filesystem primitives: positional reads, seekable wrappers over generic
//! readers, the `Input` source plumbing, and atomic file creation.
//!
//! Archive files are never memory mapped; a truncated file under mmap raises
//! SIGBUS and kills the interpreter. All random access goes through `ReadAt`
//! with explicit buffers.
#![allow(missing_docs)]

use std::collections::hash_map::RandomState;
use std::fs::{File, OpenOptions};
use std::hash::{BuildHasher, Hash, Hasher};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{Error, Result};

/// Positional, shareable read access to a byte range.
pub trait ReadAt: Send + Sync {
    /// Read up to `buf.len()` bytes at `offset`, returning the count.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize>;

    /// Total length in bytes.
    fn len(&self) -> io::Result<u64>;

    /// Whether the source has zero length.
    fn is_empty(&self) -> io::Result<bool> {
        self.len().map(|len| len == 0)
    }

    /// Read exactly `buf.len()` bytes at `offset`.
    fn read_exact_at(&self, mut offset: u64, mut buf: &mut [u8]) -> io::Result<()> {
        while !buf.is_empty() {
            match self.read_at(offset, buf)? {
                0 => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "unexpected end of file",
                    ));
                }
                count => {
                    let (_, rest) = buf.split_at_mut(count);
                    buf = rest;
                    offset = offset.saturating_add(count as u64);
                }
            }
        }
        Ok(())
    }
}

impl ReadAt for File {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        #[cfg(unix)]
        {
            std::os::unix::fs::FileExt::read_at(self, buf, offset)
        }
        #[cfg(windows)]
        {
            std::os::windows::fs::FileExt::seek_read(self, buf, offset)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (offset, buf);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "positional reads are not implemented on this platform",
            ))
        }
    }

    fn len(&self) -> io::Result<u64> {
        Ok(self.metadata()?.len())
    }
}

impl ReadAt for Arc<[u8]> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let start = usize::try_from(offset).map_err(|_| {
            io::Error::new(io::ErrorKind::UnexpectedEof, "offset beyond memory source")
        })?;
        let total = self.as_ref().len();
        if start >= total {
            return Ok(0);
        }
        let available = &self.as_ref()[start..];
        let count = available.len().min(buf.len());
        let (target, _) = buf.split_at_mut(count);
        target.copy_from_slice(&available[..count]);
        Ok(count)
    }

    fn len(&self) -> io::Result<u64> {
        Ok(self.as_ref().len() as u64)
    }
}

/// Serialises positional access over any `Read + Seek` source, such as a
/// Python file object.
pub struct SharedSeekReader<R> {
    inner: Mutex<R>,
}

impl<R> SharedSeekReader<R> {
    /// Wrap a reader.
    pub fn new(inner: R) -> Self {
        Self {
            inner: Mutex::new(inner),
        }
    }

    /// Access the wrapped reader.
    pub fn with<T>(&self, f: impl FnOnce(&mut R) -> T) -> io::Result<T> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| io::Error::other("reader lock poisoned"))?;
        Ok(f(&mut guard))
    }
}

impl<R: Read + Seek + Send> ReadAt for SharedSeekReader<R> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        self.with(|reader| {
            reader.seek(SeekFrom::Start(offset))?;
            reader.read(buf)
        })?
    }

    fn len(&self) -> io::Result<u64> {
        self.with(|reader| {
            let end = reader.seek(SeekFrom::End(0))?;
            Ok(end)
        })?
    }
}

/// Seekable source with a known length, cheap to clone.
#[derive(Clone)]
pub struct RandomSource {
    inner: Arc<dyn ReadAt>,
    len: u64,
}

impl RandomSource {
    /// From an open file. The length is captured once.
    pub fn from_file(file: File) -> io::Result<Self> {
        let len = file.metadata()?.len();
        Ok(Self {
            inner: Arc::new(file),
            len,
        })
    }

    /// From a byte slice in memory.
    #[must_use]
    pub fn from_bytes(bytes: Arc<[u8]>) -> Self {
        let len = bytes.as_ref().len() as u64;
        Self {
            inner: Arc::new(bytes),
            len,
        }
    }

    /// From any shareable `ReadAt` implementation.
    #[must_use]
    pub fn from_read_at(inner: Arc<dyn ReadAt>, len: u64) -> Self {
        Self { inner, len }
    }

    /// Total length.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Whether the source is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Read up to `buf.len()` bytes at `offset`.
    pub fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read_at(offset, buf)
    }

    /// Read exactly `buf.len()` bytes at `offset`.
    pub fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        self.inner.read_exact_at(offset, buf)
    }

    /// Read exactly `buf.len()` bytes at `offset` relative to the end.
    pub fn read_exact_at_end(&self, back: u64, buf: &mut [u8]) -> io::Result<()> {
        let back = back.min(self.len);
        let offset = self.len.saturating_sub(back);
        self.inner.read_exact_at(offset, buf)
    }

    /// A `Read + Seek` view with its own position.
    #[must_use]
    pub fn reader(&self) -> PositionedReader {
        PositionedReader {
            source: self.clone(),
            position: 0,
        }
    }
}

/// `Read + Seek` view over a `RandomSource`.
pub struct PositionedReader {
    source: RandomSource,
    position: u64,
}

impl Read for PositionedReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let count = self.source.read_at(self.position, buf)?;
        self.position = self.position.saturating_add(count as u64);
        Ok(count)
    }
}

impl Seek for PositionedReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new = match pos {
            SeekFrom::Start(offset) => offset,
            SeekFrom::End(offset) => {
                if offset >= 0 {
                    self.source.len.saturating_add(offset as u64)
                } else {
                    self.source.len.saturating_sub(offset.unsigned_abs())
                }
            }
            SeekFrom::Current(offset) => {
                if offset >= 0 {
                    self.position.saturating_add(offset as u64)
                } else {
                    self.position.saturating_sub(offset.unsigned_abs())
                }
            }
        };
        self.position = new;
        Ok(new)
    }
}

/// Read side input: a path, a seekable source, or a one-pass stream.
pub enum Input {
    /// A path, opened on demand by the requested access mode.
    Path(PathBuf),
    /// A seekable source that may live in memory or in a Python object.
    Random(RandomSource),
    /// A stream that only supports sequential reads.
    Stream(Box<dyn Read + Send>),
}

impl Input {
    /// Whether random access is possible without opening.
    #[must_use]
    pub fn is_seekable(&self) -> bool {
        !matches!(self, Self::Stream(_))
    }

    /// Open a seekable view, if the input supports one.
    pub fn open_random(&self) -> Result<RandomSource> {
        match self {
            Self::Path(path) => {
                let file = File::open(path).map_err(map_open)?;
                Ok(RandomSource::from_file(file).map_err(map_open)?)
            }
            Self::Random(source) => Ok(source.clone()),
            Self::Stream(_) => Err(Error::unsupported(
                "random access reads from a non-seekable source",
            )),
        }
    }

    /// Convert into a sequential stream.
    pub fn open_stream(&self) -> Result<Box<dyn Read + Send>> {
        match self {
            Self::Path(path) => Ok(Box::new(File::open(path).map_err(map_open)?)),
            Self::Random(source) => Ok(Box::new(source.reader())),
            Self::Stream(_) => Err(Error::usage(
                "this source has already been consumed as a stream",
            )),
        }
    }

    /// Consume into a sequential stream.
    pub fn into_stream(self) -> Result<Box<dyn Read + Send>> {
        match self {
            Self::Path(path) => Ok(Box::new(File::open(path).map_err(map_open)?)),
            Self::Random(source) => Ok(Box::new(source.reader())),
            Self::Stream(stream) => Ok(stream),
        }
    }
}

fn map_open(error: io::Error) -> Error {
    Error::Io {
        source: error,
        loc: crate::error::Location::new(),
    }
}

/// A 16 hex digit token that is unpredictable within and across processes.
/// The seed comes from the standard library's OS entropy, so no extra
/// dependency is needed for temporary names.
#[must_use]
pub fn random_token() -> String {
    static STATE: OnceLock<RandomState> = OnceLock::new();
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let state = STATE.get_or_init(RandomState::new);
    let mut hasher = state.build_hasher();
    std::process::id().hash(&mut hasher);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    nanos.hash(&mut hasher);
    COUNTER
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        .hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

/// A file created beside its final name under an unpredictable part name and
/// renamed into place on commit. Dropping without commit removes the part
/// file, so a failed archive never leaves a partial file under the final
/// name.
pub struct AtomicFile {
    file: Option<File>,
    part: PathBuf,
    final_path: PathBuf,
    durable: bool,
    committed: bool,
}

impl AtomicFile {
    /// Create the part file next to `final_path`.
    pub fn create(final_path: &Path, durable: bool) -> io::Result<Self> {
        let file_name = final_path
            .file_name()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;
        let mut part_name = file_name.to_os_string();
        part_name.push(format!(".oxar-{}.part", random_token()));
        let part = final_path.with_file_name(part_name);
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&part)?;
        Ok(Self {
            file: Some(file),
            part,
            final_path: final_path.to_path_buf(),
            durable,
            committed: false,
        })
    }

    /// Path of the part file.
    #[must_use]
    pub fn part_path(&self) -> &Path {
        &self.part
    }

    /// Flush (and fsync when durable), then rename over the final name.
    pub fn commit(mut self) -> io::Result<()> {
        if let Some(file) = self.file.take() {
            file.sync_all()?;
            drop(file);
        }
        std::fs::rename(&self.part, &self.final_path)?;
        self.committed = true;
        if self.durable
            && let Some(parent) = self.final_path.parent()
            && let Ok(dir) = File::open(parent)
        {
            let _ = dir.sync_all();
        }
        Ok(())
    }
}

impl Write for AtomicFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match &mut self.file {
            Some(file) => file.write(buf),
            None => Err(io::Error::other("atomic file already committed")),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match &mut self.file {
            Some(file) => file.flush(),
            None => Ok(()),
        }
    }
}

impl Drop for AtomicFile {
    fn drop(&mut self) {
        if !self.committed {
            self.file.take();
            let _ = std::fs::remove_file(&self.part);
        }
    }
}

/// Read at most `max` bytes from a reader, reporting whether more remain.
pub fn read_prefix<R: Read>(reader: &mut R, max: usize) -> io::Result<(Vec<u8>, bool)> {
    let mut buffer = vec![0u8; max];
    let mut filled = 0usize;
    while filled < max {
        let (_, tail) = buffer.split_at_mut(filled);
        match reader.read(tail) {
            Ok(0) => return Ok((buffer[..filled].to_vec(), false)),
            Ok(count) => filled = filled.saturating_add(count),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    let mut probe = [0u8; 1];
    loop {
        match reader.read(&mut probe) {
            Ok(0) => return Ok((buffer, false)),
            Ok(_) => return Ok((buffer, true)),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn positional_reads_match_slice_reads() {
        let bytes: Arc<[u8]> = Arc::from((0u8..=255).collect::<Vec<u8>>());
        let source = RandomSource::from_bytes(bytes);
        let mut buffer = [0u8; 10];
        source.read_exact_at(200, &mut buffer).unwrap();
        assert_eq!(buffer, [200, 201, 202, 203, 204, 205, 206, 207, 208, 209]);
        source.read_exact_at_end(3, &mut buffer[..3]).unwrap();
        assert_eq!(&buffer[..3], &[253, 254, 255]);
        assert!(source.read_exact_at(256, &mut buffer).is_err());
    }

    #[test]
    fn positioned_reader_seeks() {
        let bytes: Arc<[u8]> = Arc::from(b"0123456789".to_vec());
        let source = RandomSource::from_bytes(bytes);
        let mut reader = source.reader();
        let mut buffer = [0u8; 3];
        reader.read_exact(&mut buffer).unwrap();
        assert_eq!(&buffer, b"012");
        reader.seek(SeekFrom::Start(8)).unwrap();
        reader.read_exact(&mut buffer[..2]).unwrap();
        assert_eq!(&buffer[..2], b"89");
        reader.seek(SeekFrom::End(-2)).unwrap();
        reader.read_exact(&mut buffer[..2]).unwrap();
        assert_eq!(&buffer[..2], b"89");
    }

    #[test]
    fn atomic_file_renames_on_commit_and_removes_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        let final_path = dir.path().join("out.bin");
        {
            let mut file = AtomicFile::create(&final_path, false).unwrap();
            file.write_all(b"hello").unwrap();
            file.commit().unwrap();
        }
        assert_eq!(std::fs::read(&final_path).unwrap(), b"hello");
        let other = dir.path().join("other.bin");
        {
            let mut file = AtomicFile::create(&other, false).unwrap();
            file.write_all(b"partial").unwrap();
        }
        assert!(!other.exists());
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().contains(".oxar-"))
            .collect();
        assert!(leftovers.is_empty());
    }

    #[test]
    fn random_tokens_differ() {
        let a = random_token();
        let b = random_token();
        assert_ne!(a, b);
        assert_eq!(a.len(), 16);
    }
}
