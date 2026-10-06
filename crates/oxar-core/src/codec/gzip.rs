//! gzip wrapper around flate2 (zlib-rs backend).

use std::io::{self, Read, Write};

use flate2::Compression as FlateLevel;
use flate2::bufread::MultiGzDecoder;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;

use super::{FinishWrite, reserve_estimate};
use crate::error::{Error, Location, Result};
use crate::policy::Limits;

/// gzip compress `data` at `level` (0 to 9).
pub fn compress(data: &[u8], level: i32, threads: u32) -> Result<Vec<u8>> {
    let _ = threads; // gzip compress is single-threaded in flate2
    let reservation = data.len().min(1024 * 1024);
    let mut encoder = GzEncoder::new(
        Vec::with_capacity(reservation),
        FlateLevel::new(level as u32),
    );
    encoder.write_all(data).map_err(io_error)?;
    encoder.finish().map_err(io_error)
}

/// gzip decompress `data`, decoding concatenated members and enforcing the
/// entry size cap.
pub fn decompress(data: &[u8], limits: &Limits, max_size: Option<u64>) -> Result<Vec<u8>> {
    let cap = max_size.or(limits.max_entry_size).unwrap_or(u64::MAX);
    let mut decoder = MultiGzDecoder::new(data);
    let reservation = data
        .len()
        .saturating_mul(2)
        .min(usize::try_from(cap.min(8 << 20)).unwrap_or(8 << 20));
    let mut output = Vec::with_capacity(reservation);
    let mut buffer = [0u8; 64 * 1024];
    let mut written = 0u64;
    loop {
        let count = decoder.read(&mut buffer).map_err(|e| Error::Io {
            source: e,
            loc: Location::new(),
        })?;
        if count == 0 {
            break;
        }
        let next_written = written.saturating_add(count as u64);
        if next_written > cap {
            return Err(Error::Bomb {
                limit: "max_entry_size",
                limit_value: cap,
                observed: next_written,
                loc: Location::new(),
            });
        }
        output.extend_from_slice(&buffer[..count]);
        written = next_written;
    }
    let _ = reserve_estimate;
    Ok(output)
}

/// Streaming gzip encoder that writes a gzip frame to an inner writer.
pub struct GzipEncoder<W: Write> {
    inner: GzEncoder<W>,
}

impl<W: Write + Send> GzipEncoder<W> {
    /// Create an encoder writing a gzip frame to `writer` at `level`.
    pub fn new(writer: W, level: i32) -> Result<Self> {
        Ok(Self {
            inner: GzEncoder::new(writer, FlateLevel::new(level as u32)),
        })
    }
}

impl<W: Write + Send + 'static> FinishWrite for GzipEncoder<W> {
    fn finish_box(self: Box<Self>) -> Result<()> {
        let value = *self;
        value.inner.finish().map_err(io_error)?;
        Ok(())
    }
}

impl<W: Write + Send> Write for GzipEncoder<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Streaming gzip decoder that reads a gzip frame from an inner reader.
pub struct GzipDecoder<R: Read> {
    inner: GzDecoder<R>,
}

impl<R: Read + Send> GzipDecoder<R> {
    /// Create a decoder reading a gzip frame from `reader`.
    pub fn new(reader: R) -> Self {
        Self {
            inner: GzDecoder::new(reader),
        }
    }
}

impl<R: Read + Send> Read for GzipDecoder<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

fn io_error(source: io::Error) -> Error {
    Error::Io {
        source,
        loc: Location::new(),
    }
}
