//! Raw stream codecs. Each submodule wraps one third party codec and adds the
//! policy limits that the container layers need.

/// Brotli codec wrapper.
pub mod brotli;
/// bzip2 codec wrapper.
pub mod bzip2;
/// Raw deflate codec wrapper.
pub mod deflate;
/// gzip codec wrapper.
pub mod gzip;
/// LZ4 frame codec wrapper.
pub mod lz4;
/// LZMA / lzma-alone codec wrapper.
pub mod lzma;
/// Snappy frame codec wrapper.
pub mod snappy;
/// xz codec wrapper.
pub mod xz;
/// zlib codec wrapper.
pub mod zlib;
/// zstd codec wrapper.
pub mod zstd;

use std::io::Write;

use crate::error::{Error, Result};
use crate::policy::Limits;

/// Options parsed from the Python API keyword for a codec.
#[derive(Debug, Clone, Copy, Default)]
pub struct CodecOptions {
    /// Use the codec's slowest, strongest mode when supported.
    pub extreme: bool,
    /// Brotli window size, in bits.
    pub lgwin: u32,
    /// zstd window log, in bits.
    pub window_log: u32,
    /// Enable the zstd long distance matcher.
    pub long_distance: bool,
    /// Enable per-frame checksums where the codec supports it.
    pub checksum: bool,
}

/// Options applied to every encoder.
#[derive(Debug, Clone, Copy)]
pub struct EncoderOptions {
    /// Compression level in the codec-specific range.
    pub level: i32,
    /// Worker threads to use when the codec supports multithreading.
    pub threads: u32,
    /// Codec-specific extra options.
    pub extra: CodecOptions,
}

impl Default for EncoderOptions {
    fn default() -> Self {
        Self {
            level: 6,
            threads: 1,
            extra: CodecOptions {
                lgwin: 22,
                window_log: 22,
                checksum: true,
                ..CodecOptions::default()
            },
        }
    }
}

/// Block oriented writer trait used by the format layers.
pub trait FinishWrite: Write + Send {
    /// Finish the frame and flush the underlying writer.
    fn finish_box(self: Box<Self>) -> Result<()>;
}

/// Produce bytes in memory.
pub fn compress_into<W>(writer: &mut W, data: &[u8]) -> Result<()>
where
    W: Write,
{
    writer.write_all(data).map_err(|e| Error::Io {
        source: e,
        loc: crate::error::Location::new(),
    })?;
    Ok(())
}

/// Copy a slice between distinct byte containers.
pub fn copy_between(src: &[u8], dst: &mut [u8]) -> usize {
    let count = src.len().min(dst.len());
    dst[..count].copy_from_slice(&src[..count]);
    count
}

/// Validate a level for gzip, zlib and deflate.
pub fn validate_gzip_level(level: i32) -> Result<i32> {
    if !(0..=9).contains(&level) {
        return Err(Error::usage(format!(
            "zlib level must be between 0 and 9, got {level}"
        )));
    }
    Ok(level)
}

/// Validate a level for bzip2 (1 to 9).
pub fn validate_bzip2_level(level: i32) -> Result<i32> {
    if !(1..=9).contains(&level) {
        return Err(Error::usage(format!(
            "bzip2 level must be between 1 and 9, got {level}"
        )));
    }
    Ok(level)
}

/// Validate a level for brotli (0 to 11).
pub fn validate_brotli_level(level: i32) -> Result<i32> {
    if !(0..=11).contains(&level) {
        return Err(Error::usage(format!(
            "brotli level must be between 0 and 11, got {level}"
        )));
    }
    Ok(level)
}

/// Conservative memory estimate for decoders, used for budget reservations.
pub fn reserve_estimate(codec: &str, limits: &Limits) -> u64 {
    match codec {
        "zstd" => 1u64 << 29,
        "xz" | "lzma" => limits.max_decoder_memory.unwrap_or(512 << 20),
        "brotli" => 32 << 20,
        "lz4" => 4 << 20,
        _ => 512 << 10,
    }
}

/// One-shot compress dispatch by codec. Levels are interpreted per codec.
pub fn compress(
    codec: crate::format::Codec,
    data: &[u8],
    level: i32,
    threads: u32,
    opts: CodecOptions,
) -> crate::error::Result<Vec<u8>> {
    use crate::format::Codec;
    match codec {
        Codec::Gzip => gzip::compress(data, level, threads),
        Codec::Zlib => Ok(zlib::compress(data, level)),
        Codec::Deflate => Ok(deflate::compress(data, level)),
        Codec::Bzip2 => Ok(bzip2::compress(data, level)),
        Codec::Xz => xz::compress(data, level, opts.extreme, threads),
        Codec::Lzma => lzma::compress(data, level, opts.extreme, threads),
        Codec::Zstd => zstd::compress(data, level, threads, opts.window_log, opts.long_distance),
        Codec::Lz4 => lz4::compress(data, level),
        Codec::Brotli => {
            brotli::compress(data, level, if opts.lgwin > 0 { opts.lgwin } else { 22 })
        }
        Codec::Snappy => snappy::compress(data),
    }
}

/// One-shot decompress dispatch by codec. `max_size` bounds output.
pub fn decompress(
    codec: crate::format::Codec,
    data: &[u8],
    limits: &Limits,
    max_size: Option<u64>,
) -> crate::error::Result<Vec<u8>> {
    use crate::format::Codec;
    match codec {
        Codec::Gzip => gzip::decompress(data, limits, max_size),
        Codec::Zlib => zlib::decompress(data, limits, max_size),
        Codec::Deflate => deflate::decompress(data, limits, max_size),
        Codec::Bzip2 => bzip2::decompress(data, limits, max_size),
        Codec::Xz => xz::decompress(data, limits, max_size),
        Codec::Lzma => lzma::decompress(data, limits, max_size),
        Codec::Zstd => zstd::decompress(data, limits, max_size),
        Codec::Lz4 => lz4::decompress(data, limits, max_size),
        Codec::Brotli => brotli::decompress(data, limits, max_size),
        Codec::Snappy => snappy::decompress(data, limits, max_size),
    }
}
