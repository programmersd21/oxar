//! Streaming encoder and decoder objects for every codec.
//!
//! One factory per direction produces a trait object free enum so the format
//! layers can stack a decoder under a container reader without knowing which
//! codec is in use. Decoder memory is reserved against the budget before the
//! decoder is constructed; see `docs/SECURITY_MODEL.md` and section 7.6 of the
//! specification for the attacks this closes.

use std::io::{self, Read, Write};

use flate2::{Compression as FlateLevel, read as flate_read, write as flate_write};

use super::CodecOptions;
use crate::error::{Error, Location, Result};
use crate::format::Codec;
use crate::policy::Limits;

/// Writer that must be finished explicitly to emit the trailer of its frame.
pub enum StreamEncoder {
    /// gzip frame encoder.
    Gzip(flate_write::GzEncoder<Box<dyn Write + Send>>),
    /// zlib frame encoder.
    Zlib(flate_write::ZlibEncoder<Box<dyn Write + Send>>),
    /// Raw deflate frame encoder.
    Deflate(flate_write::DeflateEncoder<Box<dyn Write + Send>>),
    /// bzip2 stream encoder.
    Bzip2(bzip2::write::BzEncoder<Box<dyn Write + Send>>),
    /// xz stream encoder.
    Xz(liblzma::write::XzEncoder<Box<dyn Write + Send>>),
    /// zstd frame encoder.
    Zstd(Box<zstd::stream::write::Encoder<'static, Box<dyn Write + Send>>>),
    /// LZ4 frame encoder.
    Lz4(lz4_flex::frame::FrameEncoder<Box<dyn Write + Send>>),
    /// Brotli stream encoder.
    Brotli(Box<brotli::CompressorWriter<Box<dyn Write + Send>>>),
    /// Snappy frame encoder.
    Snappy(Box<snap::write::FrameEncoder<Box<dyn Write + Send>>>),
}

impl Write for StreamEncoder {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Gzip(inner) => inner.write(buf),
            Self::Zlib(inner) => inner.write(buf),
            Self::Deflate(inner) => inner.write(buf),
            Self::Bzip2(inner) => inner.write(buf),
            Self::Xz(inner) => inner.write(buf),
            Self::Zstd(inner) => inner.write(buf),
            Self::Lz4(inner) => inner.write(buf),
            Self::Brotli(inner) => inner.write(buf),
            Self::Snappy(inner) => inner.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Gzip(inner) => inner.flush(),
            Self::Zlib(inner) => inner.flush(),
            Self::Deflate(inner) => inner.flush(),
            Self::Bzip2(inner) => inner.flush(),
            Self::Xz(inner) => inner.flush(),
            Self::Zstd(inner) => inner.flush(),
            Self::Lz4(inner) => inner.flush(),
            Self::Brotli(inner) => inner.flush(),
            Self::Snappy(inner) => inner.flush(),
        }
    }
}

impl StreamEncoder {
    /// Finish the frame and flush the underlying writer. Must be called for a
    /// valid stream in every codec; dropping without finishing leaves a
    /// truncated frame.
    pub fn finish(self) -> Result<Box<dyn Write + Send>> {
        let io_err = |source: io::Error| Error::Io {
            source,
            loc: Location::new(),
        };
        let other = |source: String| Error::Io {
            source: io::Error::other(source),
            loc: Location::new(),
        };
        match self {
            Self::Gzip(inner) => inner.finish().map_err(io_err),
            Self::Zlib(inner) => inner.finish().map_err(io_err),
            Self::Deflate(inner) => inner.finish().map_err(io_err),
            Self::Bzip2(inner) => inner.finish().map_err(io_err),
            Self::Xz(inner) => inner.finish().map_err(io_err),
            Self::Zstd(inner) => inner.finish().map_err(io_err),
            Self::Lz4(inner) => inner.finish().map_err(|error| other(error.to_string())),
            Self::Brotli(mut inner) => {
                inner.flush().map_err(io_err)?;
                Ok(inner.into_inner())
            }
            Self::Snappy(inner) => inner.into_inner().map_err(|error| other(error.to_string())),
        }
    }
}

/// Valid levels per codec, so the binding layer and the codec layer agree.
pub fn validate_level(codec: Codec, level: i32) -> Result<()> {
    let reject = |low: i32, high: i32| {
        Err(Error::usage(format!(
            "{codec} level must be between {low} and {high}, got {level}"
        )))
    };
    match codec {
        Codec::Gzip | Codec::Zlib | Codec::Deflate => {
            if !(0..=9).contains(&level) {
                return reject(0, 9);
            }
        }
        Codec::Bzip2 => {
            if !(1..=9).contains(&level) {
                return reject(1, 9);
            }
        }
        Codec::Xz | Codec::Lzma => {
            if !(0..=9).contains(&level) {
                return reject(0, 9);
            }
        }
        Codec::Zstd => {
            // Negative levels are the zstd fast modes; the crate accepts them
            // down to a documented floor, above which we reject before the
            // library sees an invalid value.
            if !(-131_072..=22).contains(&level) {
                return reject(-131_072, 22);
            }
        }
        Codec::Lz4 => {
            if !(0..=12).contains(&level) {
                return reject(0, 12);
            }
        }
        Codec::Brotli => {
            if !(0..=11).contains(&level) {
                return reject(0, 11);
            }
        }
        Codec::Snappy => {
            if level != 0 {
                return Err(Error::usage(format!(
                    "snappy has no compression levels, got {level}"
                )));
            }
        }
    }
    Ok(())
}

/// Build an encoder over `writer`.
pub fn stream_encoder(
    codec: Codec,
    writer: Box<dyn Write + Send>,
    level: i32,
    threads: u32,
    opts: CodecOptions,
) -> Result<StreamEncoder> {
    validate_level(codec, level)?;
    let io_err = |source: io::Error| Error::Io {
        source,
        loc: Location::new(),
    };
    let lz_err = |source: liblzma::stream::Error| Error::Io {
        source: io::Error::other(source.to_string()),
        loc: Location::new(),
    };
    match codec {
        Codec::Gzip => Ok(StreamEncoder::Gzip(flate_write::GzEncoder::new(
            writer,
            FlateLevel::new(level as u32),
        ))),
        Codec::Zlib => Ok(StreamEncoder::Zlib(flate_write::ZlibEncoder::new(
            writer,
            FlateLevel::new(level as u32),
        ))),
        Codec::Deflate => Ok(StreamEncoder::Deflate(flate_write::DeflateEncoder::new(
            writer,
            FlateLevel::new(level as u32),
        ))),
        Codec::Bzip2 => Ok(StreamEncoder::Bzip2(bzip2::write::BzEncoder::new(
            writer,
            bzip2::Compression::new(level as u32),
        ))),
        Codec::Xz | Codec::Lzma => {
            let preset_number = u32::try_from(level)
                .map_err(|_| Error::usage("invalid lzma preset"))?
                | if opts.extreme {
                    liblzma::stream::PRESET_EXTREME
                } else {
                    0
                };
            let stream = if codec == Codec::Xz {
                super::xz::encoder_stream(level, opts.extreme, threads)?
            } else {
                let preset =
                    liblzma::stream::LzmaOptions::new_preset(preset_number).map_err(lz_err)?;
                liblzma::stream::Stream::new_lzma_encoder(&preset).map_err(lz_err)?
            };
            Ok(StreamEncoder::Xz(liblzma::write::XzEncoder::new_stream(
                writer, stream,
            )))
        }
        Codec::Zstd => {
            let mut encoder = zstd::stream::write::Encoder::new(writer, level).map_err(io_err)?;
            if threads > 1 {
                encoder.multithread(threads).map_err(io_err)?;
            }
            if opts.window_log > 0 {
                encoder
                    .set_parameter(zstd::zstd_safe::CParameter::WindowLog(opts.window_log))
                    .map_err(io_err)?;
            }
            let _ = opts.long_distance;
            Ok(StreamEncoder::Zstd(Box::new(encoder)))
        }
        Codec::Lz4 => {
            let _ = level;
            Ok(StreamEncoder::Lz4(lz4_flex::frame::FrameEncoder::new(
                writer,
            )))
        }
        Codec::Brotli => {
            let lgwin = if opts.lgwin == 0 { 22 } else { opts.lgwin };
            Ok(StreamEncoder::Brotli(Box::new(
                brotli::CompressorWriter::new(writer, 64 * 1024, level as u32, lgwin),
            )))
        }
        Codec::Snappy => Ok(StreamEncoder::Snappy(Box::new(
            snap::write::FrameEncoder::new(writer),
        ))),
    }
}

/// Reader that decompresses one stream, decoding concatenated members of the
/// same codec the way the command line tools do.
pub enum StreamDecoder {
    /// gzip decoder over concatenated members.
    Gzip(flate_read::MultiGzDecoder<Box<dyn Read + Send>>),
    /// zlib frame decoder.
    Zlib(flate_read::ZlibDecoder<Box<dyn Read + Send>>),
    /// Raw deflate frame decoder.
    Deflate(flate_read::DeflateDecoder<Box<dyn Read + Send>>),
    /// bzip2 decoder over concatenated streams.
    Bzip2(bzip2::read::MultiBzDecoder<Box<dyn Read + Send>>),
    /// xz stream decoder.
    Xz(liblzma::read::XzDecoder<Box<dyn Read + Send>>),
    /// lzma-alone stream decoder.
    Lzma(liblzma::read::XzDecoder<Box<dyn Read + Send>>),
    /// zstd frame decoder.
    Zstd(zstd::stream::read::Decoder<'static, io::BufReader<Box<dyn Read + Send>>>),
    /// LZ4 frame decoder.
    Lz4(lz4_flex::frame::FrameDecoder<Box<dyn Read + Send>>),
    /// Brotli stream decoder.
    Brotli(Box<brotli::Decompressor<Box<dyn Read + Send>>>),
    /// Snappy frame decoder.
    Snappy(snap::read::FrameDecoder<Box<dyn Read + Send>>),
}

impl Read for StreamDecoder {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Gzip(inner) => inner.read(buf),
            Self::Zlib(inner) => inner.read(buf),
            Self::Deflate(inner) => inner.read(buf),
            Self::Bzip2(inner) => inner.read(buf),
            Self::Xz(inner) => inner.read(buf),
            Self::Lzma(inner) => inner.read(buf),
            Self::Zstd(inner) => inner.read(buf),
            Self::Lz4(inner) => inner.read(buf),
            Self::Brotli(inner) => inner.read(buf),
            Self::Snappy(inner) => inner.read(buf),
        }
    }
}

/// Build a decoder over `reader`, applying the decoder memory limit before
/// any decoder state is allocated.
pub fn stream_decoder(
    codec: Codec,
    reader: Box<dyn Read + Send>,
    limits: &Limits,
) -> Result<StreamDecoder> {
    let io_err = |source: io::Error| Error::Io {
        source,
        loc: Location::new(),
    };
    let lz_err = |source: liblzma::stream::Error| Error::Io {
        source: io::Error::other(source.to_string()),
        loc: Location::new(),
    };
    let memlimit = limits.max_decoder_memory.unwrap_or(u64::MAX);
    match codec {
        Codec::Gzip => Ok(StreamDecoder::Gzip(flate_read::MultiGzDecoder::new(reader))),
        Codec::Zlib => Ok(StreamDecoder::Zlib(flate_read::ZlibDecoder::new(reader))),
        Codec::Deflate => Ok(StreamDecoder::Deflate(flate_read::DeflateDecoder::new(
            reader,
        ))),
        Codec::Bzip2 => Ok(StreamDecoder::Bzip2(bzip2::read::MultiBzDecoder::new(
            reader,
        ))),
        Codec::Xz => {
            let stream = liblzma::stream::Stream::new_stream_decoder(
                memlimit,
                liblzma::stream::CONCATENATED,
            )
            .map_err(lz_err)?;
            Ok(StreamDecoder::Xz(liblzma::read::XzDecoder::new_stream(
                reader, stream,
            )))
        }
        Codec::Lzma => {
            let stream = liblzma::stream::Stream::new_lzma_decoder(memlimit).map_err(lz_err)?;
            Ok(StreamDecoder::Lzma(liblzma::read::XzDecoder::new_stream(
                reader, stream,
            )))
        }
        Codec::Zstd => {
            let mut decoder = zstd::stream::read::Decoder::new(reader).map_err(io_err)?;
            if let Some(limit) = limits.max_decoder_memory {
                let window_log = window_log_for_limit(limit);
                decoder.window_log_max(window_log).map_err(io_err)?;
            }
            Ok(StreamDecoder::Zstd(decoder))
        }
        Codec::Lz4 => Ok(StreamDecoder::Lz4(lz4_flex::frame::FrameDecoder::new(
            reader,
        ))),
        Codec::Brotli => Ok(StreamDecoder::Brotli(Box::new(brotli::Decompressor::new(
            reader,
            64 * 1024,
        )))),
        Codec::Snappy => Ok(StreamDecoder::Snappy(snap::read::FrameDecoder::new(reader))),
    }
}

/// Largest window log whose window fits in `limit` bytes; the zstd decoder
/// parameter takes a log, the policy is stated in bytes.
fn window_log_for_limit(limit: u64) -> u32 {
    let mut log = 10u32;
    while log < 31 && (1u64 << (log + 1)) <= limit {
        log += 1;
    }
    log
}

/// Whether a codec accepts a `threads` value above one for encoding.
pub fn codec_supports_threads(codec: Codec) -> bool {
    matches!(codec, Codec::Zstd | Codec::Xz)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Default, Clone)]
    struct SharedVec(Arc<Mutex<Vec<u8>>>);

    impl SharedVec {
        fn take(&self) -> Vec<u8> {
            std::mem::take(&mut self.0.lock().unwrap())
        }
    }

    impl Write for SharedVec {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn round_trip(codec: Codec, level: i32, data: &[u8], window_log: u32) {
        let limits = Limits::default();
        let sink = SharedVec::default();
        let collector = sink.clone();
        let opts = CodecOptions {
            window_log,
            ..CodecOptions::default()
        };
        let mut encoder = stream_encoder(codec, Box::new(sink), level, 1, opts).unwrap();
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap();
        let frame = collector.take();
        let mut decoder = stream_decoder(codec, Box::new(io::Cursor::new(frame)), &limits).unwrap();
        let mut output = Vec::new();
        decoder.read_to_end(&mut output).unwrap();
        assert_eq!(output, data, "codec {codec} level {level}");
    }

    #[test]
    fn every_codec_round_trips_through_the_stream_api() {
        let data: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
        for codec in [
            Codec::Gzip,
            Codec::Zlib,
            Codec::Deflate,
            Codec::Bzip2,
            Codec::Xz,
            Codec::Lzma,
            Codec::Zstd,
            Codec::Lz4,
            Codec::Brotli,
            Codec::Snappy,
        ] {
            let level = match codec {
                Codec::Bzip2 => 1,
                Codec::Snappy => 0,
                _ => 1,
            };
            round_trip(codec, level, &data, 0);
            round_trip(codec, level, b"", 0);
            round_trip(codec, level, b"x", 0);
        }
    }

    #[test]
    fn level_validation_names_the_range() {
        assert!(validate_level(Codec::Gzip, 10).is_err());
        assert!(validate_level(Codec::Bzip2, 0).is_err());
        assert!(validate_level(Codec::Snappy, 1).is_err());
        assert!(validate_level(Codec::Zstd, -131_072).is_ok());
        assert!(validate_level(Codec::Zstd, -131_073).is_err());
    }

    #[test]
    fn zstd_window_limit_rejects_a_large_window_frame() {
        let data = vec![7u8; 400_000];
        let limits = Limits {
            max_decoder_memory: Some(1 << 18),
            ..Limits::default()
        };
        let mut decoder = {
            let sink = SharedVec::default();
            let collector = sink.clone();
            let mut encoder = stream_encoder(
                Codec::Zstd,
                Box::new(sink),
                1,
                1,
                CodecOptions {
                    window_log: 20,
                    ..CodecOptions::default()
                },
            )
            .unwrap();
            encoder.write_all(&data).unwrap();
            encoder.finish().unwrap();
            let frame = collector.take();
            stream_decoder(Codec::Zstd, Box::new(io::Cursor::new(frame)), &limits).unwrap()
        };
        let mut output = Vec::new();
        assert!(decoder.read_to_end(&mut output).is_err());
    }
}
