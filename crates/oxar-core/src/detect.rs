//! Content based format and codec detection. Inspects at most the first 64 KiB
//! plus, for seekable sources, the final 66 KiB for zip End of Central
//! Directory records. File names are never the deciding signal.

use std::io::Read;

use crate::error::{Error, Result};
use crate::format::Codec;
use crate::format::{Compression, Format};
use crate::fsio::Input;

const PREFIX_LIMIT: usize = 64 * 1024;
const SUFFIX_LIMIT: usize = 66 * 1024;

/// Detection confidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    /// A magic number matched directly.
    Magic,
    /// Structure was recovered only after decoding a candidate outer stream.
    Structure,
    /// Nothing was recognised from the bytes; a name hint would be needed.
    Extension,
}

/// Result of running `detect`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detection {
    /// Container format, when recognised.
    pub format: Option<Format>,
    /// Outer compression, for tar.
    pub compression: Option<Compression>,
    /// Raw codec, when the source is a bare stream.
    pub codec: Option<Codec>,
    /// How the result was reached.
    pub confidence: Confidence,
}

/// Run detection against a seekable or stream source.
pub fn detect(input: &Input, _policy: &crate::policy::Policy) -> Result<Detection> {
    // Read the prefix bytes.
    let mut prefix = vec![0u8; PREFIX_LIMIT];
    let mut prefix_len = 0usize;
    let mut reader = input.open_stream()?;
    // read up to limit
    while prefix_len < PREFIX_LIMIT {
        match reader.read(&mut prefix[prefix_len..]) {
            Ok(0) => break,
            Ok(count) => prefix_len += count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(Error::Io {
                    source: error,
                    loc: crate::error::Location::new(),
                });
            }
        }
    }
    prefix.truncate(prefix_len);

    let suffix = if input.is_seekable() {
        // read tail
        if let Ok(random) = input.open_random() {
            let len = random.len();
            if len > 0 {
                let amount = SUFFIX_LIMIT.min(len as usize);
                let mut tail = vec![0u8; amount];
                match random.read_exact_at(len.saturating_sub(amount as u64), &mut tail) {
                    Ok(()) => Some(tail),
                    Err(_) => None,
                }
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };

    Ok(detect_bytes(&prefix, suffix.as_deref()))
}

/// Detection from already loaded byte slices.
pub fn detect_bytes(prefix: &[u8], suffix: Option<&[u8]>) -> Detection {
    let mut detection = Detection {
        format: None,
        compression: None,
        codec: None,
        confidence: Confidence::Extension,
    };

    // 7z
    if prefix.starts_with(b"7z\xBC\xAF\x27\x1C") {
        detection.format = Some(Format::SevenZ);
        detection.confidence = Confidence::Magic;
        return detection;
    }

    // snappy framed
    if prefix.starts_with(b"\xFF\x06\x00\x00sNaPpY") {
        detection.codec = Some(Codec::Snappy);
        detection.confidence = Confidence::Magic;
        return detection;
    }

    // lz4 frame
    if prefix.starts_with(&[0x04, 0x22, 0x4D, 0x18]) {
        detection.codec = Some(Codec::Lz4);
        detection.compression = Some(Compression::Lz4);
        if is_compressed_tar(prefix, Compression::Lz4) {
            detection.format = Some(Format::Tar);
            detection.confidence = Confidence::Structure;
        } else {
            detection.confidence = Confidence::Magic;
        }
        return detection;
    }

    // zstd
    if prefix.len() >= 4
        && (prefix[0] == 0x28 && prefix[1] == 0xB5 && prefix[2] == 0x2F && prefix[3] == 0xFD)
    {
        detection.codec = Some(Codec::Zstd);
        detection.compression = Some(Compression::Zstd);
        if is_compressed_tar(prefix, Compression::Zstd) {
            detection.format = Some(Format::Tar);
            detection.confidence = Confidence::Structure;
        } else {
            detection.confidence = Confidence::Magic;
        }
        return detection;
    }
    // skipable frame
    if prefix.len() >= 8
        && prefix[0] == 0x50
        && prefix[1] == 0x2A
        && prefix[2] == 0x4D
        && prefix[3] == 0x18
    {
        detection.codec = Some(Codec::Zstd);
        detection.compression = Some(Compression::Zstd);
        detection.confidence = Confidence::Magic;
        return detection;
    }

    // xz
    if prefix.starts_with(&[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]) {
        detection.codec = Some(Codec::Xz);
        detection.compression = Some(Compression::Xz);
        if is_compressed_tar(prefix, Compression::Xz) {
            detection.format = Some(Format::Tar);
            detection.confidence = Confidence::Structure;
        } else {
            detection.confidence = Confidence::Magic;
        }
        return detection;
    }

    // bzip2
    if prefix.starts_with(b"BZh") {
        detection.codec = Some(Codec::Bzip2);
        detection.compression = Some(Compression::Bzip2);
        if is_compressed_tar(prefix, Compression::Bzip2) {
            detection.format = Some(Format::Tar);
            detection.confidence = Confidence::Structure;
        } else {
            detection.confidence = Confidence::Magic;
        }
        return detection;
    }

    // gzip
    if prefix.len() >= 2 && prefix[0] == 0x1F && prefix[1] == 0x8B {
        detection.codec = Some(Codec::Gzip);
        detection.compression = Some(Compression::Gzip);
        if is_compressed_tar(prefix, Compression::Gzip) {
            detection.format = Some(Format::Tar);
            detection.confidence = Confidence::Structure;
        } else {
            detection.confidence = Confidence::Magic;
        }
        return detection;
    }

    // zip: direct magic
    if prefix.starts_with(b"PK\x03\x04")
        || prefix.starts_with(b"PK\x05\x06")
        || prefix.starts_with(b"PK\x07\x08")
    {
        detection.format = Some(Format::Zip);
        detection.confidence = Confidence::Magic;
        return detection;
    }
    // self extracting prefix: scan suffix for last EOCD
    if let Some(suffix) = suffix
        && suffix.windows(4).any(|w| w == b"PK\x05\x06")
    {
        detection.format = Some(Format::Zip);
        detection.confidence = Confidence::Magic;
        return detection;
    }

    // tar: ustar magic at offset 257 or valid checksum in the first block
    if prefix.len() >= 512 {
        // ustar at offset 257
        if prefix.len() >= 257 + 5 {
            let magic = &prefix[257..262];
            if magic == b"ustar" || magic == b"ustar\x00" {
                detection.format = Some(Format::Tar);
                detection.confidence = Confidence::Magic;
                return detection;
            }
        }
        // checksum check for first header block
        if let Some(block) = prefix.get(..512)
            && tar_checksum_valid(block)
        {
            detection.format = Some(Format::Tar);
            detection.confidence = Confidence::Magic;
            return detection;
        }
    }

    detection
}

fn tar_checksum_valid(block: &[u8]) -> bool {
    // octal (or base-256) checksum at bytes 148..156
    let mut declared = 0u64;
    for byte in &block[148..156] {
        let value = *byte;
        if value == 0 || value == 32 {
            break;
        }
        if (b'0'..=b'7').contains(&value) {
            declared = declared
                .saturating_mul(8)
                .saturating_add((value - b'0') as u64);
        } else {
            return false;
        }
    }
    if declared == 0 {
        return false;
    }
    let mut sum = 0u64;
    for (index, byte) in block.iter().enumerate() {
        let contribution = if (148..156).contains(&index) {
            32u64
        } else {
            *byte as u64
        };
        sum = sum.saturating_add(contribution);
    }
    sum == declared
}

fn is_compressed_tar(prefix: &[u8], compression: Compression) -> bool {
    let decoded = match decode_prefix(prefix, compression, 512) {
        Some(decoded) => decoded,
        None => return false,
    };
    if decoded.len() < 512 {
        return false;
    }
    let block = &decoded[..512];
    if block.len() >= 262 && &block[257..262] == b"ustar" {
        return true;
    }
    tar_checksum_valid(block)
}

fn decode_prefix(prefix: &[u8], compression: Compression, max: usize) -> Option<Vec<u8>> {
    use flate2::bufread::MultiGzDecoder;
    use std::io::Read;
    let mut buf = Vec::with_capacity(max);
    match compression {
        Compression::Gzip => {
            let mut decoder = MultiGzDecoder::new(prefix);
            let mut tmp = [0u8; 4096];
            while buf.len() < max {
                let remaining = max - buf.len();
                let n = decoder.read(&mut tmp[..remaining.min(4096)]).ok()?;
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
            }
            return Some(buf);
        }
        Compression::Bzip2 => {
            use bzip2::bufread::MultiBzDecoder;
            let mut decoder = MultiBzDecoder::new(prefix);
            let mut tmp = [0u8; 4096];
            while buf.len() < max {
                let remaining = max - buf.len();
                let n = decoder.read(&mut tmp[..remaining.min(4096)]).ok()?;
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
            }
            return Some(buf);
        }
        Compression::Lz4 => {
            // lz4_flex decoder does not support read from &[u8] easily through bufread.
            return None;
        }
        Compression::Zstd => {
            use zstd::stream::read::Decoder;
            let mut decoder = Decoder::new(prefix).ok()?;
            let mut tmp = [0u8; 4096];
            while buf.len() < max {
                let remaining = max - buf.len();
                let n = decoder.read(&mut tmp[..remaining.min(4096)]).ok()?;
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
            }
            return Some(buf);
        }
        Compression::Xz => {
            use liblzma::read::XzDecoder;
            let mut decoder = XzDecoder::new(prefix);
            let mut tmp = [0u8; 4096];
            while buf.len() < max {
                let remaining = max - buf.len();
                let n = decoder.read(&mut tmp[..remaining.min(4096)]).ok()?;
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
            }
            return Some(buf);
        }
        _ => {}
    }
    None
}
