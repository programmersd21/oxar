use std::io::{Read, Write};

use liblzma::read::XzDecoder as XzDecoderInner;
use liblzma::stream::{Check, MtStreamBuilder, PRESET_EXTREME, Stream};
use liblzma::write::XzEncoder as XzEncoderInner;

use crate::error::{Error, Location};
use crate::policy::Limits;

/// xz compress `data` at `level`, optionally in extreme mode.
pub fn compress(data: &[u8], level: i32, extreme: bool, threads: u32) -> Result<Vec<u8>, Error> {
    // liblzma allocates a block queue per worker. Small one-shot inputs cannot
    // fill those blocks, so the queue adds latency without parallel work.
    let effective_threads = if data.len() >= 64 * 1024 * 1024 {
        threads
    } else {
        1
    };
    let stream = encoder_stream(level, extreme, effective_threads)?;
    let reservation = data.len().min(1024 * 1024);
    let mut encoder = XzEncoderInner::new_stream(Vec::with_capacity(reservation), stream);
    encoder.write_all(data).map_err(|e| Error::Io {
        source: e,
        loc: Location::new(),
    })?;
    encoder.finish().map_err(|e| Error::Io {
        source: e,
        loc: Location::new(),
    })
}

/// Create an xz stream using the requested worker count.
pub(crate) fn encoder_stream(level: i32, extreme: bool, threads: u32) -> Result<Stream, Error> {
    let mut preset = u32::try_from(level).map_err(|_| Error::usage("invalid xz preset"))?;
    if extreme {
        preset |= PRESET_EXTREME;
    }
    if threads > 1 {
        let mut builder = MtStreamBuilder::new();
        builder.threads(threads).preset(preset).check(Check::Crc64);
        builder.encoder().map_err(|error| Error::Io {
            source: std::io::Error::other(error.to_string()),
            loc: Location::new(),
        })
    } else {
        Stream::new_easy_encoder(preset, liblzma::stream::Check::Crc64).map_err(|error| Error::Io {
            source: std::io::Error::other(error.to_string()),
            loc: Location::new(),
        })
    }
}

/// xz decompress `data`, decoding concatenated streams and enforcing the entry
/// size cap.
pub fn decompress(data: &[u8], limits: &Limits, max_size: Option<u64>) -> Result<Vec<u8>, Error> {
    let cap = max_size.or(limits.max_entry_size).unwrap_or(u64::MAX);
    let mem = limits.max_decoder_memory.unwrap_or(u64::MAX);
    let stream = liblzma::stream::Stream::new_stream_decoder(mem, liblzma::stream::CONCATENATED)
        .map_err(|error| Error::Io {
            source: std::io::Error::other(error.to_string()),
            loc: Location::new(),
        })?;
    let mut decoder = XzDecoderInner::new_stream(data, stream);
    // Most streams do not expand beyond their input size; a bounded initial
    // reservation avoids repeated growth without trusting frame metadata.
    let reservation = data
        .len()
        .min(usize::try_from(cap.min(8 << 20)).unwrap_or(8 << 20));
    let mut out = Vec::with_capacity(reservation);
    let mut buffer = [0u8; 64 * 1024];
    let mut written = 0u64;
    loop {
        let count = decoder.read(&mut buffer).map_err(|source| Error::Io {
            source,
            loc: Location::new(),
        })?;
        if count == 0 {
            break;
        }
        let next_size = written.saturating_add(count as u64);
        if next_size > cap {
            return Err(Error::Bomb {
                limit: "max_entry_size",
                limit_value: cap,
                observed: next_size,
                loc: Location::new(),
            });
        }
        out.extend_from_slice(&buffer[..count]);
        written = next_size;
    }
    Ok(out)
}
