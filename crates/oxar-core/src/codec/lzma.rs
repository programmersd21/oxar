use std::io::{self, Read, Write};

// Keep import aliases to avoid confusion with the C container format above.
use liblzma::read::XzDecoder as LzmaAloneDecoder;
use liblzma::stream::{LzmaOptions, PRESET_EXTREME, Stream};
use liblzma::write::XzEncoder as LzmaAloneEncoder;

use crate::error::{Error, Location};
use crate::policy::Limits;

/// lzma-alone compress `data` at `level`, optionally in extreme mode.
pub fn compress(data: &[u8], level: i32, extreme: bool, threads: u32) -> Result<Vec<u8>, Error> {
    let _ = threads; // LZMA-alone does not support independent block encoding.
    let mut level = level as u32;
    if extreme {
        level |= PRESET_EXTREME;
    }
    // LZMA-alone has one stream dictionary and cannot be split into xz blocks.
    let options = LzmaOptions::new_preset(level).map_err(|e| Error::Io {
        source: io::Error::other(e.to_string()),
        loc: Location::new(),
    })?;
    let stream = Stream::new_lzma_encoder(&options).map_err(|e| Error::Io {
        source: io::Error::other(format!("{e}")),
        loc: Location::new(),
    })?;
    let mut encoder = LzmaAloneEncoder::new_stream(Vec::new(), stream);
    encoder.write_all(data).map_err(|e| Error::Io {
        source: e,
        loc: Location::new(),
    })?;
    encoder.finish().map_err(|e| Error::Io {
        source: e,
        loc: Location::new(),
    })
}

/// lzma-alone decompress `data`, enforcing the memory limit and entry size cap.
pub fn decompress(data: &[u8], limits: &Limits, max_size: Option<u64>) -> Result<Vec<u8>, Error> {
    let cap = max_size.or(limits.max_entry_size).unwrap_or(u64::MAX);
    let mem = limits.max_decoder_memory.unwrap_or(u64::MAX);
    let stream = Stream::new_lzma_decoder(mem).map_err(|e| Error::Io {
        source: io::Error::other(format!("{e}")),
        loc: Location::new(),
    })?;
    let mut dec = LzmaAloneDecoder::new_stream(data, stream);
    let mut out = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut w = 0u64;
    loop {
        let n = dec.read(&mut buf).map_err(|e| Error::Io {
            source: e,
            loc: Location::new(),
        })?;
        if n == 0 {
            break;
        }
        if w.saturating_add(n as u64) > cap {
            return Err(Error::Bomb {
                limit: "max_entry_size",
                limit_value: cap,
                observed: w + n as u64,
                loc: Location::new(),
            });
        }
        out.extend_from_slice(&buf[..n]);
        w += n as u64;
    }
    Ok(out)
}
