use std::io::{Read, Write};

use lz4_flex::frame::{FrameDecoder, FrameEncoder, FrameInfo};

use crate::error::{Error, Location};
use crate::policy::Limits;

/// LZ4 frame compress `data`; higher levels select a larger block size.
pub fn compress(data: &[u8], level: i32) -> Result<Vec<u8>, Error> {
    let mut info = FrameInfo::new();
    if level > 0 {
        // lz4_flex frame does not expose level; block size influences ratio
        info = info.block_size(lz4_flex::frame::BlockSize::Max4MB);
    }
    let mut encoder = FrameEncoder::with_frame_info(info, Vec::new());
    encoder.write_all(data).map_err(|e| Error::Io {
        source: e,
        loc: Location::new(),
    })?;
    encoder.finish().map_err(|e| Error::Io {
        source: std::io::Error::other(format!("{e}")),
        loc: Location::new(),
    })
}

/// LZ4 frame decompress `data`, enforcing the entry size cap.
pub fn decompress(data: &[u8], limits: &Limits, max_size: Option<u64>) -> Result<Vec<u8>, Error> {
    let cap = max_size.or(limits.max_entry_size).unwrap_or(u64::MAX);
    let mut dec = FrameDecoder::new(data);
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
