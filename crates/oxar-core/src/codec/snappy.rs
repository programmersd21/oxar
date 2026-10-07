use std::io::{Read, Write};

use snap::read::FrameDecoder as FrameDecoderInner;
use snap::write::FrameEncoder as WriteEncoder;

use crate::error::{Error, Location};
use crate::policy::Limits;

/// Snappy frame compress `data`.
pub fn compress(data: &[u8]) -> Result<Vec<u8>, Error> {
    let mut encoder = WriteEncoder::new(Vec::new());
    encoder.write_all(data).map_err(|e| Error::Io {
        source: e,
        loc: Location::new(),
    })?;
    encoder.into_inner().map_err(|e| Error::Io {
        source: std::io::Error::other(format!("{e}")),
        loc: Location::new(),
    })
}

/// Snappy frame decompress `data`, enforcing the entry size cap.
pub fn decompress(data: &[u8], limits: &Limits, max_size: Option<u64>) -> Result<Vec<u8>, Error> {
    let cap = max_size.or(limits.max_entry_size).unwrap_or(u64::MAX);
    let mut dec = FrameDecoderInner::new(data);
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
