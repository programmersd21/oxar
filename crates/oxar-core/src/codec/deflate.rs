//! raw deflate wrapper around flate2.

use std::io::{Read, Write};

use flate2::Compression as FlateLevel;
use flate2::read::DeflateDecoder as DeflateDecoderInner;
use flate2::write::DeflateEncoder as DeflateEncoderInner;

use crate::error::{Error, Location};
use crate::policy::Limits;

/// Raw deflate compress `data` at `level` (0 to 9).
pub fn compress(data: &[u8], level: i32) -> Vec<u8> {
    let mut encoder = DeflateEncoderInner::new(Vec::new(), FlateLevel::new(level as u32));
    if encoder.write_all(data).is_ok() {
        encoder.finish().unwrap_or_default()
    } else {
        Vec::new()
    }
}

/// Raw deflate decompress `data`, enforcing the entry size cap.
pub fn decompress(data: &[u8], limits: &Limits, max_size: Option<u64>) -> Result<Vec<u8>, Error> {
    let cap = max_size.or(limits.max_entry_size).unwrap_or(u64::MAX);
    let mut dec = DeflateDecoderInner::new(data);
    let reservation = data
        .len()
        .saturating_mul(2)
        .min(usize::try_from(cap.min(8 << 20)).unwrap_or(8 << 20));
    let mut out = Vec::with_capacity(reservation);
    let mut buf = [0u8; 64 * 1024];
    let mut w = 0u64;
    loop {
        let n = dec.read(&mut buf).map_err(|e| Error::Io {
            source: e,
            loc: Location::new(),
        })?;
        if n == 0 {
            break;
        }
        let next_w = w.saturating_add(n as u64);
        if next_w > cap {
            return Err(Error::Bomb {
                limit: "max_entry_size",
                limit_value: cap,
                observed: next_w,
                loc: Location::new(),
            });
        }
        out.extend_from_slice(&buf[..n]);
        w = next_w;
    }
    Ok(out)
}
