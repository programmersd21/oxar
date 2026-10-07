use std::io::{Read, Write};

use bzip2::Compression as BzLevel;
use bzip2::bufread::MultiBzDecoder;
use bzip2::write::BzEncoder as BzEncoderInner;

use crate::error::{Error, Location};
use crate::policy::Limits;

/// bzip2 compress `data` at `level` (1 to 9).
pub fn compress(data: &[u8], level: i32) -> Vec<u8> {
    let reservation = data.len().min(1024 * 1024);
    let mut enc = BzEncoderInner::new(
        Vec::with_capacity(reservation),
        BzLevel::try_new(level as u32).unwrap_or(BzLevel::best()),
    );
    if enc.write_all(data).is_ok() {
        enc.finish().unwrap_or_default()
    } else {
        Vec::new()
    }
}

/// bzip2 decompress `data`, decoding concatenated members and enforcing the
/// entry size cap.
pub fn decompress(data: &[u8], limits: &Limits, max_size: Option<u64>) -> Result<Vec<u8>, Error> {
    let cap = max_size.or(limits.max_entry_size).unwrap_or(u64::MAX);
    let mut dec = MultiBzDecoder::new(data);
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
