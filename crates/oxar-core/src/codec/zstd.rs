use std::io::Write;

use zstd::bulk::{compress as bulk_compress, decompress as bulk_decompress};

use crate::error::{Error, Location};
use crate::policy::Limits;

/// zstd compress `data` at `level`.
pub fn compress(
    data: &[u8],
    level: i32,
    threads: u32,
    window_log: u32,
    long_distance: bool,
) -> Result<Vec<u8>, Error> {
    if data.len() <= 8 * 1024 * 1024 && threads <= 1 && window_log == 0 && !long_distance {
        return bulk_compress(data, level).map_err(|e| Error::Io {
            source: e,
            loc: Location::new(),
        });
    }
    let mut encoder =
        zstd::stream::write::Encoder::new(Vec::new(), level).map_err(|e| Error::Io {
            source: e,
            loc: Location::new(),
        })?;
    if threads > 1 && data.len() >= 1024 * 1024 {
        encoder.multithread(threads).map_err(|e| Error::Io {
            source: e,
            loc: Location::new(),
        })?;
    }
    if window_log > 0 {
        encoder.window_log(window_log).map_err(|e| Error::Io {
            source: e,
            loc: Location::new(),
        })?;
    }
    if long_distance {
        encoder
            .long_distance_matching(true)
            .map_err(|e| Error::Io {
                source: e,
                loc: Location::new(),
            })?;
    }
    encoder.write_all(data).map_err(|e| Error::Io {
        source: e,
        loc: Location::new(),
    })?;
    encoder.finish().map_err(|e| Error::Io {
        source: e,
        loc: Location::new(),
    })
}

/// zstd decompress `data`, enforcing the entry size cap.
pub fn decompress(data: &[u8], limits: &Limits, max_size: Option<u64>) -> Result<Vec<u8>, Error> {
    let cap = max_size.or(limits.max_entry_size).unwrap_or(u64::MAX);
    let result = bulk_decompress(data, cap as usize).map_err(|e| Error::Io {
        source: e,
        loc: Location::new(),
    })?;
    Ok(result)
}
