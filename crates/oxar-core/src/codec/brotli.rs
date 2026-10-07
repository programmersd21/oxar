use std::io::{Read, Write};

use brotli::CompressorWriter;
use brotli::Decompressor;

use crate::error::{Error, Location};
use crate::policy::Limits;

/// Brotli compress `data` with window size `lgwin`.
pub fn compress(data: &[u8], level: i32, lgwin: u32) -> Result<Vec<u8>, Error> {
    let mut output = Vec::new();
    {
        let mut writer = CompressorWriter::new(&mut output, 65536, level as u32, lgwin);
        writer.write_all(data).map_err(|e| Error::Io {
            source: e,
            loc: Location::new(),
        })?;
        writer.flush().map_err(|e| Error::Io {
            source: e,
            loc: Location::new(),
        })?;
    }
    Ok(output)
}

/// Brotli decompress `data` into memory.
pub fn decompress(data: &[u8], limits: &Limits, max_size: Option<u64>) -> Result<Vec<u8>, Error> {
    let _limits = limits;
    let _max_size = max_size;
    let mut reader = Decompressor::new(data, 65536);
    let mut output = Vec::new();
    reader.read_to_end(&mut output).map_err(|e| Error::Io {
        source: e,
        loc: Location::new(),
    })?;
    Ok(output)
}
