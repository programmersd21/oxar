//! Sparse file support for tar: map validation, old GNU header parsing, PAX
//! map parsing, and the readers that expand stored regions while emitting the
//! gaps as zeros.

use std::io;

use super::{BLOCK, Source, decode_number};
use crate::error::{Error, Result};
use crate::policy::Limits;

/// Region map of a sparse entry: stored regions in archive order plus the
/// expanded file size.
#[derive(Debug, Clone, Default)]
pub struct SparseMap {
    /// Stored regions as (offset in the expanded file, length).
    pub regions: Vec<(u64, u64)>,
    /// Expanded file size.
    pub real_size: u64,
}

impl SparseMap {
    /// Validate a map: ordered, non-overlapping, within the real size, and no
    /// more regions than the policy allows.
    pub fn validate(regions: Vec<(u64, u64)>, real_size: u64, limits: &Limits) -> Result<Self> {
        if let Some(max) = limits.max_sparse_regions
            && regions.len() as u64 > max
        {
            return Err(Error::limit(
                "max_sparse_regions",
                max,
                regions.len() as u64,
            ));
        }
        let mut cursor = 0u64;
        for (offset, length) in &regions {
            if *offset < cursor {
                return Err(Error::corrupt("sparse regions are out of order or overlap"));
            }
            let end = offset
                .checked_add(*length)
                .ok_or_else(|| Error::corrupt("sparse region overflows"))?;
            if end > real_size {
                return Err(Error::corrupt(
                    "sparse region extends past the declared file size",
                ));
            }
            cursor = end;
        }
        Ok(Self { regions, real_size })
    }

    /// Bytes of stored data described by the map.
    #[must_use]
    pub fn packed_bytes(&self) -> u64 {
        self.regions
            .iter()
            .fold(0u64, |sum, (_, length)| sum.saturating_add(*length))
    }
}

fn io_err(error: io::Error) -> Error {
    Error::Io {
        source: error,
        loc: crate::error::Location::new(),
    }
}

/// Parse the old GNU sparse header layout: four region slots in the header
/// padding area, optionally extended by follow-up blocks.
pub(super) fn parse_old_gnu(
    block: &[u8; BLOCK],
    source: &mut Source,
    limits: &Limits,
) -> Result<SparseMap> {
    let real_size = decode_number(&block[483..495])
        .ok_or_else(|| Error::corrupt("gnu sparse realsize is not a number"))?;
    let mut regions: Vec<(u64, u64)> = Vec::new();
    for slot in 0..4 {
        let start = 386 + slot * 24;
        push_region(
            &mut regions,
            decode_number(&block[start..start + 12]),
            decode_number(&block[start + 12..start + 24]),
        )?;
    }
    let mut extended = block[482] == 1;
    let mut guard = 0u32;
    while extended {
        guard = guard.saturating_add(1);
        if guard > 65_536 {
            return Err(Error::corrupt("gnu sparse extension chain is too long"));
        }
        let mut extension = [0u8; BLOCK];
        source.read_exact_bytes(&mut extension).map_err(io_err)?;
        for slot in 0..21 {
            let start = slot * 24;
            push_region(
                &mut regions,
                decode_number(&extension[start..start + 12]),
                decode_number(&extension[start + 12..start + 24]),
            )?;
        }
        extended = extension[504] == 1;
    }
    SparseMap::validate(regions, real_size, limits)
}

fn push_region(
    regions: &mut Vec<(u64, u64)>,
    offset: Option<u64>,
    length: Option<u64>,
) -> Result<()> {
    match (offset, length) {
        (Some(0), Some(0)) | (None, None) => Ok(()),
        (Some(offset), Some(length)) => {
            regions.push((offset, length));
            Ok(())
        }
        _ => Err(Error::corrupt("gnu sparse header is inconsistent")),
    }
}

/// Parse a PAX sparse 0.0/0.1 comma separated map.
pub(super) fn parse_pax_map(value: &[u8], limits: &Limits) -> Result<Vec<(u64, u64)>> {
    let text =
        std::str::from_utf8(value).map_err(|_| Error::corrupt("pax sparse map is not text"))?;
    let mut regions = Vec::new();
    let mut pieces = text.split(',').map(str::trim).filter(|s| !s.is_empty());
    while let Some(offset_text) = pieces.next() {
        let length_text = pieces
            .next()
            .ok_or_else(|| Error::corrupt("pax sparse map has an odd number of values"))?;
        let offset: u64 = offset_text
            .parse()
            .map_err(|_| Error::corrupt("pax sparse map offset is not a number"))?;
        let length: u64 = length_text
            .parse()
            .map_err(|_| Error::corrupt("pax sparse map length is not a number"))?;
        regions.push((offset, length));
        if let Some(max) = limits.max_sparse_regions
            && regions.len() as u64 > max
        {
            return Err(Error::limit(
                "max_sparse_regions",
                max,
                regions.len() as u64,
            ));
        }
    }
    Ok(regions)
}

/// Read the in-data map of a PAX sparse 1.0 entry: decimal numbers separated
/// by newlines, starting with the number of regions. Returns the regions and
/// how many bytes the map occupied at the start of the data.
pub(super) fn parse_pax_1_0_map(
    source: &mut Source,
    data_bytes: u64,
    limits: &Limits,
) -> Result<(Vec<(u64, u64)>, u64)> {
    let ceiling = limits
        .max_pax_header_bytes
        .unwrap_or(16 * 1024 * 1024)
        .min(data_bytes);
    let mut values: Vec<u64> = Vec::new();
    let mut consumed: u64 = 0;
    let mut current: u64 = 0;
    let mut digits_seen = false;
    let mut byte = [0u8; 1];
    let mut wanted: Option<u64> = None;
    while consumed < ceiling {
        source.read_exact_bytes(&mut byte).map_err(io_err)?;
        consumed = consumed.saturating_add(1);
        match byte[0] {
            b'0'..=b'9' => {
                current = current
                    .checked_mul(10)
                    .and_then(|value| value.checked_add(u64::from(byte[0] - b'0')))
                    .ok_or_else(|| Error::corrupt("pax sparse 1.0 map value overflows"))?;
                digits_seen = true;
            }
            b'\n' => {
                if digits_seen {
                    values.push(current);
                    current = 0;
                    digits_seen = false;
                }
                match wanted {
                    None => {
                        let count = values
                            .first()
                            .copied()
                            .ok_or_else(|| Error::corrupt("pax sparse 1.0 map is empty"))?;
                        if let Some(max) = limits.max_sparse_regions
                            && count > max
                        {
                            return Err(Error::limit("max_sparse_regions", max, count));
                        }
                        wanted = Some(count.saturating_mul(2));
                    }
                    Some(total) => {
                        if values.len() as u64 > total {
                            break;
                        }
                    }
                }
            }
            other => {
                return Err(Error::corrupt(format!(
                    "pax sparse 1.0 map contains an unexpected byte {other}"
                )));
            }
        }
    }
    let count = values
        .first()
        .copied()
        .ok_or_else(|| Error::corrupt("pax sparse 1.0 map is empty"))?;
    if values.len() as u64 != count.saturating_mul(2).saturating_add(1) {
        return Err(Error::corrupt("pax sparse 1.0 map is truncated"));
    }
    let mut regions = Vec::with_capacity(count as usize);
    for pair in values[1..].chunks(2) {
        regions.push((pair[0], pair[1]));
    }
    Ok((regions, consumed))
}

/// Expansion state for one sparse entry. Reads stored regions from the source
/// in archive order and emits zero filled gaps; never seeks, so it works on
/// sequential sources and on positioned slice reads alike.
#[derive(Debug, Clone)]
pub(crate) struct SparseState {
    regions: Vec<(u64, u64)>,
    real_size: u64,
    packed_left: u64,
    region: usize,
    region_left: u64,
    gap_left: u64,
    emitted: u64,
}

impl SparseState {
    pub(crate) fn new(regions: Vec<(u64, u64)>, real_size: u64, packed: u64) -> Self {
        Self {
            regions,
            real_size,
            packed_left: packed,
            region: 0,
            region_left: 0,
            gap_left: 0,
            emitted: 0,
        }
    }

    /// Bytes of stored data not yet consumed from the source.
    pub(crate) fn packed_left(&self) -> u64 {
        self.packed_left
    }
}

impl SparseState {
    fn advance(&mut self) {
        loop {
            if self.region >= self.regions.len() {
                self.gap_left = self.real_size.saturating_sub(self.emitted);
                self.region_left = 0;
                return;
            }
            let (offset, length) = self.regions[self.region];
            let end = offset.saturating_add(length);
            if offset >= self.emitted {
                self.gap_left = offset - self.emitted;
                self.region_left = length;
                return;
            }
            if end > self.emitted {
                self.gap_left = 0;
                self.region_left = end - self.emitted;
                return;
            }
            self.region = self.region.saturating_add(1);
        }
    }

    /// Read expanded bytes into `buf`; `Ok(0)` only after the whole file.
    pub(crate) fn read(&mut self, source: &mut Source, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if self.gap_left > 0 {
                let count = buf.len().min(self.gap_left as usize);
                for byte in &mut buf[..count] {
                    *byte = 0;
                }
                self.gap_left -= count as u64;
                self.emitted = self.emitted.saturating_add(count as u64);
                return Ok(count);
            }
            if self.region_left > 0 {
                let want = buf.len().min(self.region_left as usize);
                let count = source.read(&mut buf[..want])?;
                if count == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "sparse data region is truncated",
                    ));
                }
                self.region_left -= count as u64;
                self.packed_left = self.packed_left.saturating_sub(count as u64);
                self.emitted = self.emitted.saturating_add(count as u64);
                if self.region_left == 0 {
                    self.region = self.region.saturating_add(1);
                }
                return Ok(count);
            }
            if self.emitted >= self.real_size {
                return Ok(0);
            }
            self.advance();
            if self.gap_left == 0 && self.region_left == 0 && self.emitted >= self.real_size {
                return Ok(0);
            }
        }
    }
}
