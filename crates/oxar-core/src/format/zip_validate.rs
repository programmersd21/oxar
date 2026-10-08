//! Independent zip structural validator. It never trusts the zip crate's view.

use std::io::{BufReader, Read, Seek, SeekFrom};

use crate::{Error, Result};

/// One central directory entry as seen by the independent validator.
#[derive(Debug, Clone)]
pub struct ZipCentralHeader {
    /// Raw entry name bytes as stored in the central directory.
    pub name: Vec<u8>,
    /// General purpose bit flags.
    pub flags: u16,
    /// Compression method code.
    pub method: u16,
    /// Compressed size in bytes (after zip64 resolution).
    pub compressed_size: u64,
    /// Uncompressed size in bytes (after zip64 resolution).
    pub uncompressed_size: u64,
    /// CRC-32 of the uncompressed data.
    pub crc32: u32,
    /// Offset of the matching local file header.
    pub local_header_offset: u64,
    /// `[start, end)` byte range of this central entry within the file.
    pub cd_range: (u64, u64),
}

/// Result of a structural validation pass over a zip archive.
#[derive(Debug, Clone)]
pub struct ZipValidation {
    /// Bytes before the first local header, nonzero for self-extracting stubs.
    pub prefix_len: u64,
    /// Number of entries the central directory declares.
    pub entries: u64,
    /// `[start, end)` byte range of the end-of-central-directory record.
    pub eocd_range: (u64, u64),
    /// Offset of the first central directory entry.
    pub cd_start: u64,
    /// Offset just past the last central directory entry.
    pub cd_end: u64,
    /// All parsed central directory headers, in file order.
    pub headers: Vec<ZipCentralHeader>,
}

/// Which header region a parsed range belongs to.
#[derive(Debug, Clone)]
pub enum RangeKind {
    /// A local file header plus its data, identified by name.
    Local(Vec<u8>),
    /// A central directory header.
    Central,
}

/// Parse and cross-check a zip archive. All strict checks happen here.
pub fn validate<R: Read + Seek>(reader: &mut R, strict: bool) -> Result<ZipValidation> {
    let len = reader.seek(SeekFrom::End(0)).map_err(io_err)?;
    if len < 22 {
        return Err(Error::Truncated {
            detail: "truncated zip archive".into(),
            loc: crate::error::Location::new(),
        });
    }
    // detect self-extracting prefix via last EOCD candidate
    let eocd_offset = find_eocd(reader, len)?;
    reader.seek(SeekFrom::Start(eocd_offset)).map_err(io_err)?;
    let mut eocd = [0u8; 22];
    reader.read_exact(&mut eocd).map_err(io_err)?;
    if &eocd[..4] != b"PK\x05\x06" {
        return Err(Error::Corrupt {
            detail: "EOCD magic not found".into(),
            loc: crate::error::Location::new(),
        });
    }
    let this_disk = u32::from(u16::from_le_bytes([eocd[4], eocd[5]]));
    let _first_cd_disk = u32::from(u16::from_le_bytes([eocd[6], eocd[7]]));
    let cd_entries_this_disk = u32::from(u16::from_le_bytes([eocd[8], eocd[9]]));
    let cd_entries_total = u32::from(u16::from_le_bytes([eocd[10], eocd[11]]));
    let cd_size = u32::from_le_bytes([eocd[12], eocd[13], eocd[14], eocd[15]]) as u64;
    let cd_offset = u32::from_le_bytes([eocd[16], eocd[17], eocd[18], eocd[19]]) as u64;

    // zip64 fields already accumulated in EOCD are handled below via the
    // locator path; the sentinel checks decide whether they are in use.

    let mut true_cd_offset = cd_offset;
    let mut true_cd_size = cd_size;
    let mut true_total = cd_entries_total as u64;
    let _ = cd_entries_this_disk;

    // extremely large sentinel => zip64 locator
    if (cd_offset == 0xFFFFFFFF || cd_size == 0xFFFFFFFF || cd_entries_total == 0xFFFF)
        && eocd_offset >= 20
    {
        let locpos = eocd_offset.saturating_sub(20);
        let mut loc = [0u8; 20];
        reader.seek(SeekFrom::Start(locpos)).map_err(io_err)?;
        reader.read_exact(&mut loc).map_err(io_err)?;
        if &loc[..4] != b"PK\x06\x07" {
            return Err(Error::Corrupt {
                detail: "zip64 locator magic missing while zip64 fields are used".into(),
                loc: crate::error::Location::new(),
            });
        }
        let zip64_cd_offset = u64::from_le_bytes([
            loc[8], loc[9], loc[10], loc[11], loc[12], loc[13], loc[14], loc[15],
        ]);
        reader
            .seek(SeekFrom::Start(zip64_cd_offset))
            .map_err(io_err)?;
        let mut zr = [0u8; 56];
        reader.read_exact(&mut zr).map_err(io_err)?;
        if &zr[..4] != b"PK\x06\x06" {
            return Err(Error::Corrupt {
                detail: "zip64 central directory record magic missing".into(),
                loc: crate::error::Location::new(),
            });
        }
        true_total = u64::from_le_bytes([
            zr[24], zr[25], zr[26], zr[27], zr[28], zr[29], zr[30], zr[31],
        ]);
        true_cd_size = u64::from_le_bytes([
            zr[40], zr[41], zr[42], zr[43], zr[44], zr[45], zr[46], zr[47],
        ]);
        true_cd_offset = u64::from_le_bytes([
            zr[48], zr[49], zr[50], zr[51], zr[52], zr[53], zr[54], zr[55],
        ]);
    }

    if true_cd_offset + true_cd_size > len || true_cd_offset >= len {
        return Err(Error::Corrupt {
            detail: "central directory range outside the file".into(),
            loc: crate::error::Location::new(),
        });
    }
    if strict && this_disk != 0 {
        return Err(Error::Corrupt {
            detail: format!("multi-disk archives are not supported, disk {this_disk}"),
            loc: crate::error::Location::new(),
        });
    }

    let mut collected: Vec<ZipCentralHeader> = Vec::new();
    let cd_end = true_cd_offset
        .checked_add(true_cd_size)
        .ok_or_else(|| Error::Corrupt {
            detail: "central directory range overflows the file".into(),
            loc: crate::error::Location::new(),
        })?;
    {
        let cd_bytes_len = usize::try_from(true_cd_size).map_err(|_| Error::Corrupt {
            detail: "central directory too large for memory".into(),
            loc: crate::error::Location::new(),
        })?;
        let mut cd_buf = vec![0u8; cd_bytes_len];
        reader
            .seek(SeekFrom::Start(true_cd_offset))
            .map_err(io_err)?;
        reader.read_exact(&mut cd_buf).map_err(io_err)?;
        let mut cd_pos = 0usize;
        while cd_pos < cd_bytes_len {
            let position = true_cd_offset + cd_pos as u64;
            if cd_pos + 46 > cd_bytes_len {
                return Err(Error::Corrupt {
                    detail: "central directory entry header truncated".into(),
                    loc: crate::error::Location::new(),
                });
            }
            let head = &cd_buf[cd_pos..cd_pos + 46];
            if &head[..4] != b"PK\x01\x02" {
                return Err(Error::Corrupt {
                    detail: "central directory entry signature missing".into(),
                    loc: crate::error::Location::new(),
                });
            }
            let flags = u16::from_le_bytes([head[8], head[9]]);
            let method = u16::from_le_bytes([head[10], head[11]]);
            let crc32 = u32::from_le_bytes([head[16], head[17], head[18], head[19]]);
            let mut comp = u32::from_le_bytes([head[20], head[21], head[22], head[23]]) as u64;
            let mut uncomp = u32::from_le_bytes([head[24], head[25], head[26], head[27]]) as u64;
            let name_len = u16::from_le_bytes([head[28], head[29]]) as usize;
            let extra_len = u16::from_le_bytes([head[30], head[31]]) as usize;
            let comment_len = u16::from_le_bytes([head[32], head[33]]) as usize;
            let mut local = u32::from_le_bytes([head[42], head[43], head[44], head[45]]) as u64;

            let entry_len = 46usize
                .checked_add(name_len)
                .and_then(|length| length.checked_add(extra_len))
                .and_then(|length| length.checked_add(comment_len))
                .ok_or_else(|| Error::corrupt("central directory entry length overflows"))?;
            if cd_pos + entry_len > cd_bytes_len {
                return Err(Error::Corrupt {
                    detail: "central directory entry extends beyond central directory".into(),
                    loc: crate::error::Location::new(),
                });
            }
            let name = cd_buf[cd_pos + 46..cd_pos + 46 + name_len].to_vec();
            let extra = &cd_buf[cd_pos + 46 + name_len..cd_pos + 46 + name_len + extra_len];

            // zip64 extra field override (0x0001)
            let mut p = 0usize;
            while p + 4 <= extra.len() {
                let tag = u16::from_le_bytes([extra[p], extra[p + 1]]);
                let sz = u16::from_le_bytes([extra[p + 2], extra[p + 3]]) as usize;
                if p + 4 + sz > extra.len() {
                    break;
                }
                if tag == 0x0001 {
                    let mut off = p + 4;
                    if uncomp == 0xFFFFFFFF && off + 8 <= p + 4 + sz {
                        uncomp = read_u64(extra, off);
                        off += 8;
                    }
                    if comp == 0xFFFFFFFF && off + 8 <= p + 4 + sz {
                        comp = read_u64(extra, off);
                        off += 8;
                    }
                    if local == 0xFFFFFFFF && off + 8 <= p + 4 + sz {
                        local = read_u64(extra, off);
                    }
                }
                // Unicode path extra field 0x7075 (strict check of name mismatch)
                if tag == 0x7075 && strict {
                    let block = &extra[p + 4..p + 4 + sz];
                    if block.len() >= 5 && block[0] == 1 {
                        let utf8_name = String::from_utf8(block[5..].to_vec()).ok();
                        let primary = String::from_utf8(name.clone()).ok();
                        if let (Some(utf8), Some(primary)) = (utf8_name, primary)
                            && utf8 != primary
                        {
                            return Err(Error::Corrupt {
                                detail: "unicode path extra field disagrees with the primary name"
                                    .into(),
                                loc: crate::error::Location::new(),
                            });
                        }
                    }
                }
                p += 4 + sz;
            }

            let entry_start = position;
            let entry_end = position + entry_len as u64;
            if entry_end > cd_end {
                return Err(Error::Corrupt {
                    detail: "central directory entry extends beyond its declared range".into(),
                    loc: crate::error::Location::new(),
                });
            }
            collected.push(ZipCentralHeader {
                name,
                flags,
                method,
                compressed_size: comp,
                uncompressed_size: uncomp,
                crc32,
                local_header_offset: local,
                cd_range: (entry_start, entry_end),
            });

            cd_pos += entry_len;
        }
    }

    if collected.len() as u64 != true_total {
        return Err(Error::Corrupt {
            detail: format!(
                "central directory declares {} entries but iterates {}",
                true_total,
                collected.len()
            ),
            loc: crate::error::Location::new(),
        });
    }

    // Strict checks on local headers and overlaps
    if strict {
        // verify offsets and overlap
        let mut ranges: Vec<(u64, u64)> = Vec::new();
        let mut cd_ranges: Vec<(u64, u64)> = Vec::new();
        let mut local_reader = BufReader::with_capacity(64 * 1024, &mut *reader);
        for h in &collected {
            let lh = h.local_header_offset;
            if lh.checked_add(30).is_none_or(|end| end > len) {
                return Err(Error::Corrupt {
                    detail: "local header points past the file".into(),
                    loc: crate::error::Location::new(),
                });
            }
            local_reader.seek(SeekFrom::Start(lh)).map_err(io_err)?;
            let mut local_header = [0u8; 30];
            local_reader.read_exact(&mut local_header).map_err(io_err)?;
            if &local_header[..4] != b"PK\x03\x04" {
                return Err(Error::Corrupt {
                    detail: "local header signature missing at declared offset".into(),
                    loc: crate::error::Location::new(),
                });
            }
            // data starts after local header + name + extra
            let l_name_len = usize::from(u16::from_le_bytes([local_header[26], local_header[27]]));
            let l_extra_len = u64::from(u16::from_le_bytes([local_header[28], local_header[29]]));
            let mut local_name = vec![0u8; l_name_len];
            local_reader.read_exact(&mut local_name).map_err(io_err)?;
            let mut local_extra = vec![0u8; l_extra_len as usize];
            local_reader.read_exact(&mut local_extra).map_err(io_err)?;
            let data_start = lh
                .checked_add(30)
                .and_then(|offset| offset.checked_add(l_name_len as u64))
                .and_then(|offset| offset.checked_add(l_extra_len))
                .ok_or_else(|| Error::corrupt("local entry data offset overflows"))?;
            let data_end = data_start
                .checked_add(h.compressed_size)
                .ok_or_else(|| Error::corrupt("local entry data range overflows"))?;
            if data_end > len {
                return Err(Error::Corrupt {
                    detail: "entry data extends past the file".into(),
                    loc: crate::error::Location::new(),
                });
            }

            // strict name agreement between central and local headers
            if strict {
                if local_name != h.name {
                    return Err(Error::Corrupt {
                        detail: "local header name disagrees with central directory".into(),
                        loc: crate::error::Location::new(),
                    });
                }
                let l_method = u16::from_le_bytes([local_header[8], local_header[9]]);
                if l_method != h.method {
                    return Err(Error::Corrupt {
                        detail: "method mismatch between central and local headers".into(),
                        loc: crate::error::Location::new(),
                    });
                }
                let l_flags = u16::from_le_bytes([local_header[6], local_header[7]]);
                if l_flags != h.flags {
                    return Err(Error::Corrupt {
                        detail: "flags mismatch between headers".into(),
                        loc: crate::error::Location::new(),
                    });
                }
                // back to after data? reader position doesn't matter; next seek lh again via top loop.
            }
            ranges.push((data_start, data_end));
            cd_ranges.push(h.cd_range);

            // consistency (unless a data descriptor is used)
            let general_flags = h.flags;
            let uses_descriptor = general_flags & 0x08 != 0;
            if !uses_descriptor {
                let local_crc = u32::from_le_bytes([
                    local_header[14],
                    local_header[15],
                    local_header[16],
                    local_header[17],
                ]);
                let local_comp = u32::from_le_bytes([
                    local_header[18],
                    local_header[19],
                    local_header[20],
                    local_header[21],
                ]);
                let local_uncomp = u32::from_le_bytes([
                    local_header[22],
                    local_header[23],
                    local_header[24],
                    local_header[25],
                ]);
                if local_crc != h.crc32 {
                    return Err(Error::Corrupt {
                        detail: "CRC mismatch between central and local headers".into(),
                        loc: crate::error::Location::new(),
                    });
                }
                let (resolved_uncomp, resolved_comp) =
                    resolve_local_zip64_sizes(&local_extra, local_uncomp, local_comp)?;
                if resolved_comp != h.compressed_size {
                    return Err(Error::Corrupt {
                        detail: "compressed size mismatch between headers".into(),
                        loc: crate::error::Location::new(),
                    });
                }
                if resolved_uncomp != h.uncompressed_size {
                    return Err(Error::Corrupt {
                        detail: "uncompressed size mismatch between headers".into(),
                        loc: crate::error::Location::new(),
                    });
                }
                // method and flags equality is too strict to check against local name, but we check signature existence
            }
        }
        // overlap check
        let mut sorted: Vec<(u64, u64)> = ranges.clone();
        sorted.sort_by_key(|r| r.0);
        for pair in sorted.windows(2) {
            if pair[0].1 > pair[1].0 {
                return Err(Error::Overlapping {
                    detail: format!("entries {} and {} share byte range", pair[0].0, pair[1].0),
                    loc: crate::error::Location::new(),
                });
            }
        }
        // central directory region must not overlap entry data
        // Simplest check: compare cd (true_cd_offset, cd_end) against every range; if overlaps any data range => error
        for &(ds, de) in &ranges {
            if true_cd_offset > ds && true_cd_offset < de {
                return Err(Error::Corrupt {
                    detail: "central directory overlaps entry data".into(),
                    loc: crate::error::Location::new(),
                });
            }
            if cd_end > ds && cd_end < de {
                return Err(Error::Corrupt {
                    detail: "central directory overlaps entry data".into(),
                    loc: crate::error::Location::new(),
                });
            }
        }
    }

    if eocd_offset > true_cd_offset && strict {
        // bytes after the central directory up to EOCD are allowed
    }
    let cd_start = true_cd_offset;
    let cd_end_final = cd_end;
    // Self-extracting archives have a stub before the first local header; for
    // plain archives the first local header sits at offset zero.
    let prefix_len = collected
        .iter()
        .map(|h| h.local_header_offset)
        .min()
        .unwrap_or(0);

    Ok(ZipValidation {
        prefix_len,
        entries: true_total,
        eocd_range: (eocd_offset, eocd_offset + 22),
        cd_start,
        cd_end: cd_end_final,
        headers: collected,
    })
}

fn resolve_local_zip64_sizes(extra: &[u8], uncomp: u32, comp: u32) -> Result<(u64, u64)> {
    let mut resolved_uncomp = u64::from(uncomp);
    let mut resolved_comp = u64::from(comp);
    let mut position = 0usize;
    while position < extra.len() {
        if extra.len() - position < 4 {
            return Err(Error::corrupt("truncated local zip extra field header"));
        }
        let tag = u16::from_le_bytes([extra[position], extra[position + 1]]);
        let size = usize::from(u16::from_le_bytes([
            extra[position + 2],
            extra[position + 3],
        ]));
        let data_start = position + 4;
        let data_end = data_start
            .checked_add(size)
            .ok_or_else(|| Error::corrupt("local zip extra field size overflows"))?;
        if data_end > extra.len() {
            return Err(Error::corrupt(
                "local zip extra field extends past its header",
            ));
        }
        if tag == 0x0001 {
            let mut cursor = data_start;
            if uncomp == u32::MAX {
                resolved_uncomp = read_local_zip64_u64(extra, cursor, data_end)?;
                cursor += 8;
            }
            if comp == u32::MAX {
                resolved_comp = read_local_zip64_u64(extra, cursor, data_end)?;
            }
            break;
        }
        position = data_end;
    }
    if (uncomp == u32::MAX || comp == u32::MAX) && position == extra.len() {
        return Err(Error::corrupt(
            "zip64 local sizes are missing their extra field",
        ));
    }
    Ok((resolved_uncomp, resolved_comp))
}

fn read_local_zip64_u64(extra: &[u8], start: usize, end: usize) -> Result<u64> {
    let value_end = start
        .checked_add(8)
        .ok_or_else(|| Error::corrupt("zip64 local size offset overflows"))?;
    let value = extra
        .get(start..value_end)
        .filter(|_| value_end <= end)
        .ok_or_else(|| Error::corrupt("zip64 local size is truncated"))?;
    let bytes = <[u8; 8]>::try_from(value)
        .map_err(|_| Error::corrupt("zip64 local size has invalid width"))?;
    Ok(u64::from_le_bytes(bytes))
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(buf)
}

fn find_eocd<R: Read + Seek>(reader: &mut R, len: u64) -> Result<u64> {
    let search = SUFFIX_SIZE.min(len);
    let start = len.saturating_sub(search);
    let mut window = vec![0u8; search as usize];
    reader.seek(SeekFrom::Start(start)).map_err(io_err)?;
    reader.read_exact(&mut window).map_err(io_err)?;
    let mut found = None;
    let mut count = 0;
    for pos in (0..window.len().saturating_sub(21)).rev() {
        if &window[pos..pos + 4] == b"PK\x05\x06" {
            let cl = u16::from_le_bytes([window[pos + 20], window[pos + 21]]) as usize;
            if pos + 22 + cl > window.len() {
                continue;
            }
            found = Some(start + pos as u64);
            count += 1;
            if count > 1 {
                // ambiguity but still allow (polyglot rejection needs full check)
            }
        }
    }
    found.ok_or_else(|| Error::UnknownFormat {
        loc: crate::error::Location::new(),
    })
}

fn io_err(e: std::io::Error) -> Error {
    Error::Io {
        source: e,
        loc: crate::error::Location::new(),
    }
}

const SUFFIX_SIZE: u64 = 66 * 1024;
