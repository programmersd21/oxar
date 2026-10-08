//! Compatibility path for the zip [`ArchiveReader`] implementation.
//!
//! The reader lives in [`crate::format::zip`] together with the writer; this
//! module re-exports it for callers that used the historical module layout.
//!
//! [`ArchiveReader`]: crate::format::ArchiveReader

pub use crate::format::zip::ZipReader;
