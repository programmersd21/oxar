//! oxar core: detection, codecs, container formats, safe extraction and
//! streaming rewrite for zip, tar and 7z. This crate has no Python types and
//! no Python concepts; the binding crate wraps it.

#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]

pub mod budget;
pub mod codec;
pub mod detect;
pub mod error;
pub mod format;
pub mod fsio;
pub mod path;
pub mod policy;
pub mod progress;
pub mod secret;
pub mod sink;

pub use budget::{Budget, EntryScope};
pub use error::{Error, Location, Result};
pub use format::{
    ArchiveReader, ArchiveWriter, Codec, Compression, Entry, EntryKind, Format, Method, NewEntry,
    OtherKind,
};
pub use policy::{
    Duplicates, Limits, LinkPolicy, ModePolicy, Overwrite, Policy, SpecialFilesPolicy, WindowsNames,
};
pub use progress::{CancelToken, NullProgress, ProgressEvent, ProgressKind, ProgressSink};
pub use secret::Secret;
pub use sink::{EntryExpect, FileAttrs, FsSink, PutOutcome, Sink, VirtualSink};
