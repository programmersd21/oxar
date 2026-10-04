//! oxar core: detection, codecs, container formats, safe extraction and
//! streaming rewrite for zip, tar and 7z. This crate has no Python types and
//! no Python concepts; the binding crate wraps it.

#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]

pub mod error;
pub mod policy;

pub use error::{Error, Location, Result};
pub use policy::{
    Duplicates, Limits, LinkPolicy, ModePolicy, Overwrite, Policy, SpecialFilesPolicy, WindowsNames,
};
