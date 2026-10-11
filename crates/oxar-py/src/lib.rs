use oxar_core::fsio::{Input, RandomSource};
use pyo3::exceptions::{PyOSError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList, PyTuple};
use std::path::{Path, PathBuf};
use std::sync::Arc;

type PyExtractResult = (u64, u64, Vec<(String, String)>, Vec<String>);

#[pyclass(frozen, name = "_NativeCancelToken")]
struct NativeCancelToken {
    inner: CancelToken,
}

#[pymethods]
impl NativeCancelToken {
    #[new]
    fn new() -> Self {
        Self {
            inner: CancelToken::new(),
        }
    }

    fn cancel(&self) {
        self.inner.cancel();
    }

    #[getter]
    fn cancelled(&self) -> bool {
        self.inner.is_cancelled()
    }
}

struct MemberSelectionReader<'a> {
    inner: &'a mut dyn oxar_core::format::ArchiveReader,
    members: Option<std::collections::HashSet<String>>,
}

impl oxar_core::format::ArchiveReader for MemberSelectionReader<'_> {
    fn format(&self) -> oxar_core::Format {
        self.inner.format()
    }

    fn next_entry(&mut self) -> oxar_core::Result<Option<oxar_core::Entry>> {
        loop {
            match self.inner.next_entry()? {
                Some(entry)
                    if self
                        .members
                        .as_ref()
                        .is_none_or(|members| members.contains(&entry.path)) =>
                {
                    return Ok(Some(entry));
                }
                Some(_) => continue,
                None => return Ok(None),
            }
        }
    }

    fn open_current(&mut self) -> oxar_core::Result<Box<dyn oxar_core::format::EntryRead + '_>> {
        self.inner.open_current()
    }

    fn open_entry(
        &mut self,
        entry: &oxar_core::Entry,
    ) -> oxar_core::Result<Box<dyn oxar_core::format::EntryRead + '_>> {
        self.inner.open_entry(entry)
    }

    fn is_random_access(&self) -> bool {
        self.inner.is_random_access()
    }
}

use oxar_core::extract;
use oxar_core::format::ArchiveReader;
use oxar_core::format::Entry;
use oxar_core::policy::{ModePolicy, Policy as RustPolicy};
use oxar_core::progress::CancelToken;

fn parse_codec(name: &str) -> PyResult<oxar_core::format::Codec> {
    name.parse()
        .map_err(|e: oxar_core::Error| PyValueError::new_err(e.to_string()))
}

fn default_threads() -> u32 {
    std::thread::available_parallelism()
        .map(|count| u32::try_from(count.get().min(8)).unwrap_or(1))
        .unwrap_or(1)
}

fn policy_from_dict(options: Option<Bound<'_, PyDict>>) -> PyResult<RustPolicy> {
    let mut policy = RustPolicy::default();
    let Some(options) = options else {
        return Ok(policy);
    };
    macro_rules! bool_field {
        ($field:ident) => {
            if let Some(value) = options.get_item(stringify!($field))? {
                policy.$field = value.extract()?;
            }
        };
    }
    macro_rules! enum_field {
        ($field:ident, $ty:path, { $($name:literal => $variant:path),+ $(,)? }) => {
            if let Some(value) = options.get_item(stringify!($field))? {
                let value = value.extract::<String>()?;
                policy.$field = match value.as_str() {
                    $($name => $variant,)+
                    _ => return Err(PyValueError::new_err(format!("invalid {} policy value: {value}", stringify!($field)))),
                };
            }
        };
    }
    macro_rules! limit_u64 {
        ($field:ident) => {
            if let Some(value) = options.get_item(stringify!($field))? {
                policy.limits.$field = value.extract::<Option<u64>>()?;
            }
        };
    }
    macro_rules! limit_usize {
        ($field:ident) => {
            if let Some(value) = options.get_item(stringify!($field))? {
                let parsed = value.extract::<Option<u64>>()?;
                policy.limits.$field = parsed.map(usize::try_from).transpose().map_err(|_| {
                    PyValueError::new_err(concat!(
                        stringify!($field),
                        " exceeds this platform's size range"
                    ))
                })?;
            }
        };
    }

    enum_field!(symlinks, oxar_core::policy::LinkPolicy, {
        "contained" => oxar_core::policy::LinkPolicy::Contained,
        "skip" => oxar_core::policy::LinkPolicy::Skip,
        "reject" => oxar_core::policy::LinkPolicy::Reject,
    });
    enum_field!(hardlinks, oxar_core::policy::LinkPolicy, {
        "contained" => oxar_core::policy::LinkPolicy::Contained,
        "skip" => oxar_core::policy::LinkPolicy::Skip,
        "reject" => oxar_core::policy::LinkPolicy::Reject,
    });
    enum_field!(special_files, oxar_core::policy::SpecialFilesPolicy, {
        "reject" => oxar_core::policy::SpecialFilesPolicy::Reject,
        "skip" => oxar_core::policy::SpecialFilesPolicy::Skip,
    });
    enum_field!(modes, oxar_core::policy::ModePolicy, {
        "safe" => oxar_core::policy::ModePolicy::Safe,
        "none" => oxar_core::policy::ModePolicy::None,
        "preserve" => oxar_core::policy::ModePolicy::Preserve,
    });
    enum_field!(overwrite, oxar_core::policy::Overwrite, {
        "error" => oxar_core::policy::Overwrite::Error,
        "skip" => oxar_core::policy::Overwrite::Skip,
        "replace" => oxar_core::policy::Overwrite::Replace,
        "newer" => oxar_core::policy::Overwrite::Newer,
    });
    enum_field!(duplicates, oxar_core::policy::Duplicates, {
        "auto" => oxar_core::policy::Duplicates::Auto,
        "reject" => oxar_core::policy::Duplicates::Reject,
        "last" => oxar_core::policy::Duplicates::Last,
        "first" => oxar_core::policy::Duplicates::First,
    });
    enum_field!(windows_names, oxar_core::policy::WindowsNames, {
        "auto" => oxar_core::policy::WindowsNames::Auto,
        "reject" => oxar_core::policy::WindowsNames::Reject,
        "allow" => oxar_core::policy::WindowsNames::Allow,
    });
    bool_field!(allow_setid);
    bool_field!(preserve_mtime);
    bool_field!(cleanup_on_error);
    bool_field!(strict);
    bool_field!(allow_streaming_zip);
    bool_field!(follow_existing_symlinks);
    bool_field!(create_dest);
    bool_field!(durable);
    limit_u64!(max_entries);
    limit_u64!(max_entry_size);
    limit_u64!(max_total_size);
    limit_u64!(max_ratio);
    limit_u64!(max_decoder_memory);
    limit_u64!(max_pax_header_bytes);
    limit_u64!(max_extra_bytes);
    limit_u64!(max_sparse_regions);
    limit_u64!(max_solid_block_bytes);
    limit_usize!(max_path_bytes);
    limit_usize!(max_component_bytes);
    limit_usize!(max_depth);
    if let Some(value) = options.get_item("ratio_floor")? {
        policy.limits.ratio_floor = value.extract()?;
    }
    Ok(policy)
}

#[pyfunction(signature = (data, codec, level=None, threads=None))]
fn compress<'py>(
    py: Python<'py>,
    data: &[u8],
    codec: &str,
    level: Option<i32>,
    threads: Option<u32>,
) -> PyResult<Bound<'py, PyBytes>> {
    let codec = parse_codec(codec)?;
    let level = level.unwrap_or(6);
    let threads = threads.unwrap_or_else(default_threads);
    if threads == 0 || threads > 256 {
        return Err(PyValueError::new_err("threads must be between 1 and 256"));
    }
    if data.len() < 512 * 1024 && threads == 1 {
        let bytes = oxar_core::codec::compress(
            codec,
            data,
            level,
            threads,
            oxar_core::codec::CodecOptions::default(),
        )
        .map_err(|error| PyValueError::new_err(error.to_string()))?;
        return Ok(PyBytes::new(py, &bytes));
    }
    let input = data.to_vec();
    let bytes = py
        .detach(move || {
            oxar_core::codec::compress(
                codec,
                &input,
                level,
                threads,
                oxar_core::codec::CodecOptions::default(),
            )
            .map_err(|error| error.to_string())
        })
        .map_err(PyValueError::new_err)?;
    Ok(PyBytes::new(py, &bytes))
}

#[pyfunction(signature = (data, codec=None, max_size=None))]
fn decompress<'py>(
    py: Python<'py>,
    data: &[u8],
    codec: Option<String>,
    max_size: Option<u64>,
) -> PyResult<Bound<'py, PyBytes>> {
    let main_codec = match codec {
        Some(s) => parse_codec(&s)?,
        None => {
            let det = oxar_core::detect::detect_bytes(data, None);
            match det.codec {
                Some(c) => c,
                None => return Err(PyValueError::new_err("Could not detect codec")),
            }
        }
    };
    let mut limits = RustPolicy::default().limits;
    if let Some(size) = max_size {
        limits.max_entry_size = Some(size);
        limits.max_total_size = Some(size);
    }
    if data.len() < 512 * 1024 {
        let out = oxar_core::codec::decompress(main_codec, data, &limits, max_size)
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        return Ok(PyBytes::new(py, &out));
    }
    let input = data.to_vec();
    let out = py
        .detach(move || {
            oxar_core::codec::decompress(main_codec, &input, &limits, max_size)
                .map_err(|error| error.to_string())
        })
        .map_err(PyValueError::new_err)?;
    Ok(PyBytes::new(py, &out))
}

#[pyfunction]
fn detect<'py>(py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyDict>> {
    let det = oxar_core::detect::detect_bytes(data, None);
    let dict = PyDict::new(py);
    dict.set_item(
        "format",
        det.format.map(|f| f.to_string()).unwrap_or_default(),
    )?;
    dict.set_item(
        "codec",
        det.codec.map(|c| c.to_string()).unwrap_or_default(),
    )?;
    dict.set_item(
        "compression",
        det.compression.map(|c| c.to_string()).unwrap_or_default(),
    )?;
    dict.set_item("confidence", format!("{:?}", det.confidence))?;
    Ok(dict)
}

#[pyfunction(signature = (source, password=None))]
fn list_py<'py>(
    py: Python<'py>,
    source: &str,
    password: Option<Vec<u8>>,
) -> PyResult<Bound<'py, PyList>> {
    let path = PathBuf::from(source);
    let entries = py
        .detach(move || -> oxar_core::Result<Vec<Entry>> {
            use std::io::Read as _;

            let mut file = std::fs::File::open(&path).map_err(|source| oxar_core::Error::Io {
                source,
                loc: oxar_core::Location::new(),
            })?;
            let mut prefix = [0u8; 64 * 1024];
            let count = file
                .read(&mut prefix)
                .map_err(|source| oxar_core::Error::Io {
                    source,
                    loc: oxar_core::Location::new(),
                })?;
            let detection = oxar_core::detect::detect_bytes(&prefix[..count], None);
            let format = detection
                .format
                .ok_or_else(|| oxar_core::Error::UnknownFormat {
                    loc: oxar_core::Location::new(),
                })?;
            let policy = RustPolicy::default();
            match format {
                oxar_core::Format::Tar => {
                    let random = RandomSource::from_file(file)?;
                    let input = Input::Random(random);
                    let mut reader = oxar_core::format::tar::TarReader::open(
                        &input,
                        detection.compression,
                        std::sync::Arc::new(policy.limits.clone()),
                        CancelToken::new(),
                    )?;
                    let mut entries = Vec::new();
                    while let Some(entry) = reader.next_entry()? {
                        entries.push(entry);
                    }
                    Ok(entries)
                }
                oxar_core::Format::Zip => {
                    let random = RandomSource::from_file(file)?;
                    let reader = oxar_core::format::zip::ZipReader::open(
                        random,
                        &policy,
                        password.as_deref().map(oxar_core::secret::Secret::new),
                        oxar_core::format::zip::NameEncoding::default(),
                    )?;
                    Ok(reader.entries().to_vec())
                }
                oxar_core::Format::SevenZ => {
                    let password = password.as_deref().map(String::from_utf8_lossy);
                    oxar_core::format::sevenz::read_sevenz_entries(&path, password.as_deref())
                }
            }
        })
        .map_err(|error| PyOSError::new_err(error.to_string()))?;
    let values = entries
        .iter()
        .map(|entry| entry_to_py(py, entry))
        .collect::<PyResult<Vec<_>>>()?;
    PyList::new(py, values)
}

fn entry_to_py<'py>(py: Python<'py>, entry: &Entry) -> PyResult<Bound<'py, PyTuple>> {
    let kind = match entry.kind {
        oxar_core::EntryKind::File => "file",
        oxar_core::EntryKind::Dir => "dir",
        oxar_core::EntryKind::Symlink => "symlink",
        oxar_core::EntryKind::Hardlink => "hardlink",
        oxar_core::EntryKind::Other(_) => "other",
    };
    let path_bytes = PyBytes::new(py, &entry.path_bytes);
    let link_target = entry
        .link_target
        .as_deref()
        .map(String::from_utf8_lossy)
        .map(|target| target.into_owned());
    let method = entry.method.map(|method| method.to_string());
    let values = vec![
        entry.path.as_str().into_pyobject(py)?.into_any(),
        path_bytes.into_any(),
        kind.into_pyobject(py)?.into_any(),
        entry.size.into_pyobject(py)?.into_any(),
        entry.compressed_size.into_pyobject(py)?.into_any(),
        entry.mode.into_pyobject(py)?.into_any(),
        entry.uid.into_pyobject(py)?.into_any(),
        entry.gid.into_pyobject(py)?.into_any(),
        entry.uname.as_deref().into_pyobject(py)?.into_any(),
        entry.gname.as_deref().into_pyobject(py)?.into_any(),
        entry.mtime_ns.into_pyobject(py)?.into_any(),
        entry.crc32.into_pyobject(py)?.into_any(),
        link_target.into_pyobject(py)?.into_any(),
        entry.encrypted.into_pyobject(py)?.to_owned().into_any(),
        method.into_pyobject(py)?.into_any(),
        entry.comment.as_deref().into_pyobject(py)?.into_any(),
    ];
    PyTuple::new(py, values)
}

#[pyfunction(signature = (source, name, password=None, max_size=None))]
fn read_entry_py(
    py: Python<'_>,
    source: &str,
    name: &str,
    password: Option<Vec<u8>>,
    max_size: Option<u64>,
) -> PyResult<Vec<u8>> {
    let path = PathBuf::from(source);
    let cap = max_size.unwrap_or(8 * 1024 * 1024 * 1024);
    let name = name.to_owned();
    py.detach(move || -> oxar_core::Result<Vec<u8>> {
        use std::io::Read as _;

        let mut file = std::fs::File::open(&path).map_err(|source| oxar_core::Error::Io {
            source,
            loc: oxar_core::Location::new(),
        })?;
        let mut prefix = [0u8; 64 * 1024];
        let count = file
            .read(&mut prefix)
            .map_err(|source| oxar_core::Error::Io {
                source,
                loc: oxar_core::Location::new(),
            })?;
        let detection = oxar_core::detect::detect_bytes(&prefix[..count], None);
        let format = detection
            .format
            .ok_or_else(|| oxar_core::Error::UnknownFormat {
                loc: oxar_core::Location::new(),
            })?;
        let mut limits = RustPolicy::default().limits;
        if max_size.is_some() {
            limits.max_entry_size = Some(cap);
            limits.max_total_size = Some(cap);
        }
        let mut data = Vec::new();
        match format {
            oxar_core::Format::Zip => {
                let random = RandomSource::from_file(file)?;
                data = oxar_core::format::zip::ZipReader::read_single_entry(
                    random,
                    &name,
                    password.map(oxar_core::secret::Secret::new),
                    cap,
                )?;
            }
            oxar_core::Format::Tar => {
                let input = Input::Path(path.clone());
                let mut archive = oxar_core::format::tar::TarReader::open(
                    &input,
                    detection.compression,
                    Arc::new(limits),
                    CancelToken::new(),
                )?;
                let mut found = false;
                while let Some(entry) = archive.next_entry()? {
                    if entry.path == name {
                        found = true;
                        archive
                            .open_current()?
                            .take(cap.saturating_add(1))
                            .read_to_end(&mut data)
                            .map_err(|source| oxar_core::Error::Io {
                                source,
                                loc: oxar_core::Location::new(),
                            })?;
                        break;
                    }
                }
                if !found {
                    return Err(oxar_core::Error::usage(format!("entry not found: {name}")));
                }
            }
            oxar_core::Format::SevenZ => {
                let password = password.as_deref().map(String::from_utf8_lossy);
                data = oxar_core::format::sevenz::read_sevenz_entry(
                    &path,
                    &name,
                    password.as_deref(),
                    cap,
                )?;
            }
        }
        if u64::try_from(data.len()).unwrap_or(u64::MAX) > cap {
            return Err(oxar_core::Error::usage("entry exceeds max_size"));
        }
        Ok(data)
    })
    .map_err(|error| PyOSError::new_err(error.to_string()))
}

#[pyfunction(signature = (source, dest, password=None, members=None, policy=None, cancel=None))]
fn extract_py(
    py: Python<'_>,
    source: &str,
    dest: &str,
    password: Option<Vec<u8>>,
    members: Option<Vec<String>>,
    policy: Option<Bound<'_, PyDict>>,
    cancel: Option<Py<NativeCancelToken>>,
) -> PyResult<PyExtractResult> {
    let path = PathBuf::from(source);
    let dest_path = PathBuf::from(dest);
    let policy = policy_from_dict(policy)?;
    let cancel = cancel.map_or_else(CancelToken::new, |token| token.borrow(py).inner.clone());
    let result = py.detach(move || -> oxar_core::Result<PyExtractResult> {
        use std::io::Read as _;

        let mut file = std::fs::File::open(&path).map_err(|source| oxar_core::Error::Io {
            source,
            loc: oxar_core::Location::new(),
        })?;
        let mut prefix = [0u8; 64 * 1024];
        let count = file
            .read(&mut prefix)
            .map_err(|source| oxar_core::Error::Io {
                source,
                loc: oxar_core::Location::new(),
            })?;
        let detection = oxar_core::detect::detect_bytes(&prefix[..count], None);
        let format = detection
            .format
            .ok_or_else(|| oxar_core::Error::UnknownFormat {
                loc: oxar_core::Location::new(),
            })?;
        let cancel = cancel;
        let sink: std::sync::Arc<dyn oxar_core::sink::Sink> = std::sync::Arc::new(
            oxar_core::sink::FsSink::new(&dest_path, std::sync::Arc::new(policy.clone()))?,
        );
        let mut reader: Box<dyn oxar_core::format::ArchiveReader> = match format {
            oxar_core::Format::Zip => {
                let source =
                    RandomSource::from_file(std::fs::File::open(&path).map_err(|source| {
                        oxar_core::Error::Io {
                            source,
                            loc: oxar_core::Location::new(),
                        }
                    })?)?;
                Box::new(oxar_core::format::zip::ZipReader::open(
                    source,
                    &policy,
                    password.as_deref().map(oxar_core::secret::Secret::new),
                    oxar_core::format::zip::NameEncoding::default(),
                )?)
            }
            oxar_core::Format::Tar => {
                let input = Input::Path(path);
                Box::new(oxar_core::format::tar::TarReader::open(
                    &input,
                    detection.compression,
                    std::sync::Arc::new(policy.limits.clone()),
                    cancel.clone(),
                )?)
            }
            oxar_core::Format::SevenZ => {
                let password = password
                    .as_deref()
                    .map(String::from_utf8_lossy)
                    .map(|value| value.into_owned());
                Box::new(oxar_core::format::sevenz::SevenzReader::open(
                    &path,
                    password.as_deref(),
                    std::sync::Arc::new(policy.limits.clone()),
                    cancel.clone(),
                )?)
            }
        };
        let mut selected = MemberSelectionReader {
            inner: reader.as_mut(),
            members: members.map(|names| names.into_iter().collect()),
        };
        let report = extract::extract(&mut selected, sink, policy, None, &cancel)?;
        let skipped = report
            .skipped
            .into_iter()
            .map(|item| (item.path, item.reason))
            .collect();
        Ok((
            report.entries,
            report.bytes_written,
            skipped,
            report.warnings,
        ))
    });
    result.map_err(|error| {
        if matches!(error, oxar_core::Error::Cancelled) {
            PyValueError::new_err("operation cancelled")
        } else {
            PyOSError::new_err(error.to_string())
        }
    })
}

#[pyfunction]
fn create_py(
    py: Python<'_>,
    dest: &str,
    sources: Vec<String>,
    format: &str,
) -> PyResult<(u64, u64)> {
    let format = format
        .parse::<oxar_core::Format>()
        .map_err(|error| PyValueError::new_err(error.to_string()))?;
    if format == oxar_core::Format::SevenZ {
        return Err(PyValueError::new_err(
            "7z creation is not available through this binding",
        ));
    }
    let destination = PathBuf::from(dest);
    let parent = destination.parent().unwrap_or_else(|| Path::new("."));
    let name = destination
        .file_name()
        .ok_or_else(|| PyValueError::new_err("destination must name a file"))?;
    let temp = parent.join(format!(
        ".{}.oxar-{}-{}.part",
        name.to_string_lossy(),
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| PyValueError::new_err(error.to_string()))?
            .as_nanos()
    ));
    let temp_path = temp.clone();
    let result = py.detach(move || -> oxar_core::Result<(u64, u64)> {
        use oxar_core::format::{ArchiveWriter, EntryKind, NewEntry};
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
            .map_err(|source| oxar_core::Error::Io {
                source,
                loc: oxar_core::Location::new(),
            })?;
        let discovered = sources
            .iter()
            .map(|source| {
                let path = Path::new(source);
                oxar_core::create::discover(path, false)
            })
            .collect::<oxar_core::Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        let (mut writer, mut entries, mut bytes): (Box<dyn ArchiveWriter>, u64, u64) = match format
        {
            oxar_core::Format::Zip => {
                (Box::new(oxar_core::format::zip::ZipWriter::new(file)), 0, 0)
            }
            oxar_core::Format::Tar => {
                (Box::new(oxar_core::format::tar::TarWriter::new(file)), 0, 0)
            }
            oxar_core::Format::SevenZ => {
                return Err(oxar_core::Error::unsupported("7z creation"));
            }
        };
        for item in discovered {
            let metadata =
                std::fs::metadata(&item.fs_path).map_err(|source| oxar_core::Error::Io {
                    source,
                    loc: oxar_core::Location::new(),
                })?;
            let entry = NewEntry {
                path: item.path,
                kind: if item.is_dir {
                    EntryKind::Dir
                } else {
                    EntryKind::File
                },
                mode: item.mode,
                mtime_ns: None,
                link_target: None,
                size_hint: if item.is_dir {
                    None
                } else {
                    Some(metadata.len())
                },
                method: None,
                level: None,
                password: None,
            };
            let mut input: Box<dyn std::io::Read> = if item.is_dir {
                Box::new(std::io::empty())
            } else {
                Box::new(std::fs::File::open(item.fs_path).map_err(|source| {
                    oxar_core::Error::Io {
                        source,
                        loc: oxar_core::Location::new(),
                    }
                })?)
            };
            writer.add(&entry, &mut input)?;
            entries = entries.saturating_add(1);
            bytes = bytes.saturating_add(entry.size_hint.unwrap_or(0));
        }
        writer.finish()?;
        std::fs::rename(&temp_path, &destination).map_err(|source| oxar_core::Error::Io {
            source,
            loc: oxar_core::Location::new(),
        })?;
        Ok((entries, bytes))
    });
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result.map_err(|error| PyValueError::new_err(error.to_string()))
}

#[pyfunction(signature = (source, dest, format, password=None, dest_password=None, policy=None, cancel=None))]
#[allow(clippy::too_many_arguments)]
fn convert_py(
    py: Python<'_>,
    source: &str,
    dest: &str,
    format: &str,
    password: Option<Vec<u8>>,
    dest_password: Option<Vec<u8>>,
    policy: Option<Bound<'_, PyDict>>,
    cancel: Option<Py<NativeCancelToken>>,
) -> PyResult<(u64, u64, u64, u64, u64)> {
    use oxar_core::format::{ArchiveReader, ArchiveWriter, EntryKind, NewEntry};
    use oxar_core::path::{SeparatorRule, sanitize};
    let source_path = PathBuf::from(source);
    let destination = PathBuf::from(dest);
    let output_format = format
        .parse::<oxar_core::Format>()
        .map_err(|error| PyValueError::new_err(error.to_string()))?;
    if !matches!(
        output_format,
        oxar_core::Format::Zip | oxar_core::Format::Tar
    ) {
        return Err(PyValueError::new_err(
            "conversion to 7z is not available through this binding",
        ));
    }
    let policy = policy_from_dict(policy)?;
    let cancel = cancel.map_or_else(CancelToken::new, |token| token.borrow(py).inner.clone());
    let password = password.map(oxar_core::secret::Secret::new);
    let dest_password = dest_password.map(oxar_core::secret::Secret::new);
    let parent = destination.parent().unwrap_or_else(|| Path::new("."));
    let file_name = destination
        .file_name()
        .ok_or_else(|| PyValueError::new_err("destination must name a file"))?;
    let temp_path = parent.join(format!(
        ".{}.oxar-{}.part",
        file_name.to_string_lossy(),
        oxar_core::fsio::random_token()
    ));
    let cleanup_path = temp_path.clone();
    let result = py.detach(move || -> oxar_core::Result<(u64, u64, u64, u64, u64)> {
        let input = Input::Path(source_path.clone());
        let detection = oxar_core::detect::detect(&input, &policy)?;
        let input_format = detection
            .format
            .ok_or_else(|| oxar_core::Error::UnknownFormat {
                loc: oxar_core::Location::new(),
            })?;
        if !matches!(
            input_format,
            oxar_core::Format::Zip | oxar_core::Format::Tar | oxar_core::Format::SevenZ
        ) {
            return Err(oxar_core::Error::unsupported(
                "conversion from this format through this binding",
            ));
        }
        let mut reader: Box<dyn ArchiveReader> = match input_format {
            oxar_core::Format::Zip => {
                let random = RandomSource::from_file(std::fs::File::open(&source_path).map_err(
                    |source| oxar_core::Error::Io {
                        source,
                        loc: oxar_core::Location::new(),
                    },
                )?)?;
                Box::new(oxar_core::format::zip::ZipReader::open(
                    random,
                    &policy,
                    password.clone(),
                    oxar_core::format::zip::NameEncoding::default(),
                )?)
            }
            oxar_core::Format::Tar => Box::new(oxar_core::format::tar::TarReader::open(
                &input,
                detection.compression,
                Arc::new(policy.limits.clone()),
                cancel.clone(),
            )?),
            oxar_core::Format::SevenZ => {
                let password = password.clone(); // already Option<Secret>
                let pw = password
                    .as_ref()
                    .map(|s| String::from_utf8_lossy(s.expose()).into_owned());
                Box::new(oxar_core::format::sevenz::SevenzReader::open(
                    &source_path,
                    pw.as_deref(),
                    std::sync::Arc::new(policy.limits.clone()),
                    cancel.clone(),
                )?)
            }
        };

        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
            .map_err(|source| oxar_core::Error::Io {
                source,
                loc: oxar_core::Location::new(),
            })?;
        let mut writer: Box<dyn ArchiveWriter> = match output_format {
            oxar_core::Format::Zip => Box::new(oxar_core::format::zip::ZipWriter::with_password(
                file,
                dest_password.clone(),
            )),
            oxar_core::Format::Tar => Box::new(oxar_core::format::tar::TarWriter::new(file)),
            oxar_core::Format::SevenZ => {
                return Err(oxar_core::Error::unsupported("7z conversion"));
            }
        };

        let budget = oxar_core::Budget::new(policy.limits.clone(), cancel.clone());
        let separator = match input_format {
            oxar_core::Format::Tar => SeparatorRule::BackslashIsLiteral,
            oxar_core::Format::Zip | oxar_core::Format::SevenZ => {
                SeparatorRule::BackslashIsSeparator
            }
        };
        let output_separator = match output_format {
            oxar_core::Format::Tar => SeparatorRule::BackslashIsLiteral,
            oxar_core::Format::Zip | oxar_core::Format::SevenZ => {
                SeparatorRule::BackslashIsSeparator
            }
        };
        let mut seen_input = std::collections::HashSet::new();
        let mut seen_output = std::collections::HashSet::new();
        let mut seen_files = std::collections::HashSet::new();
        let mut entries = 0u64;
        let mut recompressed = 0u64;
        while let Some(entry) = reader.next_entry()? {
            budget.check_cancel()?;
            let mut scope = budget.start_entry()?;
            let safe_input = sanitize(&entry.path_bytes, separator, &policy, cfg!(windows))?;
            let safe = sanitize(
                safe_input.raw_bytes(),
                output_separator,
                &policy,
                cfg!(windows),
            )?;
            if !seen_input.insert(safe_input.collision_key().to_owned())
                || !seen_output.insert(safe.collision_key().to_owned())
            {
                return Err(oxar_core::Error::usage(format!(
                    "conversion found a duplicate entry name: {}",
                    safe.display()
                )));
            }
            let path = std::str::from_utf8(safe.raw_bytes()).map_err(|_| {
                oxar_core::Error::unsupported("destination archive names must be valid UTF-8")
            })?;
            if matches!(entry.kind, EntryKind::Symlink | EntryKind::Hardlink) {
                let link_policy = if entry.kind == EntryKind::Symlink {
                    policy.symlinks
                } else {
                    policy.hardlinks
                };
                match link_policy {
                    oxar_core::LinkPolicy::Reject => {
                        return Err(oxar_core::Error::UnsafeLink {
                            detail: "link entries are rejected by policy".to_owned(),
                            loc: oxar_core::Location::new(),
                        });
                    }
                    oxar_core::LinkPolicy::Skip => {
                        entries = entries.saturating_add(1);
                        continue;
                    }
                    oxar_core::LinkPolicy::Contained => {}
                }
                let target =
                    entry
                        .link_target
                        .as_deref()
                        .ok_or_else(|| oxar_core::Error::UnsafeLink {
                            detail: "link entry has no target".to_owned(),
                            loc: oxar_core::Location::new(),
                        })?;
                if entry.kind == EntryKind::Symlink {
                    oxar_core::path::validate_symlink_target(
                        target,
                        safe.depth().saturating_sub(1),
                        &policy,
                    )?;
                } else {
                    let target_path = sanitize(target, separator, &policy, cfg!(windows))?;
                    if !seen_files.contains(target_path.collision_key()) {
                        return Err(oxar_core::Error::UnsafeLink {
                            detail: "hard link target is not an earlier regular file".to_owned(),
                            loc: oxar_core::Location::new(),
                        });
                    }
                }
            }
            if let EntryKind::Other(kind) = entry.kind {
                match policy.special_files {
                    oxar_core::SpecialFilesPolicy::Reject => {
                        return Err(oxar_core::Error::unsupported(format!(
                            "conversion of special entry {kind}"
                        )));
                    }
                    oxar_core::SpecialFilesPolicy::Skip => {
                        entries = entries.saturating_add(1);
                        continue;
                    }
                }
            }
            scope.charge_in(entry.compressed_size.or(entry.size).unwrap_or(0));
            let mut data = reader.open_current()?;
            let new_entry = NewEntry {
                path: path.to_owned(),
                kind: entry.kind,
                mode: match policy.modes {
                    ModePolicy::None => None,
                    ModePolicy::Safe => entry.mode.map(|mode| (mode & !0o7022) & 0o777),
                    ModePolicy::Preserve => entry.mode.map(|mode| {
                        if policy.allow_setid {
                            mode
                        } else {
                            mode & !0o6000
                        }
                    }),
                },
                mtime_ns: if policy.preserve_mtime {
                    entry.mtime_ns
                } else {
                    None
                },
                link_target: entry.link_target,
                size_hint: entry.size,
                method: None,
                level: None,
                password: None,
            };
            {
                let mut charged = BudgetedReader {
                    inner: data.as_mut(),
                    scope: &mut scope,
                    failure: None,
                };
                match entry.kind {
                    EntryKind::File => {
                        let result = writer.add(&new_entry, &mut charged);
                        if let Some(error) = charged.failure.take() {
                            return Err(error);
                        }
                        result?;
                        recompressed = recompressed.saturating_add(1);
                    }
                    EntryKind::Dir | EntryKind::Symlink | EntryKind::Hardlink => {
                        writer.add(&new_entry, &mut std::io::empty())?
                    }
                    EntryKind::Other(kind) => {
                        return Err(oxar_core::Error::unsupported(format!(
                            "conversion of special entry {kind}"
                        )));
                    }
                }
            }
            if entry.kind == EntryKind::File {
                seen_files.insert(safe.collision_key().to_owned());
            }
            entries = entries.saturating_add(1);
        }
        let bytes_in = std::fs::metadata(&source_path)
            .map_err(|source| oxar_core::Error::Io {
                source,
                loc: oxar_core::Location::new(),
            })?
            .len();
        writer.finish()?;
        let output_bytes = std::fs::metadata(&temp_path)
            .map_err(|source| oxar_core::Error::Io {
                source,
                loc: oxar_core::Location::new(),
            })?
            .len();
        drop(reader);
        std::fs::rename(&temp_path, &destination).map_err(|source| oxar_core::Error::Io {
            source,
            loc: oxar_core::Location::new(),
        })?;
        Ok((entries, bytes_in, output_bytes, recompressed, 0))
    });
    if result.is_err() {
        let _ = std::fs::remove_file(cleanup_path);
    }
    result.map_err(|error| {
        if matches!(error, oxar_core::Error::Cancelled) {
            PyValueError::new_err("operation cancelled")
        } else {
            PyOSError::new_err(error.to_string())
        }
    })
}

struct BudgetedReader<'a> {
    inner: &'a mut dyn oxar_core::format::EntryRead,
    scope: &'a mut oxar_core::EntryScope,
    failure: Option<oxar_core::Error>,
}

impl std::io::Read for BudgetedReader<'_> {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        if let Err(error) = self.scope.check_cancel() {
            let message = error.to_string();
            self.failure = Some(error);
            return Err(std::io::Error::other(message));
        }
        let limit = output.len().min(64 * 1024);
        let count = self.inner.read(&mut output[..limit])?;
        if count > 0
            && let Err(error) = self
                .scope
                .charge_out(u64::try_from(count).unwrap_or(u64::MAX))
        {
            let message = error.to_string();
            self.failure = Some(error);
            return Err(std::io::Error::other(message));
        }
        Ok(count)
    }
}

#[pyfunction]
fn rewrite_zip_py(
    py: Python<'_>,
    archive: &str,
    delete_names: Vec<String>,
    sources: Vec<String>,
    replace_existing: bool,
) -> PyResult<(u64, u64)> {
    use oxar_core::format::{EntryKind, NewEntry};
    use std::io::Write as _;

    let path = PathBuf::from(archive);
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .ok_or_else(|| PyValueError::new_err("archive path must name a file"))?;
    let temp = parent.join(format!(
        ".{}.oxar-{}.part",
        name.to_string_lossy(),
        oxar_core::fsio::random_token()
    ));
    let temp_path = temp.clone();
    let result = py.detach(move || -> oxar_core::Result<(u64, u64)> {
        let index_source =
            RandomSource::from_file(std::fs::File::open(&path).map_err(|source| {
                oxar_core::Error::Io {
                    source,
                    loc: oxar_core::Location::new(),
                }
            })?)
            .map_err(|source| oxar_core::Error::Io {
                source,
                loc: oxar_core::Location::new(),
            })?;
        let index_reader = oxar_core::format::zip::ZipReader::open(
            index_source,
            &RustPolicy::default(),
            None,
            oxar_core::format::zip::NameEncoding::default(),
        )?;
        let existing_names = index_reader
            .entries()
            .iter()
            .map(|entry| entry.path.clone())
            .collect::<std::collections::HashSet<_>>();
        let mut source = std::fs::File::open(&path).map_err(|source| oxar_core::Error::Io {
            source,
            loc: oxar_core::Location::new(),
        })?;
        let mut temp_file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&temp_path)
            .map_err(|source| oxar_core::Error::Io {
                source,
                loc: oxar_core::Location::new(),
            })?;
        std::io::copy(&mut source, &mut temp_file).map_err(|source| oxar_core::Error::Io {
            source,
            loc: oxar_core::Location::new(),
        })?;
        let mut writer = oxar_core::format::zip::ZipWriter::append(temp_file)?;
        for name in &delete_names {
            writer.hide_file(name)?;
        }
        let discovered = sources
            .iter()
            .map(|source| oxar_core::create::discover(Path::new(source), false))
            .collect::<oxar_core::Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        let mut entries = 0u64;
        let mut bytes = 0u64;
        for item in discovered {
            let metadata =
                std::fs::metadata(&item.fs_path).map_err(|source| oxar_core::Error::Io {
                    source,
                    loc: oxar_core::Location::new(),
                })?;
            let entry = NewEntry {
                path: item.path,
                kind: if item.is_dir {
                    EntryKind::Dir
                } else {
                    EntryKind::File
                },
                mode: item.mode,
                mtime_ns: None,
                link_target: None,
                size_hint: (!item.is_dir).then_some(metadata.len()),
                method: None,
                level: None,
                password: None,
            };
            if replace_existing && existing_names.contains(&entry.path) {
                writer.hide_file(&entry.path)?;
            }
            let mut input: Box<dyn std::io::Read> = if item.is_dir {
                Box::new(std::io::empty())
            } else {
                Box::new(std::fs::File::open(item.fs_path).map_err(|source| {
                    oxar_core::Error::Io {
                        source,
                        loc: oxar_core::Location::new(),
                    }
                })?)
            };
            writer.add(&entry, &mut input)?;
            entries = entries.saturating_add(1);
            bytes = bytes.saturating_add(entry.size_hint.unwrap_or(0));
        }
        let mut finished = writer.finish()?;
        finished
            .flush()
            .and_then(|()| finished.sync_all())
            .map_err(|source| oxar_core::Error::Io {
                source,
                loc: oxar_core::Location::new(),
            })?;
        drop(finished);
        std::fs::rename(&temp_path, &path).map_err(|source| oxar_core::Error::Io {
            source,
            loc: oxar_core::Location::new(),
        })?;
        Ok((entries, bytes))
    });
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result.map_err(|error| PyValueError::new_err(error.to_string()))
}

#[pyfunction(signature = (source, password=None))]
fn test_py<'py>(
    py: Python<'py>,
    source: &str,
    password: Option<Vec<u8>>,
) -> PyResult<Bound<'py, PyDict>> {
    let path = PathBuf::from(source);
    let report = py
        .detach(
            move || -> oxar_core::Result<oxar_core::test_archive::TestReport> {
                use std::io::Read as _;

                let mut file =
                    std::fs::File::open(&path).map_err(|source| oxar_core::Error::Io {
                        source,
                        loc: oxar_core::Location::new(),
                    })?;
                let mut prefix = [0u8; 64 * 1024];
                let count = file
                    .read(&mut prefix)
                    .map_err(|source| oxar_core::Error::Io {
                        source,
                        loc: oxar_core::Location::new(),
                    })?;
                let detection = oxar_core::detect::detect_bytes(&prefix[..count], None);
                let format = detection
                    .format
                    .ok_or_else(|| oxar_core::Error::UnknownFormat {
                        loc: oxar_core::Location::new(),
                    })?;
                let policy = RustPolicy::default();
                let cancel = CancelToken::new();
                let mut reader: Box<dyn oxar_core::format::ArchiveReader> = match format {
                    oxar_core::Format::Tar => {
                        let input = Input::Path(path.clone());
                        Box::new(oxar_core::format::tar::TarReader::open(
                            &input,
                            detection.compression,
                            std::sync::Arc::new(policy.limits.clone()),
                            cancel.clone(),
                        )?)
                    }
                    oxar_core::Format::Zip => {
                        let random = RandomSource::from_file(std::fs::File::open(&path).map_err(
                            |source| oxar_core::Error::Io {
                                source,
                                loc: oxar_core::Location::new(),
                            },
                        )?)?;
                        Box::new(oxar_core::format::zip::ZipReader::open(
                            random,
                            &policy,
                            password.as_deref().map(oxar_core::secret::Secret::new),
                            oxar_core::format::zip::NameEncoding::default(),
                        )?)
                    }
                    oxar_core::Format::SevenZ => {
                        let password = password
                            .as_deref()
                            .map(String::from_utf8_lossy)
                            .map(|value| value.into_owned());
                        Box::new(oxar_core::format::sevenz::SevenzReader::open(
                            &path,
                            password.as_deref(),
                            std::sync::Arc::new(policy.limits.clone()),
                            cancel.clone(),
                        )?)
                    }
                };
                oxar_core::test_archive::test_all(reader.as_mut(), &policy, None, &cancel)
            },
        )
        .map_err(|error| PyOSError::new_err(error.to_string()))?;
    let dict = PyDict::new(py);
    dict.set_item("ok", report.ok)?;
    dict.set_item("entries", report.entries)?;
    dict.set_item("bytes_checked", report.bytes_checked)?;
    let problems = PyList::empty(py);
    for problem in report.problems {
        let d = PyDict::new(py);
        d.set_item("path", problem.path)?;
        d.set_item("kind", problem.kind)?;
        d.set_item("detail", problem.detail)?;
        problems.append(d)?;
    }
    dict.set_item("problems", problems)?;
    Ok(dict)
}

use oxar_core::codec::stream::{StreamDecoder, StreamEncoder, stream_decoder, stream_encoder};
use std::io::{Read, Write};
use std::sync::Mutex;

#[derive(Clone)]
struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

impl Write for SharedBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct SharedReader {
    buffer: Arc<Mutex<Vec<u8>>>,
    position: Arc<Mutex<usize>>,
}

impl Read for SharedReader {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        let buffer = self.buffer.lock().unwrap();
        let mut position = self.position.lock().unwrap();
        let available = buffer.len().saturating_sub(*position);

        if available == 0 {
            return Ok(0);
        }
        let count = available.min(out.len());
        out[..count].copy_from_slice(&buffer[*position..*position + count]);
        *position += count;
        Ok(count)
    }
}

#[pyclass(name = "CodecEncoder")]
struct CodecEncoder {
    inner: Mutex<Option<StreamEncoder>>,
    sink: Arc<Mutex<Vec<u8>>>,
    consumed: usize,
}

#[pymethods]
impl CodecEncoder {
    #[new]
    #[pyo3(signature = (codec, level=None, threads=None))]
    fn new(codec: &str, level: Option<i32>, threads: Option<u32>) -> PyResult<Self> {
        let codec = parse_codec(codec)?;
        let level = level.unwrap_or(6);
        let threads = threads.unwrap_or(1);
        if threads == 0 || threads > 256 {
            return Err(PyValueError::new_err("threads must be between 1 and 256"));
        }
        oxar_core::codec::stream::validate_level(codec, level)
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        let sink = Arc::new(Mutex::new(Vec::new()));
        let writer = SharedBuffer(sink.clone());
        let encoder = stream_encoder(
            codec,
            Box::new(writer),
            level,
            threads,
            oxar_core::codec::CodecOptions::default(),
        )
        .map_err(|error| PyValueError::new_err(error.to_string()))?;
        Ok(Self {
            inner: Mutex::new(Some(encoder)),
            sink,
            consumed: 0,
        })
    }

    fn compress(&mut self, data: &[u8]) -> PyResult<Vec<u8>> {
        let mut guard = self.inner.lock().unwrap();
        let encoder = guard
            .as_mut()
            .ok_or_else(|| PyValueError::new_err("encoder is finished"))?;
        encoder
            .write_all(data)
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        encoder
            .flush()
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        let sink = self.sink.lock().unwrap();
        let output = sink[self.consumed..].to_vec();
        self.consumed = sink.len();
        Ok(output)
    }

    fn flush(&mut self) -> PyResult<Vec<u8>> {
        if let Some(encoder) = self.inner.lock().unwrap().as_mut() {
            encoder
                .flush()
                .map_err(|error| PyValueError::new_err(error.to_string()))?;
        }
        let sink = self.sink.lock().unwrap();
        let output = sink[self.consumed..].to_vec();
        self.consumed = sink.len();
        Ok(output)
    }

    fn finish(&mut self) -> PyResult<Vec<u8>> {
        if let Some(encoder) = self.inner.lock().unwrap().take() {
            encoder
                .finish()
                .map_err(|error| PyValueError::new_err(error.to_string()))?;
        }
        let sink = self.sink.lock().unwrap();
        let output = sink[self.consumed..].to_vec();
        self.consumed = sink.len();
        Ok(output)
    }
}

#[pyclass(name = "CodecDecoder")]
struct CodecDecoder {
    codec: String,
    inner: Mutex<Option<StreamDecoder>>,
    input: Arc<Mutex<Vec<u8>>>,
    position: Arc<Mutex<usize>>,
}

#[pymethods]
impl CodecDecoder {
    #[new]
    fn new(codec: &str) -> PyResult<Self> {
        let _ = parse_codec(codec)?;
        let input = Arc::new(Mutex::new(Vec::new()));
        let position = Arc::new(Mutex::new(0usize));
        Ok(Self {
            codec: codec.to_owned(),
            inner: Mutex::new(None),
            input,
            position,
        })
    }

    fn decompress(&mut self, data: &[u8]) -> PyResult<Vec<u8>> {
        self.input.lock().unwrap().extend_from_slice(data);
        let mut guard = self.inner.lock().unwrap();
        if guard.is_none() {
            let codec = parse_codec(&self.codec)?;
            let reader = SharedReader {
                buffer: self.input.clone(),
                position: self.position.clone(),
            };
            let limits = RustPolicy::default().limits;
            let decoder = stream_decoder(codec, Box::new(reader), &limits)
                .map_err(|error| PyValueError::new_err(error.to_string()))?;
            *guard = Some(decoder);
        }
        let decoder = guard
            .as_mut()
            .ok_or_else(|| PyValueError::new_err("decoder is finished"))?;
        let mut output = Vec::new();
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let count = decoder
                .read(&mut buffer)
                .map_err(|error| PyValueError::new_err(error.to_string()))?;
            if count == 0 {
                break;
            }
            output.extend_from_slice(&buffer[..count]);
        }
        Ok(output)
    }

    fn flush(&mut self) -> PyResult<Vec<u8>> {
        self.decompress(&[])
    }

    fn finish(&mut self) -> PyResult<Vec<u8>> {
        let output = self.decompress(&[])?;
        *self.inner.lock().unwrap() = None;
        Ok(output)
    }
}

#[pymodule]
fn _oxar(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<NativeCancelToken>()?;
    m.add_class::<CodecEncoder>()?;
    m.add_class::<CodecDecoder>()?;
    m.add_class::<CodecEncoder>()?;
    m.add_class::<CodecDecoder>()?;
    m.add_function(wrap_pyfunction!(compress, m)?)?;
    m.add_function(wrap_pyfunction!(decompress, m)?)?;
    m.add_function(wrap_pyfunction!(detect, m)?)?;
    m.add_function(wrap_pyfunction!(list_py, m)?)?;
    m.add_function(wrap_pyfunction!(extract_py, m)?)?;
    m.add_function(wrap_pyfunction!(create_py, m)?)?;
    m.add_function(wrap_pyfunction!(convert_py, m)?)?;
    m.add_function(wrap_pyfunction!(rewrite_zip_py, m)?)?;
    m.add_function(wrap_pyfunction!(test_py, m)?)?;
    m.add_function(wrap_pyfunction!(read_entry_py, m)?)?;
    Ok(())
}
