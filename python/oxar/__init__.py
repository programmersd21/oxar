"""Archive and compression primitives backed by the :mod:`oxar._oxar` Rust extension.

The package's Rust core is available as a standalone crate. The Python binding
exposes the operations documented here and reports unsupported operations
explicitly instead of silently substituting another archive implementation.
"""

from __future__ import annotations

import builtins
import io
import os
import tempfile
import time
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from typing import Any, BinaryIO, Literal

from ._models import (
    ArchiveBomb,
    Cancelled,
    CancelToken,
    ChecksumMismatch,
    ConvertReport,
    CorruptArchive,
    CreateReport,
    Detection,
    Entry,
    EntryKind,
    ExtractionError,
    ExtractReport,
    FormatError,
    OxarError,
    OxarIOError,
    OxarWarning,
    Policy,
    Problem,
    ProgressEvent,
    SecurityError,
    Skipped,
    TestReport,
    TruncatedArchive,
    UnknownFormat,
    UnsupportedFeature,
    UsageError,
    entry_from_native,
)
from ._oxar import CodecDecoder as _CodecDecoder
from ._oxar import CodecEncoder as _CodecEncoder
from ._oxar import (
    compress as _compress,
)
from ._oxar import convert_py as _convert_py
from ._oxar import create_py as _create_py
from ._oxar import (
    decompress as _decompress,
)
from ._oxar import (
    detect as _detect,
)
from ._oxar import (
    extract_py as _extract_py,
)
from ._oxar import (
    list_py as _list_py,
)
from ._oxar import (
    read_entry_py as _read_entry_py,
)
from ._oxar import rewrite_zip_py as _rewrite_zip_py
from ._oxar import (
    test_py as _test_py,
)

CodecEncoder = _CodecEncoder
CodecDecoder = _CodecDecoder

__version__ = "0.1.1"
PathLike = str | os.PathLike[str]
Source = PathLike | BinaryIO
Sink = PathLike | BinaryIO
CodecName = (
    Literal["gzip"]
    | Literal["zlib"]
    | Literal["deflate"]
    | Literal["bzip2"]
    | Literal["xz"]
    | Literal["lzma"]
    | Literal["zstd"]
    | Literal["lz4"]
    | Literal["brotli"]
    | Literal["snappy"]
)
EntryList = builtins.list[Entry]
DetectSource = Source | bytes | bytearray | memoryview
_MAX_FILELIKE_ARCHIVE_BYTES = 8 * 2**30


def _password_bytes(password: str | bytes | None) -> bytes | None:
    if password is None:
        return None
    if isinstance(password, str):
        return password.encode("utf-8")
    if isinstance(password, bytes):
        return password
    raise UsageError("password must be str, bytes, or None")


def _copy_filelike(source: BinaryIO, output: BinaryIO) -> None:
    """Copy a file-like source with bounded memory and a disk usage ceiling."""
    total = 0
    while True:
        block = source.read(256 * 1024)
        if block is None:
            raise OxarIOError("source read returned None")
        if not isinstance(block, (bytes, bytearray, memoryview)):
            raise OxarIOError("source read must return bytes")
        if not block:
            return
        total += len(block)
        if total > _MAX_FILELIKE_ARCHIVE_BYTES:
            raise ArchiveBomb("max_archive_input_size", _MAX_FILELIKE_ARCHIVE_BYTES, total)
        output.write(block)


@contextmanager
def _source_path(source: Source) -> Iterator[str]:
    if isinstance(source, (str, os.PathLike)):
        yield os.fspath(source)
        return
    if not callable(getattr(source, "read", None)):
        raise UsageError("source must be a path or a binary object with read()")
    try:
        with tempfile.TemporaryDirectory(prefix="oxar-source-") as directory:
            path = os.path.join(directory, "source.archive")
            with builtins.open(path, "wb") as output:
                _copy_filelike(source, output)
            yield path
    except OSError as error:
        raise OxarIOError(str(error)) from error


def compress(
    data: bytes | bytearray | memoryview,
    codec: CodecName,
    *,
    level: int | None = None,
    threads: int | None = None,
    **codec_options: Any,
) -> bytes:
    """Compress one byte string with a raw codec.

    Args:
        data: Input bytes.
        codec: One of gzip, zlib, deflate, bzip2, xz, lzma, zstd, lz4, brotli, snappy.
        level: Codec level, or the codec default when omitted.
        threads: Requested codec worker count.
        **codec_options: Codec-specific settings. Only options accepted by the Rust core are valid.

    Raises:
        UsageError: If a codec or option is invalid.

    Example:
        >>> round_trip = decompress(compress(b"hello", "gzip"))
    """
    if codec_options:
        raise UsageError(f"unsupported codec options: {', '.join(sorted(codec_options))}")
    defaults = {"bzip2": 9, "zstd": 3, "lz4": 0, "snappy": 0}
    default_level = defaults.get(codec, 6)
    payload = data if isinstance(data, (bytes, bytearray, memoryview)) else bytes(data)
    return _compress(
        payload,  # type: ignore[arg-type]
        codec,
        default_level if level is None else level,
        threads,
    )


def decompress(
    data: bytes | bytearray | memoryview,
    codec: CodecName | None = None,
    *,
    max_size: int | None = None,
    policy: Policy | None = None,
    ignore_trailing: bool = False,
) -> bytes:
    """Decompress one framed or raw byte string.

    Args:
        data: Compressed input.
        codec: Codec name, or None to detect a format with a magic signature.
        max_size: Maximum output size in bytes.
        policy: Optional policy whose decoder output limit is used.
        ignore_trailing: Whether to accept trailing bytes after a frame.

    Raises:
        UsageError: If the codec is unknown or an option is unsupported.
        OxarError: If decoding fails or exceeds a limit.

    Example:
        >>> payload = decompress(compress(b"hello", "gzip"), "gzip")
    """
    if ignore_trailing:
        raise UnsupportedFeature("ignore_trailing for raw codec decoding")
    if policy is not None:
        if max_size is not None:
            raise UsageError("pass either policy or max_size, not both")
        max_size = policy.max_entry_size
    payload = data if isinstance(data, (bytes, bytearray, memoryview)) else bytes(data)
    return _decompress(payload, codec, max_size)  # type: ignore[arg-type]


def detect(source: DetectSource) -> Detection:
    """Detect an archive or codec using its content.

    Args:
        source: A filesystem path or a byte buffer.

    Raises:
        OxarIOError: If a path cannot be read.

    Example:
        >>> detect(b"PK\\x03\\x04")
    """
    if isinstance(source, (bytes, bytearray, memoryview)):
        result = _detect(bytes(source))
    elif isinstance(source, (str, os.PathLike)):
        try:
            with builtins.open(source, "rb") as stream:
                result = _detect(stream.read(64 * 1024))
        except OSError as error:
            raise OxarIOError(str(error)) from error
    elif callable(getattr(source, "read", None)):
        try:
            prefix = source.read(64 * 1024)
            if prefix is None or not isinstance(prefix, (bytes, bytearray, memoryview)):
                raise OxarIOError("source read must return bytes")
            result = _detect(bytes(prefix))
        except OSError as error:
            raise OxarIOError(str(error)) from error
    else:
        raise UsageError("source must be bytes, a path, or a binary object with read()")
    return Detection(
        format=result.get("format") or None,
        compression=result.get("compression") or None,
        codec=result.get("codec") or None,
        confidence=(result.get("confidence") or "magic").lower(),
    )


def list(
    source: Source,
    *,
    password: str | bytes | None = None,
    encoding: str | None = None,
    policy: Policy | None = None,
) -> EntryList:
    """List archive metadata without extracting entry contents.

    Args:
        source: A filesystem path to a zip, tar, or 7z archive.
        password: Password for encrypted entries or headers.
        encoding: Zip legacy-name encoding override.
        policy: Extraction and resource limits.

    Raises:
        UnknownFormat: If the input is not a supported archive.
        UnsupportedFeature: If a file-like source, encoding override, or non-default
            policy is requested by this binding build.

    Example:
        >>> entries = list("backup.zip")
        >>> [entry.path for entry in entries]
    """
    if encoding is not None:
        raise UnsupportedFeature("zip encoding overrides in the Python binding")
    if policy is not None and policy != Policy.default():
        raise UnsupportedFeature("custom listing policy in the Python binding")
    with _source_path(source) as path:
        raw = _list_py(path, _password_bytes(password))
    return [entry_from_native(item) for item in raw]


def extract(
    source: Source,
    dest: PathLike,
    *,
    members: Iterable[str] | None = None,
    password: str | bytes | None = None,
    encoding: str | None = None,
    policy: Policy | None = None,
    threads: int | None = None,
    progress: Any = None,
    cancel: CancelToken | None = None,
) -> ExtractReport:
    """Extract an archive into a directory using the core's confined sink.

    Args:
        source: Archive path.
        dest: Destination directory.
        members: Optional names to extract.
        password: Password for encrypted entries.
        encoding: Zip legacy-name encoding override.
        policy: Extraction security policy.
        threads: Number of worker threads.
        progress: Progress callback.
        cancel: Thread-safe cancellation token.

    Raises:
        UnsupportedFeature: If encoding, callbacks, or parallel extraction is
            requested by this binding build.
        OxarError: If the archive is invalid or extraction is refused.

    Example:
        >>> report = extract("backup.zip", "restored/")
    """
    if encoding is not None or progress is not None:
        raise UnsupportedFeature("encoding or callback extraction")
    if threads not in (None, 1):
        raise UnsupportedFeature("parallel extraction in the Python binding")
    if cancel is not None and cancel.cancelled:
        raise Cancelled("operation cancelled")
    started = time.perf_counter()
    with _source_path(source) as path:
        selected = None if members is None else [name for name in members]
        policy_options = None if policy is None else dict(policy._values)
        try:
            entries, bytes_written, skipped, warnings = _extract_py(
                path,
                os.fspath(dest),
                _password_bytes(password),
                selected,
                policy_options,
                None if cancel is None else cancel._native,
            )
        except ValueError as error:
            if cancel is not None and cancel.cancelled and str(error) == "operation cancelled":
                raise Cancelled("operation cancelled") from None
            raise
    skipped_entries = [Skipped(path, reason) for path, reason in skipped]
    return ExtractReport(
        entries,
        bytes_written,
        skipped_entries,
        warnings,
        time.perf_counter() - started,
    )


def test(
    source: Source,
    *,
    password: str | bytes | None = None,
    encoding: str | None = None,
    policy: Policy | None = None,
    threads: int | None = None,
    progress: Any = None,
    cancel: CancelToken | None = None,
) -> TestReport:
    """Read and check every entry without writing to the filesystem.

    Args:
        source: Archive path.
        password: Password for encrypted content.
        encoding: Zip legacy-name encoding override.
        policy: Resource limits.
        threads: Number of worker threads.
        progress: Progress callback.
        cancel: Thread-safe cancellation token.

    Raises:
        UnsupportedFeature: If optional binding controls are requested.
        OxarError: If the archive cannot be opened.

    Example:
        >>> report = test("backup.zip")
        >>> report.ok
    """
    if encoding is not None or progress is not None or threads not in (None, 1):
        raise UnsupportedFeature("test callback, encoding, or parallelism controls")
    if policy is not None and policy != Policy.default():
        raise UnsupportedFeature("custom test policy in the Python binding")
    if cancel is not None and cancel.cancelled:
        raise Cancelled("operation cancelled")
    with _source_path(source) as path:
        result = _test_py(path, _password_bytes(password))
    problems = [Problem(**problem) for problem in result.get("problems", [])]
    return TestReport(
        bool(result["ok"]), int(result["entries"]), int(result["bytes_checked"]), problems
    )


class Archive:
    """An open, read-only archive view.

    Use :func:`open` to construct an instance. The current binding accepts
    filesystem paths and materializes an entry for :meth:`read`.
    """

    def __init__(self, source: Source, password: str | bytes | None = None) -> None:
        self._source_temp: tempfile.TemporaryDirectory[str] | None = None
        if isinstance(source, (str, os.PathLike)):
            self._source = os.fspath(source)
        else:
            if not callable(getattr(source, "read", None)):
                raise UsageError("source must be a path or a binary object with read()")
            self._source_temp = tempfile.TemporaryDirectory(prefix="oxar-source-")
            self._source = os.path.join(self._source_temp.name, "source.archive")
            try:
                with builtins.open(self._source, "wb") as output:
                    _copy_filelike(source, output)
            except BaseException:
                self._source_temp.cleanup()
                self._source_temp = None
                raise
        self._password = _password_bytes(password)
        self._entries: EntryList | None = None
        self._closed = False
        self.format = detect(self._source).format
        self.compression = detect(self._source).compression
        self.comment: str | None = None

    def _check_open(self) -> None:
        if self._closed:
            raise ValueError("archive is closed")

    def __enter__(self) -> Archive:
        """Return this archive for use in a context manager."""
        self._check_open()
        return self

    def __exit__(self, *_: object) -> None:
        """Close the archive after a context manager block."""
        self.close()

    def close(self) -> None:
        """Close this archive view. Repeated calls are safe."""
        self._closed = True
        if self._source_temp is not None:
            self._source_temp.cleanup()
            self._source_temp = None

    def entries(self) -> EntryList:
        """Return all entry metadata."""
        self._check_open()
        if self._entries is None:
            self._entries = list(source=self._source, password=self._password)
        return self._entries.copy()

    def __iter__(self) -> Iterator[Entry]:
        """Iterate over entry metadata."""
        return iter(self.entries())

    def __len__(self) -> int:
        """Return the number of entries."""
        return len(self.entries())

    def __contains__(self, name: object) -> bool:
        """Return whether an entry with this name exists."""
        return isinstance(name, str) and any(entry.path == name for entry in self.entries())

    def names(self) -> builtins.list[str]:
        """Return entry names in archive order."""
        return [entry.path for entry in self.entries()]

    def getinfo(self, name: str) -> Entry:
        """Return metadata for `name`, raising KeyError when absent."""
        for entry in self.entries():
            if entry.path == name:
                return entry
        raise KeyError(name)

    def read(self, name: str | Entry, *, max_size: int | None = None) -> bytes:
        """Read one file entry into memory, subject to `max_size`."""
        self._check_open()
        entry_name = name.path if isinstance(name, Entry) else name
        cap = max_size if max_size is not None else 8 * 2**30
        try:
            return bytes(_read_entry_py(self._source, entry_name, self._password, cap))
        except ValueError as error:
            raise CorruptArchive(str(error), entry=entry_name) from error

    def open_entry(self, name: str | Entry) -> BinaryIO:
        """Return an in-memory binary stream for one entry."""
        return io.BytesIO(self.read(name))

    def extract(
        self, dest: PathLike, members: Iterable[str | Entry] | None = None, **options: Any
    ) -> ExtractReport:
        """Extract this archive using the safe default filesystem sink."""
        names = (
            None if members is None else [m.path if isinstance(m, Entry) else m for m in members]
        )
        return extract(self._source, dest, members=names, password=self._password, **options)

    def test(self, **options: Any) -> TestReport:
        """Check archive entry streams and return an integrity report."""
        return test(self._source, password=self._password, **options)

    def add(self, *_: Any, **__: Any) -> None:
        """Add a file to an archive opened for writing."""
        raise UnsupportedFeature("archive writing methods in the Python binding")

    def writestr(self, *_: Any, **__: Any) -> None:
        """Write bytes to an archive opened for writing."""
        raise UnsupportedFeature("archive writing methods in the Python binding")

    def mkdir(self, *_: Any, **__: Any) -> None:
        """Add a directory entry to an archive opened for writing."""
        raise UnsupportedFeature("archive writing methods in the Python binding")

    def add_symlink(self, *_: Any, **__: Any) -> None:
        """Add a symbolic link entry to an archive opened for writing."""
        raise UnsupportedFeature("archive writing methods in the Python binding")

    def delete(self, names: Iterable[str]) -> None:
        """Remove named entries from a ZIP archive by updating its directory."""
        self._check_open()
        if self.format != "zip":
            raise UnsupportedFeature("entry deletion is currently supported for zip archives")
        _rewrite_zip_py(self._source, builtins.list(names), [], False)
        self._entries = None

    def update(self, files: Iterable[PathLike], *, root: PathLike | None = None) -> None:
        """Add or replace ZIP entries using paths relative to each source."""
        self._check_open()
        if self.format != "zip":
            raise UnsupportedFeature("entry update is currently supported for zip archives")
        if root is not None:
            raise UnsupportedFeature("custom update roots")
        _rewrite_zip_py(self._source, [], [os.fspath(item) for item in files], True)
        self._entries = None


def open(source: Source, mode: str = "r", **options: Any) -> Archive:
    """Open a filesystem archive for reading.

    Args:
        source: Archive path.
        mode: Read mode `r`. Write modes require the archive writer binding.
        **options: `password` is supported for encrypted archives.

    Raises:
        UnsupportedFeature: If the mode or an option is not supported.

    Example:
        >>> with open("backup.zip") as archive:
        ...     payload = archive.read("notes.txt")
    """
    if mode != "r":
        raise UnsupportedFeature(f"archive mode {mode!r}")
    extra = options.keys() - {"password"}
    if extra:
        raise UnsupportedFeature(f"open options: {', '.join(sorted(extra))}")
    return Archive(source, options.get("password"))


def create(
    dest: PathLike,
    sources: Iterable[PathLike],
    *,
    format: Literal["zip", "tar"] = "zip",
) -> CreateReport:
    """Create a zip or plain tar archive from files and directories.

    Args:
        dest: Destination archive path. The completed archive replaces this path.
        sources: Files or directories to add. Directory names are stored relative to each source.
        format: Container format, either zip or uncompressed tar.

    Raises:
        UsageError: If the format is unsupported.
        OxarError: If a source cannot be read or the archive cannot be written.

    Example:
        >>> report = create("backup.zip", ["project/"])
    """
    if format not in ("zip", "tar"):
        raise UnsupportedFeature(f"archive creation format {format!r}")
    source_paths = [os.fspath(source) for source in sources]
    started = time.perf_counter()
    entries, bytes_in = _create_py(os.fspath(dest), source_paths, format)
    try:
        bytes_out = os.path.getsize(dest)
    except OSError:
        bytes_out = 0
    return CreateReport(int(entries), int(bytes_in), bytes_out, time.perf_counter() - started)


def append(archive: PathLike, files: Iterable[PathLike]) -> CreateReport:
    """Append files or directory contents to an existing zip archive.

    Args:
        archive: Existing zip archive path.
        files: Files or directories to append.

    Raises:
        UnsupportedFeature: If the archive format is not zip.
        OxarError: If reading or writing fails.

    Example:
        >>> report = append("backup.zip", ["new-report.txt"])
    """
    archive_path = os.fspath(archive)
    if detect(archive_path).format != "zip":
        raise UnsupportedFeature("append supports zip archives")
    started = time.perf_counter()
    entries, bytes_in = _rewrite_zip_py(
        archive_path, [], [os.fspath(item) for item in files], False
    )
    bytes_out = os.stat(archive_path).st_size
    return CreateReport(int(entries), int(bytes_in), bytes_out, time.perf_counter() - started)


def convert(
    source: Source,
    dest: PathLike,
    *,
    format: Literal["zip", "tar"] | None = None,
    compression: CodecName | None = None,
    level: int | None = None,
    password: str | bytes | None = None,
    dest_password: str | bytes | None = None,
    policy: Policy | None = None,
    threads: int | None = None,
    solid: bool | None = None,
    reproducible: bool = False,
    progress: Any = None,
    cancel: CancelToken | None = None,
) -> ConvertReport:
    """Rewrite an archive as a ZIP or plain TAR archive.

    Args:
        source: A path or binary object containing a ZIP or TAR archive.
        dest: Path for the converted archive.
        format: Destination format. When omitted, `.zip` selects ZIP and `.tar`
            selects plain TAR.
        compression: Outer TAR compression is not available in this binding.
        level: Compression level override, currently unsupported.
        password: Password for encrypted source ZIP entries.
        dest_password: Optional password for destination ZIP entries.
        policy: Security limits applied while reading the source.
        threads: Conversion currently uses one thread.
        solid: SevenZ option, unsupported for ZIP and TAR conversion.
        reproducible: Request deterministic metadata.
        progress: Progress callback, currently unsupported.
        cancel: Thread-safe cancellation token.

    Raises:
        UnsupportedFeature: If a requested conversion option or format is not
            supported by this binding.
        OxarError: If the source is invalid, unsafe, or exceeds a policy limit.

    Example:
        >>> report = convert("backup.zip", "backup.tar", format="tar")
    """
    if compression is not None or level is not None or solid is not None:
        raise UnsupportedFeature("conversion compression, level, or solid options")
    if threads not in (None, 1) or reproducible or progress is not None:
        raise UnsupportedFeature("conversion parallelism, reproducibility, or callbacks")
    if not isinstance(dest, (str, os.PathLike)):
        raise UnsupportedFeature("file-like conversion destinations")
    destination = os.fspath(dest)
    output_format = format
    if output_format is None:
        suffix = os.path.splitext(destination)[1].lower()
        if suffix == ".zip":
            output_format = "zip"
        elif suffix == ".tar":
            output_format = "tar"
        else:
            raise UsageError("format must be provided for this destination suffix")
    if output_format not in ("zip", "tar"):
        raise UnsupportedFeature(f"conversion destination format {output_format!r}")
    if output_format == "tar" and dest_password is not None:
        raise UsageError("dest_password can only be used with ZIP output")
    if cancel is not None and cancel.cancelled:
        raise Cancelled("operation cancelled")
    started = time.perf_counter()
    policy_options = None if policy is None else dict(policy._values)
    with _source_path(source) as source_path:
        try:
            entries, bytes_in, bytes_out, recompressed, copied_raw = _convert_py(
                source_path,
                destination,
                output_format,
                _password_bytes(password),
                _password_bytes(dest_password),
                policy_options,
                None if cancel is None else cancel._native,
            )
        except ValueError as error:
            if cancel is not None and cancel.cancelled and str(error) == "operation cancelled":
                raise Cancelled("operation cancelled") from None
            raise
    return ConvertReport(
        entries,
        bytes_in,
        bytes_out,
        recompressed,
        copied_raw,
        time.perf_counter() - started,
    )


def __getattr__(name: str) -> Any:
    if name == "aio":
        from . import _aio

        return _aio
    raise AttributeError(name)


__all__ = [
    "Archive",
    "ArchiveBomb",
    "CancelToken",
    "Cancelled",
    "ChecksumMismatch",
    "CodecDecoder",
    "CodecEncoder",
    "ConvertReport",
    "CorruptArchive",
    "CreateReport",
    "Detection",
    "Entry",
    "EntryKind",
    "ExtractReport",
    "ExtractionError",
    "FormatError",
    "OxarError",
    "OxarIOError",
    "OxarWarning",
    "Policy",
    "Problem",
    "ProgressEvent",
    "SecurityError",
    "Skipped",
    "TestReport",
    "TruncatedArchive",
    "UnknownFormat",
    "UnsupportedFeature",
    "UsageError",
    "__version__",
    "append",
    "compress",
    "convert",
    "create",
    "decompress",
    "detect",
    "extract",
    "list",
    "open",
    "test",
]
