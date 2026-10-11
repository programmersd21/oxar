"""Public value objects and the immutable extraction policy."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from types import MappingProxyType
from typing import Any


class OxarError(Exception):
    """Base class for errors reported by oxar."""

    def __init__(
        self,
        message: str,
        *,
        format: str | None = None,
        entry: str | None = None,
        offset: int | None = None,
    ) -> None:
        super().__init__(message)
        self.format = format
        self.entry = entry
        self.offset = offset


class UsageError(OxarError, ValueError):
    """An argument or requested operation is invalid."""


class FormatError(OxarError):
    """An archive is unknown, corrupt, truncated, or fails a checksum."""


class UnknownFormat(FormatError):
    """No supported archive or codec signature was detected."""


class CorruptArchive(FormatError):
    """An archive structure or entry stream is invalid."""


class TruncatedArchive(CorruptArchive):
    """The archive ended before the declared structure was complete."""


class ChecksumMismatch(CorruptArchive):
    """An entry checksum did not match its contents."""


class UnsupportedFeature(OxarError):
    """The requested feature is outside the current Python binding surface."""

    def __init__(self, feature: str) -> None:
        super().__init__(f"unsupported feature: {feature}")
        self.feature = feature


class EncryptionError(OxarError):
    """A password is missing or does not unlock the requested data."""


class PasswordRequired(EncryptionError):
    """The archive requires a password."""


class WrongPassword(EncryptionError):
    """The supplied password did not authenticate the archive data."""


class SecurityError(OxarError):
    """An archive entry violates an extraction security rule."""


class UnsafePath(SecurityError):
    """An archive path cannot be safely placed under the destination."""


class UnsafeLink(SecurityError):
    """An archive link is unsafe or escapes the destination."""


class SpecialFileRejected(SecurityError):
    """An archive contains a device, FIFO, or socket entry."""


class DuplicateEntry(SecurityError):
    """An archive contains a conflicting duplicate path."""


class OverlappingEntries(SecurityError):
    """Zip entries overlap in the archive byte stream."""


class ArchiveBomb(SecurityError):
    """A configured archive resource limit was exceeded."""

    def __init__(self, limit: str, limit_value: int, observed: int) -> None:
        super().__init__(f"archive limit {limit} exceeded: {observed} > {limit_value}")
        self.limit = limit
        self.limit_value = limit_value
        self.observed = observed


class ExtractionError(OxarError, OSError):
    """An entry could not be committed to the destination."""


class OxarIOError(OxarError, OSError):
    """An operating system or file-like object operation failed."""


class Cancelled(OxarError):
    """The operation was cancelled through its cancellation token."""


class OxarWarning(UserWarning):
    """A non-fatal issue occurred during an archive operation."""


class EntryKind(Enum):
    """Kind of an archive entry."""

    FILE = "file"
    DIR = "dir"
    SYMLINK = "symlink"
    HARDLINK = "hardlink"
    OTHER = "other"


_ENTRY_KINDS = {kind.value: kind for kind in EntryKind}


@dataclass(frozen=True, slots=True)
class Entry:
    """Immutable metadata for one archive member."""

    path: str
    path_bytes: bytes
    kind: EntryKind
    size: int | None = None
    compressed_size: int | None = None
    mode: int | None = None
    uid: int | None = None
    gid: int | None = None
    uname: str | None = None
    gname: str | None = None
    mtime: datetime | None = None
    mtime_ns: int | None = None
    crc32: int | None = None
    link_target: str | None = None
    encrypted: bool = False
    method: str | None = None
    comment: str | None = None

    def is_file(self) -> bool:
        """Return whether this entry is a regular file."""
        return self.kind is EntryKind.FILE

    def is_dir(self) -> bool:
        """Return whether this entry is a directory."""
        return self.kind is EntryKind.DIR

    def is_symlink(self) -> bool:
        """Return whether this entry is a symbolic link."""
        return self.kind is EntryKind.SYMLINK

    def is_hardlink(self) -> bool:
        """Return whether this entry is a hard link."""
        return self.kind is EntryKind.HARDLINK


@dataclass(frozen=True, slots=True)
class Skipped:
    """An entry omitted by extraction policy."""

    path: str
    reason: str


@dataclass(frozen=True, slots=True)
class ExtractReport:
    """Summary of an extraction call."""

    entries: int
    bytes_written: int
    skipped: list[Skipped] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    elapsed: float = 0.0


@dataclass(frozen=True, slots=True)
class CreateReport:
    """Summary of an archive creation call."""

    entries: int
    bytes_in: int
    bytes_out: int
    elapsed: float


@dataclass(frozen=True, slots=True)
class ConvertReport:
    """Summary of a conversion call."""

    entries: int
    bytes_in: int
    bytes_out: int
    recompressed: int
    copied_raw: int
    elapsed: float


@dataclass(frozen=True, slots=True)
class Problem:
    """An integrity problem found by :func:`test`."""

    path: str
    kind: str
    detail: str
    offset: int | None = None


@dataclass(frozen=True, slots=True)
class TestReport:
    """Summary of archive integrity checking."""

    ok: bool
    entries: int
    bytes_checked: int
    problems: list[Problem] = field(default_factory=list)
    elapsed: float = 0.0


@dataclass(frozen=True, slots=True)
class Detection:
    """Result of content-based format detection."""

    format: str | None
    compression: str | None
    codec: str | None
    confidence: str


@dataclass(frozen=True, slots=True)
class ProgressEvent:
    """Progress snapshot emitted by a long-running operation."""

    kind: str
    path: str | None = None
    entries_done: int = 0
    entries_total: int | None = None
    bytes_done: int = 0
    bytes_total: int | None = None


class CancelToken:
    """Thread-safe cancellation signal for a long-running operation."""

    def __init__(self) -> None:
        from ._oxar import _NativeCancelToken

        self._native = _NativeCancelToken()

    def cancel(self) -> None:
        """Request cancellation."""
        self._native.cancel()

    @property
    def cancelled(self) -> bool:
        """Whether cancellation has been requested."""
        return self._native.cancelled


_DEFAULTS: dict[str, Any] = {
    "symlinks": "contained",
    "hardlinks": "contained",
    "special_files": "reject",
    "modes": "safe",
    "allow_setid": False,
    "overwrite": "error",
    "duplicates": "auto",
    "windows_names": "auto",
    "preserve_mtime": True,
    "cleanup_on_error": True,
    "strict": True,
    "allow_streaming_zip": False,
    "follow_existing_symlinks": False,
    "create_dest": True,
    "durable": False,
    "max_entries": 1_000_000,
    "max_entry_size": 8 * 2**30,
    "max_total_size": 32 * 2**30,
    "max_ratio": 1000,
    "ratio_floor": 64 * 2**20,
    "max_path_bytes": 4096,
    "max_component_bytes": 255,
    "max_depth": 128,
    "max_decoder_memory": 512 * 2**20,
    "max_pax_header_bytes": 2**20,
    "max_extra_bytes": 65535,
    "max_sparse_regions": 100_000,
    "max_solid_block_bytes": 2**30,
}
_ALLOWED = {
    "symlinks": {"contained", "skip", "reject"},
    "hardlinks": {"contained", "skip", "reject"},
    "special_files": {"reject", "skip"},
    "modes": {"safe", "none", "preserve"},
    "overwrite": {"error", "skip", "replace", "newer"},
    "duplicates": {"auto", "reject", "last", "first"},
    "windows_names": {"auto", "reject", "allow"},
}


class Policy:
    """Immutable extraction limits and filesystem handling rules."""

    __slots__ = ("_values",)

    def __init__(self, **changes: Any) -> None:
        unknown = changes.keys() - _DEFAULTS.keys()
        if unknown:
            raise UsageError(f"unknown policy fields: {', '.join(sorted(unknown))}")
        values = dict(_DEFAULTS)
        values.update(changes)
        for name, allowed in _ALLOWED.items():
            if values[name] not in allowed:
                raise UsageError(f"invalid {name}: expected one of {', '.join(sorted(allowed))}")
        bool_fields = {
            "allow_setid",
            "preserve_mtime",
            "cleanup_on_error",
            "strict",
            "allow_streaming_zip",
            "follow_existing_symlinks",
            "create_dest",
            "durable",
        }
        for name in bool_fields:
            if not isinstance(values[name], bool):
                raise UsageError(f"{name} must be a bool")
        for name, value in values.items():
            if (
                name.startswith("max_")
                and value is not None
                and (not isinstance(value, int) or isinstance(value, bool) or value < 0)
            ):
                raise UsageError(f"{name} must be a non-negative integer or None")
            if name.startswith("max_") and isinstance(value, int):
                maximum = (1 << (struct.calcsize("P") * 8)) - 1
                if value > maximum:
                    raise UsageError(f"{name} exceeds the platform integer range")
        if (
            not isinstance(values["ratio_floor"], int)
            or isinstance(values["ratio_floor"], bool)
            or values["ratio_floor"] < 0
            or values["ratio_floor"] > (1 << 64) - 1
        ):
            raise UsageError("ratio_floor must be a non-negative integer")
        self._values = MappingProxyType(values)

    @staticmethod
    def default() -> Policy:
        """Return a policy with the secure defaults."""
        return _DEFAULT_POLICY

    def replace(self, **changes: Any) -> Policy:
        """Return a validated copy with selected values changed."""
        return Policy(**(self._values | changes))

    def __getattr__(self, name: str) -> Any:
        try:
            return self._values[name]
        except KeyError as error:
            raise AttributeError(name) from error

    def __repr__(self) -> str:
        values = ", ".join(f"{key}={value!r}" for key, value in self._values.items())
        return f"Policy({values})"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Policy) and self._values == other._values


_DEFAULT_POLICY = Policy()


def entry_from_native(value: tuple[Any, ...] | dict[str, Any]) -> Entry:
    """Convert extension metadata to its public type."""
    if isinstance(value, tuple):
        (
            path,
            path_bytes,
            kind_value,
            size,
            compressed_size,
            mode,
            uid,
            gid,
            uname,
            gname,
            stamp_ns,
            crc32,
            link_target,
            encrypted,
            method,
            comment,
        ) = value
        kind = _ENTRY_KINDS[kind_value]
        stamp = None
        if stamp_ns is not None:
            stamp_ns = int(stamp_ns)
            stamp = datetime.fromtimestamp(stamp_ns / 1_000_000_000, UTC)
        return Entry(
            path,
            path_bytes,
            kind,
            size,
            compressed_size,
            mode,
            uid,
            gid,
            uname,
            gname,
            stamp,
            stamp_ns,
            crc32,
            link_target,
            encrypted,
            method,
            comment,
        )
    kind = EntryKind(value.get("kind", "file"))
    stamp_ns = value.get("mtime_ns")
    if stamp_ns is not None:
        stamp_ns = int(stamp_ns)
    stamp = None if stamp_ns is None else datetime.fromtimestamp(stamp_ns / 1_000_000_000, UTC)
    return Entry(
        path=value["path"],
        path_bytes=value.get("path_bytes", value["path"].encode()),
        kind=kind,
        size=value.get("size"),
        compressed_size=value.get("compressed_size"),
        mode=value.get("mode"),
        uid=value.get("uid"),
        gid=value.get("gid"),
        uname=value.get("uname"),
        gname=value.get("gname"),
        mtime=stamp,
        mtime_ns=stamp_ns,
        crc32=value.get("crc32"),
        link_target=value.get("link_target"),
        encrypted=value.get("encrypted", False),
        method=value.get("method"),
        comment=value.get("comment"),
    )
