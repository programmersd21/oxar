"""Asyncio wrappers for the synchronous oxar interface.

Calls run in worker threads. The current binding only permits path-based archive
sources, and callback coroutine dispatch is not part of this version.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import Any, cast

import oxar

from ._models import CancelToken, Entry


async def _run(function: Any, *args: Any, **kwargs: Any) -> Any:
    """Run a synchronous function in a worker thread and signal cancellation."""
    token = kwargs.setdefault("cancel", CancelToken())
    task = asyncio.create_task(asyncio.to_thread(function, *args, **kwargs))
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError:
        token.cancel()
        try:
            await asyncio.shield(task)
        except Exception:
            raise asyncio.CancelledError from None
        raise


async def acompress(
    data: bytes | bytearray | memoryview,
    codec: oxar.CodecName,
    *,
    level: int | None = None,
    threads: int | None = None,
    **options: Any,
) -> bytes:
    """Compress bytes in a worker thread."""
    return await asyncio.to_thread(
        oxar.compress, data, codec, level=level, threads=threads, **options
    )


async def adecompress(
    data: bytes | bytearray | memoryview,
    codec: oxar.CodecName | None = None,
    *,
    max_size: int | None = None,
) -> bytes:
    """Decompress bytes in a worker thread."""
    return await asyncio.to_thread(oxar.decompress, data, codec=codec, max_size=max_size)


async def alist(source: oxar.Source, **options: Any) -> list[Entry]:
    """List archive entries in a worker thread."""
    return await asyncio.to_thread(oxar.list, source, **options)


async def aextract(source: oxar.Source, dest: oxar.PathLike, **options: Any) -> oxar.ExtractReport:
    """Extract an archive in a worker thread."""
    return cast(oxar.ExtractReport, await _run(oxar.extract, source, dest, **options))


async def adetect(source: oxar.Source | bytes | bytearray | memoryview) -> oxar.Detection:
    """Detect an archive or codec in a worker thread."""
    return await asyncio.to_thread(oxar.detect, source)


class AArchive:
    """Async context manager around an archive view."""

    def __init__(self, source: oxar.Source, mode: str = "r", **options: Any) -> None:
        self._source = source
        self._mode = mode
        self._options = options
        self._archive: oxar.Archive | None = None

    async def __aenter__(self) -> AArchive:
        """Open the synchronous archive in a worker thread."""
        self._archive = await asyncio.to_thread(
            oxar.open, self._source, self._mode, **self._options
        )
        return self

    async def __aexit__(self, *_: object) -> None:
        """Close the wrapped archive."""
        if self._archive is not None:
            self._archive.close()
            self._archive = None

    def _require_open(self) -> oxar.Archive:
        if self._archive is None:
            raise ValueError("async archive is not open")
        return self._archive

    def __aiter__(self) -> AsyncIterator[Entry]:
        """Iterate over entry metadata asynchronously."""

        async def entries() -> AsyncIterator[Entry]:
            for entry in await asyncio.to_thread(self._require_open().entries):
                yield entry

        return entries()

    async def read(self, name: str | Entry, *, max_size: int | None = None) -> bytes:
        """Read one archive member in a worker thread."""
        archive = self._require_open()
        return await asyncio.to_thread(archive.read, name, max_size=max_size)

    async def extract(self, dest: oxar.PathLike, **options: Any) -> oxar.ExtractReport:
        """Extract the archive in a worker thread."""
        archive = self._require_open()
        return cast(oxar.ExtractReport, await _run(archive.extract, dest, **options))

    async def test(self, **options: Any) -> oxar.TestReport:
        """Check archive integrity in a worker thread."""
        archive = self._require_open()
        return await asyncio.to_thread(archive.test, **options)


async def aopen(source: oxar.Source, mode: str = "r", **options: Any) -> AArchive:
    """Return an async archive context manager."""
    return AArchive(source, mode, **options)


async def acreate(*args: Any, **kwargs: Any) -> oxar.CreateReport:
    """Create an archive in a worker thread."""
    return await asyncio.to_thread(oxar.create, *args, **kwargs)


async def atest(source: oxar.Source, **options: Any) -> oxar.TestReport:
    """Check an archive in a worker thread."""
    return await asyncio.to_thread(oxar.test, source, **options)


async def aconvert(source: oxar.Source, dest: oxar.Sink, **options: Any) -> oxar.ConvertReport:
    """Convert an archive in a worker thread."""
    return cast(oxar.ConvertReport, await _run(oxar.convert, source, dest, **options))


__all__ = [
    "AArchive",
    "acompress",
    "aconvert",
    "acreate",
    "adecompress",
    "adetect",
    "aextract",
    "alist",
    "aopen",
    "atest",
]
