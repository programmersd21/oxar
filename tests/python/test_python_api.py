from __future__ import annotations

import io
import os
import tarfile
import threading
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Literal

import oxar
import pytest


def make_zip(path: Path) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("folder/hello.txt", b"hello from zip")
        archive.writestr("empty", b"")


def make_tar(path: Path) -> None:
    with tarfile.open(path, "w") as archive:
        info = tarfile.TarInfo("folder/hello.txt")
        info.size = len(b"hello from tar")
        archive.addfile(info, io.BytesIO(b"hello from tar"))


@pytest.mark.parametrize(
    ("factory", "extension", "payload"),
    [
        (make_zip, ".zip", b"hello from zip"),
        (make_tar, ".tar", b"hello from tar"),
    ],
)
def test_archive_read_list_extract_and_integrity(
    tmp_path: Path, factory: Callable[[Path], None], extension: str, payload: bytes
) -> None:
    source = tmp_path / f"sample{extension}"
    factory(source)

    detection = oxar.detect(source)
    assert detection.format in {"zip", "tar"}
    entries = oxar.list(source)
    assert any(entry.path == "folder/hello.txt" for entry in entries)
    assert oxar.test(source).ok

    with oxar.open(source) as archive:
        assert "folder/hello.txt" in archive
        assert archive.read("folder/hello.txt") == payload
        assert archive.open_entry("folder/hello.txt").read() == payload

    destination = tmp_path / "extracted"
    report = oxar.extract(source, destination)
    assert report.entries == len(entries)
    assert (destination / "folder" / "hello.txt").read_bytes() == payload


@pytest.mark.parametrize(
    ("factory", "extension", "payload"),
    [
        (make_zip, ".zip", b"hello from zip"),
        (make_tar, ".tar", b"hello from tar"),
    ],
)
def test_extract_selected_members(
    tmp_path: Path,
    factory: Callable[[Path], None],
    extension: str,
    payload: bytes,
) -> None:
    source = tmp_path / f"selected{extension}"
    factory(source)
    destination = tmp_path / "selected"

    report = oxar.extract(source, destination, members=["folder/hello.txt"])

    assert report.entries == 1
    assert (destination / "folder" / "hello.txt").read_bytes() == payload
    if extension == ".zip":
        assert not (destination / "empty").exists()


def test_extract_uses_policy_overwrite_and_limits(tmp_path: Path) -> None:
    source = tmp_path / "policy.zip"
    make_zip(source)
    destination = tmp_path / "policy-dest"
    (destination / "folder").mkdir(parents=True)
    target = destination / "folder" / "hello.txt"
    target.write_bytes(b"old")

    with pytest.raises(OSError):
        oxar.extract(source, destination)

    policy = oxar.Policy(overwrite="replace")
    report = oxar.extract(source, destination, policy=policy)

    assert report.entries == 2
    assert target.read_bytes() == b"hello from zip"

    target.write_bytes(b"keep")
    (destination / "empty").unlink()
    skipped = oxar.extract(source, destination, policy=oxar.Policy(overwrite="skip"))
    assert target.read_bytes() == b"keep"
    assert [(item.path, item.reason) for item in skipped.skipped] == [
        ("folder/hello.txt", "exists")
    ]

    limited = oxar.Policy(max_entry_size=3)
    with pytest.raises(OSError):
        oxar.extract(source, tmp_path / "limited", policy=limited)


def test_convert_zip_and_tar_streams_entries_between_formats(tmp_path: Path) -> None:
    source_zip = tmp_path / "source.zip"
    make_zip(source_zip)
    converted_tar = tmp_path / "converted.tar"

    tar_report = oxar.convert(source_zip, converted_tar, format="tar")

    assert tar_report.entries == 2
    assert tar_report.recompressed == 2
    with tarfile.open(converted_tar) as archive:
        restored = archive.extractfile("folder/hello.txt")
        assert restored is not None
        assert restored.read() == b"hello from zip"

    converted_zip = tmp_path / "converted.zip"
    zip_report = oxar.convert(converted_tar, converted_zip, format="zip")

    assert zip_report.entries == 2
    with zipfile.ZipFile(converted_zip) as archive:
        assert archive.read("folder/hello.txt") == b"hello from zip"
        assert archive.read("empty") == b""


def test_convert_rejects_unsafe_names_without_committing_output(tmp_path: Path) -> None:
    source = tmp_path / "unsafe.tar"
    with tarfile.open(source, "w") as archive:
        info = tarfile.TarInfo("../outside.txt")
        info.size = 4
        archive.addfile(info, io.BytesIO(b"evil"))
    destination = tmp_path / "converted.zip"

    with pytest.raises(OSError):
        oxar.convert(source, destination, format="zip")

    assert not destination.exists()
    assert not (tmp_path.parent / "outside.txt").exists()
    assert not list(tmp_path.glob(".*.part"))


def test_convert_rejects_unsafe_links_and_over_limit_entries(tmp_path: Path) -> None:
    unsafe_link = tmp_path / "unsafe-link.tar"
    with tarfile.open(unsafe_link, "w") as archive:
        info = tarfile.TarInfo("link")
        info.type = tarfile.SYMTYPE
        info.linkname = "../outside"
        archive.addfile(info)
    link_output = tmp_path / "link.zip"

    with pytest.raises(OSError):
        oxar.convert(unsafe_link, link_output, format="zip")
    assert not link_output.exists()
    assert not list(tmp_path.glob(".*.part"))

    source = tmp_path / "limited.zip"
    make_zip(source)
    limited_output = tmp_path / "limited.tar"
    with pytest.raises(OSError):
        oxar.convert(
            source,
            limited_output,
            format="tar",
            policy=oxar.Policy(max_entry_size=3),
        )
    assert not limited_output.exists()
    assert not list(tmp_path.glob(".*.part"))


def test_convert_compressed_tar_streams_entries_between_formats(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.tar.gz"
    with tarfile.open(source, "w:gz") as archive:
        info = tarfile.TarInfo("data.txt")
        info.size = 4
        archive.addfile(info, io.BytesIO(b"data"))

    report = oxar.convert(source, tmp_path / "output.zip", format="zip")
    assert report.entries == 1
    with zipfile.ZipFile(tmp_path / "output.zip") as archive:
        assert archive.read("data.txt") == b"data"


def test_extraction_releases_the_gil(tmp_path: Path) -> None:
    source = tmp_path / "gil.zip"
    payload = os.urandom(12 * 1024 * 1024)
    with zipfile.ZipFile(source, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("payload.bin", payload)

    done = threading.Event()
    failures: list[Exception] = []

    def extract_archive() -> None:
        try:
            oxar.extract(source, tmp_path / "gil-output")
        except Exception as error:
            failures.append(error)
        finally:
            done.set()

    worker = threading.Thread(target=extract_archive)
    worker.start()
    ticks = 0
    while not done.is_set():
        ticks += 1
    worker.join()

    assert not failures
    assert ticks > 100
    assert (tmp_path / "gil-output" / "payload.bin").stat().st_size == len(payload)


def test_extraction_cancellation_reaches_rust(tmp_path: Path) -> None:
    source = tmp_path / "cancel.zip"
    payload = os.urandom(128 * 1024 * 1024)
    with zipfile.ZipFile(source, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("payload.bin", payload)

    token = oxar.CancelToken()
    failures: list[Exception] = []

    def extract_archive() -> None:
        try:
            oxar.extract(source, tmp_path / "cancel-output", cancel=token)
        except Exception as error:
            failures.append(error)

    worker = threading.Thread(target=extract_archive)
    worker.start()
    token.cancel()
    worker.join(timeout=5)

    assert not worker.is_alive()
    assert len(failures) == 1
    assert isinstance(failures[0], oxar.Cancelled)


def test_archive_creation_releases_the_gil(tmp_path: Path) -> None:
    source = tmp_path / "input.bin"
    source.write_bytes(os.urandom(8 * 1024 * 1024))

    done = threading.Event()
    failures: list[Exception] = []

    def create_archive() -> None:
        try:
            oxar.create(tmp_path / "created.zip", [source])
        except Exception as error:
            failures.append(error)
        finally:
            done.set()

    worker = threading.Thread(target=create_archive)
    worker.start()
    ticks = 0
    while not done.is_set():
        ticks += 1
    worker.join()

    assert not failures
    assert ticks > 100
    assert (tmp_path / "created.zip").is_file()


def test_file_like_archive_sources_and_short_reads(tmp_path: Path) -> None:
    source = io.BytesIO()
    make_zip_from_stream = zipfile.ZipFile(source, "w", compression=zipfile.ZIP_DEFLATED)
    make_zip_from_stream.writestr("data.txt", b"file-like archive source")
    make_zip_from_stream.close()
    encoded = source.getvalue()

    class ShortReader(io.BytesIO):
        def read(self, size: int | None = -1) -> bytes:
            if size is None:
                return super().read()
            return super().read(min(size, 3) if size >= 0 else size)

    assert oxar.detect(io.BytesIO(encoded)).format == "zip"
    assert [entry.path for entry in oxar.list(ShortReader(encoded))] == ["data.txt"]
    with oxar.open(io.BytesIO(encoded)) as archive:
        assert archive.read("data.txt") == b"file-like archive source"
    destination = tmp_path / "restored"
    oxar.extract(ShortReader(encoded), destination)
    assert (destination / "data.txt").read_bytes() == b"file-like archive source"


def test_raw_codec_round_trip() -> None:
    original = b"archive data" * 100
    for codec in (
        "gzip",
        "zlib",
        "deflate",
        "bzip2",
        "xz",
        "lzma",
        "zstd",
        "lz4",
        "brotli",
        "snappy",
    ):
        compressed = oxar.compress(original, codec)
        assert oxar.decompress(compressed, codec) == original


def test_policy_is_immutable_by_copy() -> None:
    policy = oxar.Policy.default()
    stricter = policy.replace(max_entries=3)
    assert policy.max_entries == 1_000_000
    assert stricter.max_entries == 3
    with pytest.raises(oxar.UsageError):
        oxar.Policy(overwrite="append")
    with pytest.raises(oxar.UsageError):
        oxar.Policy(strict=1)
    with pytest.raises(oxar.UsageError):
        oxar.Policy(ratio_floor=True)


@pytest.mark.parametrize("format", ["zip", "tar"])
def test_create_from_file_and_directory(tmp_path: Path, format: Literal["zip", "tar"]) -> None:
    root = tmp_path / "input"
    root.mkdir()
    (root / "message.txt").write_bytes(b"created by oxar")
    destination = tmp_path / f"created.{format}"

    report = oxar.create(destination, [root], format=format)

    assert report.entries == 1
    assert report.bytes_in == len(b"created by oxar")
    assert destination.exists()
    with oxar.open(destination) as archive:
        assert archive.read("message.txt") == b"created by oxar"


def test_append_is_atomic_and_preserves_existing_entries(tmp_path: Path) -> None:
    existing = tmp_path / "existing.txt"
    appended = tmp_path / "appended.txt"
    existing.write_bytes(b"original")
    appended.write_bytes(b"added")
    archive_path = tmp_path / "archive.zip"
    oxar.create(archive_path, [existing])

    report = oxar.append(archive_path, [appended])

    assert report.entries == 1
    with oxar.open(archive_path) as archive:
        assert archive.read("existing.txt") == b"original"
        assert archive.read("appended.txt") == b"added"


def test_zip_update_replaces_and_delete_removes_entries(tmp_path: Path) -> None:
    first = tmp_path / "same.txt"
    first.write_bytes(b"before")
    added = tmp_path / "new.txt"
    added.write_bytes(b"new member")
    archive_path = tmp_path / "archive.zip"
    oxar.create(archive_path, [first])

    first.write_bytes(b"after")
    with oxar.open(archive_path, "r") as archive:
        archive.update([first, added])
        assert archive.read("same.txt") == b"after"
        assert archive.read("new.txt") == b"new member"
        archive.delete(["same.txt"])
        assert "same.txt" not in archive


def test_unsupported_api_is_explicit() -> None:
    with pytest.raises(oxar.UnsupportedFeature):
        oxar.open("archive.zip", mode="w")


@pytest.mark.interop
def test_sevenz_extraction_and_conversion(tmp_path: Path) -> None:
    import subprocess

    source_file = tmp_path / "sample.txt"
    source_file.write_bytes(b"hello from 7z")
    archive = tmp_path / "sample.7z"
    subprocess.run(["7z", "a", str(archive), str(source_file)], check=True, capture_output=True)

    assert [entry.path for entry in oxar.list(archive)] == ["sample.txt"]
    report = oxar.extract(archive, tmp_path / "extracted")
    assert report.entries == 1
    assert (tmp_path / "extracted" / "sample.txt").read_bytes() == b"hello from 7z"
    assert oxar.test(archive).ok

    converted = tmp_path / "converted.zip"
    conversion = oxar.convert(archive, converted, format="zip")
    assert conversion.entries == 1
    import zipfile

    with zipfile.ZipFile(converted) as result:
        assert result.read("sample.txt") == b"hello from 7z"
