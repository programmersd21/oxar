#!/usr/bin/env python3
"""Run local archive and codec measurements and save raw samples as JSON."""

from __future__ import annotations

import argparse
import bz2
import gzip
import hashlib
import importlib
import json
import lzma
import os
import platform
import random
import re
import statistics
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile
import zlib
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# Benchmark the checkout under test, even when a different oxar wheel is
# installed in the active environment.
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))

oxar = importlib.import_module("oxar")
try:
    stdlib_zstd: Any | None = importlib.import_module("compression.zstd")
except ImportError:
    stdlib_zstd = None


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def timed_pair(
    first_name: str,
    first: Callable[[], Any],
    second_name: str,
    second: Callable[[], Any],
    repeats: int,
    first_output_bytes: int | None = None,
    second_output_bytes: int | None = None,
) -> list[dict[str, Any]]:
    first()
    second()
    samples: dict[str, list[float]] = {first_name: [], second_name: []}
    operations = ((first_name, first), (second_name, second))
    for index in range(repeats):
        ordered = operations if index % 2 == 0 else operations[::-1]
        for name, operation in ordered:
            started = time.perf_counter()
            operation()
            samples[name].append(time.perf_counter() - started)

    outputs = {
        first_name: first_output_bytes,
        second_name: second_output_bytes,
    }
    results = []
    for name in (first_name, second_name):
        values = samples[name]
        median = statistics.median(values)
        print(f"{name}: median {median:.6f}s across {repeats} paired runs", flush=True)
        results.append(
            {
                "name": name,
                "seconds": values,
                "median_seconds": median,
                "iqr_seconds": percentile(values, 0.75) - percentile(values, 0.25),
                "output_bytes": outputs[name],
            }
        )
    return results


def payload(index: int, size: int) -> bytes:
    rng = random.Random(index)
    block = bytearray(rng.randbytes(size))
    if index % 2 == 0:
        seed = f"oxar benchmark record {index:08d} ".encode()
        block = bytearray((seed * (size // len(seed) + 1))[:size])
    return bytes(block)


def make_fixtures(
    directory: Path, entries: int, size: int
) -> tuple[Path, Path, list[tuple[str, bytes]]]:
    records = [(f"tree/file-{i:06d}.bin", payload(i, size)) for i in range(entries)]
    zip_path = directory / "sample.zip"
    tar_path = directory / "sample.tar.gz"
    with zipfile.ZipFile(
        zip_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6
    ) as archive:
        for name, data in records:
            archive.writestr(name, data)
    with tarfile.open(tar_path, "w:gz", compresslevel=6) as archive:
        for name, data in records:
            import io

            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = 0
            archive.addfile(info, io.BytesIO(data))
    return zip_path, tar_path, records


def archive_benchmarks(
    path: Path, records: list[tuple[str, bytes]], repeats: int, fmt: str
) -> list[dict[str, Any]]:
    names = [name for name, _ in records]
    middle = names[len(names) // 2] if names else None
    results = []
    if fmt == "zip":
        with zipfile.ZipFile(path) as archive:
            expected = archive.getinfo(middle).file_size if middle else 0

        def stdlib_list() -> Any:
            with zipfile.ZipFile(path) as archive:
                return archive.infolist()

        def oxar_list() -> Any:
            return oxar.list(path)

        def oxar_read() -> bytes:
            with oxar.open(path) as archive:
                return archive.read(middle, max_size=expected) if middle else b""

        results.extend(
            timed_pair("oxar.zip.list", oxar_list, "stdlib.zip.list", stdlib_list, repeats)
        )
        results.extend(
            timed_pair(
                "oxar.zip.read_middle",
                oxar_read,
                "stdlib.zip.read_middle",
                lambda: read_zip_member(path, middle),
                repeats,
                expected,
                expected,
            )
        )

        def stdlib_extract() -> None:
            with tempfile.TemporaryDirectory() as target, zipfile.ZipFile(path) as archive:
                archive.extractall(target)

        def oxar_extract() -> None:
            with tempfile.TemporaryDirectory() as target:
                oxar.extract(path, target)

        results.extend(
            timed_pair(
                "oxar.zip.extract", oxar_extract, "stdlib.zip.extract", stdlib_extract, repeats
            )
        )
    else:
        tar_archive = tarfile.open(path, "r:gz")  # noqa: SIM115
        try:
            expected = tar_archive.getmember(middle).size if middle else 0
        finally:
            tar_archive.close()

        def stdlib_list() -> Any:
            with tarfile.open(path, "r:gz") as archive:
                return archive.getmembers()

        def oxar_list() -> Any:
            return oxar.list(path)

        def oxar_read() -> bytes:
            with oxar.open(path) as archive:
                return archive.read(middle, max_size=expected) if middle else b""

        results.extend(
            timed_pair("oxar.tar_gz.list", oxar_list, "stdlib.tar_gz.list", stdlib_list, repeats)
        )
        results.extend(
            timed_pair(
                "oxar.tar_gz.read_middle",
                oxar_read,
                "stdlib.tar_gz.read_middle",
                lambda: read_tar_member(path, middle),
                repeats,
                expected,
                expected,
            )
        )

        def stdlib_extract() -> None:
            with tempfile.TemporaryDirectory() as target, tarfile.open(path, "r:gz") as archive:
                # The fixture names and contents are generated by this script.
                archive.extractall(target)

        def oxar_extract() -> None:
            with tempfile.TemporaryDirectory() as target:
                oxar.extract(path, target)

        results.extend(
            timed_pair(
                "oxar.tar_gz.extract",
                oxar_extract,
                "stdlib.tar_gz.extract",
                stdlib_extract,
                repeats,
            )
        )
    return results


def read_zip_member(path: Path, name: str | None) -> bytes:
    if name is None:
        return b""
    with zipfile.ZipFile(path) as archive:
        return archive.read(name)


def read_tar_member(path: Path, name: str | None) -> bytes:
    if name is None:
        return b""
    with tarfile.open(path, "r:gz") as archive:
        stream = archive.extractfile(name)
        return b"" if stream is None else stream.read()


def codec_benchmarks(repeats: int, size: int) -> list[dict[str, Any]]:
    cases: list[tuple[str, Callable[[bytes], bytes], Callable[[bytes], bytes]]] = [
        (
            "gzip",
            lambda b: oxar.compress(b, "gzip", level=6),
            lambda b: gzip.compress(b, compresslevel=6, mtime=0),
        ),
        (
            "bzip2",
            lambda b: oxar.compress(b, "bzip2", level=9),
            lambda b: bz2.compress(b, compresslevel=9),
        ),
        ("xz", lambda b: oxar.compress(b, "xz", level=6), lambda b: lzma.compress(b, preset=6)),
    ]
    decoders = {"gzip": gzip.decompress, "bzip2": bz2.decompress, "xz": lzma.decompress}
    if stdlib_zstd is not None:
        cases.append(
            (
                "zstd",
                lambda b: oxar.compress(b, "zstd", level=3, threads=1),
                lambda b: stdlib_zstd.compress(b, level=3),
            )
        )
        decoders["zstd"] = stdlib_zstd.decompress
    results = []
    for data_kind, data in (("compressible", payload(16, size)), ("random", payload(17, size))):
        for name, oxar_encode, stdlib_encode in cases:
            oxar_frame = oxar_encode(data)
            stdlib_frame = stdlib_encode(data)
            results.extend(
                timed_pair(
                    f"oxar.codec.{name}.{data_kind}.compress",
                    lambda f=oxar_encode, source=data: f(source),  # type: ignore[misc]
                    f"stdlib.codec.{name}.{data_kind}.compress",
                    lambda f=stdlib_encode, source=data: f(source),  # type: ignore[misc]
                    repeats,
                    len(oxar_frame),
                    len(stdlib_frame),
                )
            )
            results.extend(
                timed_pair(
                    f"oxar.codec.{name}.{data_kind}.decompress",
                    lambda f=oxar_frame, c=name: oxar.decompress(f, c, max_size=size),  # type: ignore[misc]
                    f"stdlib.codec.{name}.{data_kind}.decompress",
                    lambda f=stdlib_frame, d=decoders[name]: d(f),  # type: ignore[misc]
                    repeats,
                    size,
                    size,
                )
            )
    return results


def machine() -> dict[str, Any]:
    cpu = platform.processor() or platform.machine()
    cpuinfo_path = Path("/proc/cpuinfo")
    if cpuinfo_path.exists():
        match = re.search(r"^model name\s*: (.+)$", cpuinfo_path.read_text(), re.MULTILINE)
        if match:
            cpu = match.group(1).strip()
    memory_bytes = None
    meminfo_path = Path("/proc/meminfo")
    if meminfo_path.exists():
        match = re.search(r"^MemTotal:\s+(\d+) kB$", meminfo_path.read_text(), re.MULTILINE)
        if match:
            memory_bytes = int(match.group(1)) * 1024
    rust = subprocess.run(["rustc", "--version"], capture_output=True, text=True, check=False)
    dirty = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    revision = subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return {
        "platform": platform.platform(),
        "machine": platform.machine(),
        "cpu": cpu,
        "logical_cpus": os.cpu_count(),
        "memory_bytes": memory_bytes,
        "python": sys.version,
        "rustc": rust.stdout.strip() if rust.returncode == 0 else None,
        "git_revision": revision.stdout.strip() if revision.returncode == 0 else None,
        "git_dirty": bool(dirty.stdout.strip()) if dirty.returncode == 0 else None,
        "oxar": oxar.__version__,
        "stdlib_codecs": {
            "zlib_runtime": zlib.ZLIB_RUNTIME_VERSION,
            "lzma_module": getattr(lzma, "__file__", None),
            "bz2_module": getattr(bz2, "__file__", None),
            "zstd_module": getattr(stdlib_zstd, "__file__", None),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--entries", type=int, default=250)
    parser.add_argument("--bytes-per-entry", type=int, default=4096)
    parser.add_argument("--codec-bytes", type=int, default=256 * 1024)
    parser.add_argument("--repeats", type=int, default=7)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "bench" / "results")
    args = parser.parse_args()
    if args.entries < 1 or args.bytes_per_entry < 1 or args.codec_bytes < 1 or args.repeats < 7:
        parser.error("sizes and entry count must be positive; repeats must be at least 7")

    with tempfile.TemporaryDirectory(prefix="oxar-bench-") as temp:
        work = Path(temp)
        zip_path, tar_path, records = make_fixtures(work, args.entries, args.bytes_per_entry)
        results = archive_benchmarks(zip_path, records, args.repeats, "zip")
        results.extend(archive_benchmarks(tar_path, records, args.repeats, "tar"))
        results.extend(codec_benchmarks(args.repeats, args.codec_bytes))
        input_hash = hashlib.sha256(b"".join(data for _, data in records)).hexdigest()
        document = {
            "date_utc": datetime.now(UTC).isoformat(),
            "machine": machine(),
            "method": "warm-cache repeated local run; archive generation excluded from timed samples",
            "workload": {
                "entries": args.entries,
                "bytes_per_entry": args.bytes_per_entry,
                "codec_bytes": args.codec_bytes,
                "repeats": args.repeats,
                "payload_sha256": input_hash,
                "zip_bytes": zip_path.stat().st_size,
                "tar_gz_bytes": tar_path.stat().st_size,
            },
            "results": results,
        }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y-%m-%d-%H%M%S-%f")
    machine_name = platform.node().lower().replace(" ", "-") or platform.machine()
    output = args.output_dir / f"{stamp}-{machine_name}.json"
    output.write_text(json.dumps(document, indent=2) + "\n")
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
