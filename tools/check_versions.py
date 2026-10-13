#!/usr/bin/env python3
"""Compare the versions pinned in this repository against the live registries.

Fetches the crates.io API (max_stable_version, which accounts for backport
releases to older major lines that the sparse index would list last) and the
PyPI JSON API. Reports drift from the pinned set.
Run before changing manifests; see docs/DECISIONS.md for the bump policy.
"""

from __future__ import annotations

import json
import sys
import urllib.request

CRATES_API = "https://crates.io/api/v1/crates/{name}"
PYPI_JSON = "https://pypi.org/pypi/{name}/json"
USER_AGENT = "oxar-version-check (https://github.com/programmersd21/oxar)"

# crate name -> version pinned in workspace Cargo.toml
CRATES: dict[str, str] = {
    "thiserror": "2.0.21",
    "rayon": "1.12.0",
    "crc32fast": "1.5.2",
    "cap-std": "4.0.3",
    "zip": "9.0.5",
    "tar": "0.4.46",
    "sevenz-rust2": "0.24.1",
    "lzma-rust2": "0.23.0",
    "flate2": "1.1.10",
    "bzip2": "0.6.1",
    "liblzma": "0.4.8",
    "zstd": "0.14.3",
    "lz4_flex": "0.14.0",
    "brotli": "9.0.0",
    "snap": "1.1.2",
    "zeroize": "1.9.1",
    "unicode-normalization": "0.1.26",
    "bitflags": "2.13.2",
    "proptest": "1.12.0",
    "criterion": "0.8.2",
    "libfuzzer-sys": "0.4.13",
    "arbitrary": "1.5.0",
    "tempfile": "3.27.0",
    "pyo3": "0.30.1",
}

# PyPI package -> version pinned in pyproject.toml
PYPI: dict[str, str] = {
    "maturin": "1.15.0",
    "cibuildwheel": "4.3.1",
    "pytest": "9.1.1",
    "hypothesis": "6.170.1",
    "mypy": "2.4.0",
    "ruff": "0.17.1",
    "pytest-benchmark": "5.3.0",
    "auditwheel": "6.8.2",
    "delocate": "0.13.0",
}


def fetch_json(url: str) -> object:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    last_err: Exception | None = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=30) as resp:
                return json.load(resp)
        except Exception as exc:
            last_err = exc
            import time

            time.sleep(1.0 * (attempt + 1))
    if last_err is not None:
        raise last_err
    raise RuntimeError("unreachable")


def latest_crate(name: str) -> tuple[str, list[str]]:
    data = fetch_json(CRATES_API.format(name=name))
    assert isinstance(data, dict)
    crate = data["crate"]
    yanked = [
        v["num"]
        for v in data["versions"]
        if v["num"] == crate["max_stable_version"] and v["yanked"]
    ]
    return str(crate["max_stable_version"]), yanked


def latest_pypi(name: str) -> str:
    data = fetch_json(PYPI_JSON.format(name=name))
    assert isinstance(data, dict)
    return str(data["info"]["version"])


def main() -> int:
    drift = 0
    print("== crates.io ==")
    for name, pinned in sorted(CRATES.items()):
        try:
            newest, yanked_flag = latest_crate(name)
        except Exception as exc:
            print(f"{name:22} pinned={pinned:12} ERROR {exc}")
            drift += 1
            continue
        flag = "same" if newest == pinned else "DRIFT"
        if newest != pinned:
            drift += 1
        note = " YANKED" if yanked_flag else ""
        print(f"{name:22} pinned={pinned:12} newest={newest:12} {flag}{note}")
    print("== pypi.org ==")
    for name, pinned in sorted(PYPI.items()):
        try:
            newest = latest_pypi(name)
        except Exception as exc:
            print(f"{name:22} pinned={pinned:12} ERROR {exc}")
            drift += 1
            continue
        flag = "same" if newest == pinned else "DRIFT"
        if newest != pinned:
            drift += 1
        print(f"{name:22} pinned={pinned:12} newest={newest:12} {flag}")
    print(f"drift count: {drift}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
