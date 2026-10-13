#!/usr/bin/env python3
"""Run a fresh local benchmark and regenerate the Markdown summary."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--entries", type=int, default=250)
    parser.add_argument("--bytes-per-entry", type=int, default=4096)
    parser.add_argument("--codec-bytes", type=int, default=256 * 1024)
    parser.add_argument("--repeats", type=int, default=7)
    args = parser.parse_args()

    run_command = [
        sys.executable,
        str(ROOT / "bench" / "run.py"),
        "--entries",
        str(args.entries),
        "--bytes-per-entry",
        str(args.bytes_per_entry),
        "--codec-bytes",
        str(args.codec_bytes),
        "--repeats",
        str(args.repeats),
    ]
    subprocess.run(run_command, cwd=ROOT, check=True)
    subprocess.run(
        [
            sys.executable,
            str(ROOT / "bench" / "report.py"),
        ],
        cwd=ROOT,
        check=True,
    )
    print(ROOT / "docs" / "benchmarks.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
