#!/usr/bin/env python3
"""Repository style, completeness and pinning check.

Fails on: todo!/unimplemented! macros, TODO/FIXME/XXX/HACK markers,
NotImplementedError, `pass  #` placeholders, and U+2014/U+2013 in tracked
text files. Also checks that workflow action references are pinned to a full
commit SHA.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

SELF = Path(__file__).resolve()

BANNED_SUBSTRINGS = [
    "todo!(",
    "unimplemented!(",
    "NotImplementedError",
]

BANNED_WORDS = re.compile(r"\b(TODO|FIXME|XXX|HACK)\b")

ACTION_PIN = re.compile(r"uses:\s+([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)(?:@([^ \t#]+))?")
SHA = re.compile(r"^[0-9a-f]{40}$")

TEXT_SUFFIXES = {
    ".rs",
    ".py",
    ".pyi",
    ".toml",
    ".md",
    ".txt",
    ".yml",
    ".yaml",
    ".json",
    ".cfg",
    ".ini",
    ".sh",
    ".ps1",
    ".c",
    ".h",
}


EXCLUDED_DIRS = {
    ".git",
    "target",
    "dist",
    ".venv",
    "venv",
    "env",
    ".maturin",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "spikes",
    ".benchmarks",
}


def tracked_files() -> list[Path]:
    try:
        out = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
            capture_output=True,
            text=True,
            check=True,
        )
        return [Path(line) for line in out.stdout.splitlines() if line]
    except (subprocess.CalledProcessError, FileNotFoundError):
        root = Path(".")
        collected: list[Path] = []
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if any(part in EXCLUDED_DIRS for part in path.parts):
                continue
            collected.append(path)
        return collected


def is_text(path: Path) -> bool:
    try:
        data = path.read_bytes()
    except OSError:
        return False
    if b"\x00" in data[:8192]:
        return False
    return path.suffix in TEXT_SUFFIXES or path.name in {
        "LICENSE-MIT",
        "LICENSE-APACHE",
        "Cargo.lock",
        "NOTICE",
    }


def check_file(path: Path) -> list[str]:
    problems: list[str] = []
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return problems
    if path.resolve() == SELF:
        return problems
    lines = text.splitlines()
    for number, line in enumerate(lines, start=1):
        for needle in BANNED_SUBSTRINGS:
            if needle in line:
                problems.append(f"{path}:{number}: contains {needle!r}")
        if BANNED_WORDS.search(line):
            problems.append(f"{path}:{number}: contains a TODO/FIXME/XXX/HACK marker")
        if "pass  #" in line:
            problems.append(f"{path}:{number}: placeholder `pass  #`")
        if "\u2014" in line or "\u2013" in line:
            problems.append(f"{path}:{number}: contains an em dash or en dash")
    if path.name.endswith(".yml") or path.name.endswith(".yaml"):
        for number, line in enumerate(lines, start=1):
            match = ACTION_PIN.search(line)
            if match:
                ref = match.group(2)
                if ref is not None and not SHA.match(ref) and not ref.startswith("./"):
                    problems.append(f"{path}:{number}: action {match.group(1)} not pinned to a SHA")
    return problems


def main() -> int:
    problems: list[str] = []
    files = tracked_files()
    for path in files:
        if path.is_dir() or not is_text(path):
            continue
        problems.extend(check_file(path))
    if problems:
        for problem in problems:
            print(problem)
        print(f"{len(problems)} problem(s)")
        return 1
    print(f"checked {len(files)} tracked files, no problems")
    return 0


if __name__ == "__main__":
    sys.exit(main())
