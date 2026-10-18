# verification

record of commands run for this checkout. dates are 2026-10-18 unless noted.
results are separated into pass, fail, and unverified. unverified items include
the environmental reason and the exact command needed to close them.

## pass

| command | result | evidence |
|---|---|---|
| `cargo fmt --all --check` | pass | no formatting differences |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | pass | finished with no warnings |
| `cargo test --workspace --all-features` | pass | all workspace tests pass; tar interop tests generate fixtures portably |
| `cargo deny check` | pass | advisories, bans, licenses, and sources ok; two unmatched license allowances |
| `cargo audit` | pass | no vulnerabilities; one allowed yanked-crate warning for `inout 0.2.3` |
| `cargo doc --workspace --no-deps` | pass | documentation generated for both crates |
| `python -m pytest tests/python` | pass | 21 passed in 1.05s on cpython 3.14 |
| `python -m mypy --strict python/oxar tests/python` | pass | no issues in 7 source files |
| `python -m mypy.stubtest oxar --ignore-missing-stub` | pass | no issues in 6 modules |
| `python -m ruff check python tests/python` | pass | all checks passed |
| `python -m ruff format --check python tests/python` | pass | 7 files already formatted |
| `python tools/check_repository.py` | pass | all tracked files checked, no problems |
| `python tools/check_versions.py` | pass | drift count: 0 (all crates and python packages up to date and pinned) |
| cross-platform CI matrix | pass | 22/22 jobs passed on ubuntu-latest, macos-latest, and windows-latest across Python 3.11-3.15 and 3.14t |
| free-threaded import and stress | pass | cpython 3.14t wheel builds and imports; 8-thread stress run completed without errors |
| wheel build | pass | wheels built and verified across Linux, macOS, and Windows runners |
| sdist build | pass | `oxar-0.1.1.tar.gz` built |
| wheel linkage audit | pass | `auditwheel show` reports only system libraries |
| clean-environment wheel import | pass | installed wheel in a fresh venv and imported `oxar` |
| tar interop tests | pass | `reads_gnu_tar_plain`, `reads_gnu_tar_pax`, `gnu_tar_reads_what_we_write` pass across all 3 platforms |
| 7z interop tests | pass | `reads_sevenz_from_7z_binary`, `sevenz_roundtrip_geo` |

## fail

none. all 22 CI matrix jobs are passing cleanly.

## unverified

| item | reason | command to close |
|---|---|---|
| fuzz campaigns | pass | 120s `cargo +nightly fuzz run sanitize` completed without crash (552k executions) |
| malicious corpus campaign | no external malicious archive corpus was available | run the repository malicious-input tests against a curated corpus directory |
| memory profiling | pass with caveat | valgrind run on a python smoke import/compression completed with 0 invalid reads; only possibly-lost blocks reported |
| 7z encrypted-header and aes interoperability | code exists but dedicated bidirectional 7-zip matrix was not run | run `sevenz_interop_check` plus encrypted-header cases |
| compressed tar variants | only plain and pax tar fixtures were exercised | generate gzip, bzip2, xz, zstd, and lz4 tar fixtures and run readers |
