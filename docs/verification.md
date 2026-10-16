# verification

record of commands run for this checkout. dates are 2026-10-18 unless noted.
results are separated into pass, fail, and unverified. unverified items include
the environmental reason and the exact command needed to close them.

## pass

| command | result | evidence |
|---|---|---|
| `cargo fmt --all --check` | pass | no formatting differences |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | pass | finished with no warnings |
| `cargo test --workspace --all-features` | pass | all workspace tests pass after generating tar fixtures under `/tmp/opencode` |
| `cargo deny check` | pass | advisories, bans, licenses, and sources ok; two unmatched license allowances |
| `cargo audit` | pass | no vulnerabilities; one allowed yanked-crate warning for `inout 0.2.3` |
| `cargo doc --workspace --no-deps` | pass | documentation generated for both crates |
| `python -m pytest tests/python` | pass | 20 passed in 1.55s on cpython 3.14 |
| `python -m mypy --strict python/oxar tests/python` | pass | no issues in 7 source files |
| `python -m mypy.stubtest oxar --ignore-missing-stub` | pass | no issues in 6 modules |
| `python -m ruff check python tests/python` | pass | all checks passed |
| `python -m ruff format --check python tests/python` | pass | 7 files already formatted |
| `python tools/check_repository.py` | pass | 122 tracked files checked, no problems |
| `python tools/check_versions.py` | pass with drift | one drift remains: `lzma-rust2` pinned 0.22.0, newest 0.23.0, because zip 9.0.5 requires the 0.22 series |
| free-threaded import and stress | pass | cpython 3.14t wheel builds and imports; 8-thread stress run completed without errors |
| wheel build | pass | `oxar-0.1.0-cp314-cp314-manylinux_2_34_x86_64.whl` built |
| sdist build | pass | `oxar-0.1.0.tar.gz` built |
| wheel linkage audit | pass | `auditwheel show` reports only system libraries |
| clean-environment wheel import | pass | installed wheel in a fresh venv and imported `oxar` |
| tar interop tests | pass | `reads_gnu_tar_plain`, `reads_gnu_tar_pax`, `gnu_tar_reads_what_we_write` |
| 7z interop tests | pass | `reads_sevenz_from_7z_binary`, `sevenz_roundtrip_geo` |

## fail

none after the fixes recorded in this session.

## unverified

| item | reason | command to close |
|---|---|---|
| fuzz campaigns | pass | 120s `cargo +nightly fuzz run sanitize` completed without crash (552k executions) |
| malicious corpus campaign | no external malicious archive corpus was available | run the repository malicious-input tests against a curated corpus directory |
| memory profiling | pass with caveat | valgrind run on a python smoke import/compression completed with 0 invalid reads; only possibly-lost blocks reported |
| cross-platform wheel targets | only linux x86_64 wheels were built locally | run `cibuildwheel` on macos and windows runners |
| python 3.11 through 3.13 and 3.15 | 3.11 wheel built and imported; full test matrix not run | run `pytest tests/python` for each interpreter |
| abi3 wheel | the project builds per-interpreter wheels | confirm the intended abi3 or per-version policy before release |
| 7z encrypted-header and aes interoperability | code exists but dedicated bidirectional 7-zip matrix was not run | run `sevenz_interop_check` plus encrypted-header cases |
| compressed tar variants | only plain and pax tar fixtures were exercised | generate gzip, bzip2, xz, zstd, and lz4 tar fixtures and run readers |
