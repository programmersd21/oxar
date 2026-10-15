# dependencies

direct dependencies and the justification required by the project rules.
versions are the floors pinned in the workspace manifest; the committed
`Cargo.lock` fixes the exact graph. `tools/check_versions.py` reports drift.

## rust, oxar-core

| crate | purpose | licence | status |
|---|---|---|---|
| thiserror | error derive | mit or apache-2.0 | maintained (dtolnay) |
| rayon | worker pools, dedicated per call | mit or apache-2.0 | maintained |
| crc32fast | crc32 with runtime simd | mit or apache-2.0 | maintained |
| cap-std | capability confined filesystem access | mit or apache-2.0 | maintained (bytecodealliance) |
| cap-primitives | fd rooted `set_times` for directory mtimes | mit or apache-2.0 | same release train as cap-std, already in the tree via cap-std |
| zip | zip method codecs and writer | mit | maintained |
| tar | tar header parse and write | mit or apache-2.0 | maintained |
| sevenz-rust2 | 7z container | apache-2.0 | maintained; gate g0.3 in docs/decisions.md |
| lzma-rust2 | lzma/lzma2 used through sevenz-rust2 and zip | mit or apache-2.0 | maintained |
| flate2 | gzip/zlib/deflate with the pure rust zlib-rs backend | mit or apache-2.0 | maintained |
| bzip2 | bzip2 with the pure rust libbz2-rs-sys backend (default) | mit or apache-2.0 | maintained (trifectatech) |
| liblzma | xz and lzma with static linking | mit or apache-2.0 | maintained (xz2 successor) |
| zstd | zstd with bundled static build and multi threading | mit | maintained |
| lz4_flex | lz4 frame | mit | maintained |
| brotli | brotli, decoder driven through brotlistate::new_strict | mit or apache-2.0 | maintained |
| snap | snappy framed | bsd-3-clause | maintained |
| zeroize | password hygiene | mit or apache-2.0 | maintained |
| unicode-normalization | nfc for collision keys | mit or apache-2.0 | maintained |
| caseless | full unicode case folding for collision keys | mit | maintained (2024 release). required because neither the standard library nor unicode-normalization implements case folding (`str::to_lowercase` does not fold `ß` to `ss`); unicode-casefold is unmaintained since 2016 |
| bitflags | flag sets | mit or apache-2.0 | maintained |

## rust, development only

proptest (property tests), criterion (benchmarks), tempfile (test fixtures),
libfuzzer-sys and arbitrary (fuzz crate only).

## rust, bindings

pyo3 0.30.1, mit or apache-2.0. the only binding layer; no tokio, no
pyo3-async-runtimes, no numpy, no pyo3-stub-gen.

## python, development only

maturin (build backend), cibuildwheel, pytest, hypothesis, mypy, ruff,
pytest-benchmark, auditwheel, delocate. all pinned in `pyproject.toml`.
