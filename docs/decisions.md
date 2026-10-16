# decisions

engineering decisions made where the specification left a choice. dates and
version statements describe the repository state when the decision was made.

1. **2026-10-16, rust toolchain:** pin stable 1.98.1 for reproducible local and
   ci builds; keep the declared msrv separate at 1.93.
2. **2026-10-16, version verification:** use the crates.io api's
   `max_stable_version` field because sparse-index ordering can place a later
   backport from an older major line at the end.
3. **2026-10-16, dependency resolution:** use compatible version ranges with a
   committed `Cargo.lock`; `tools/check_versions.py` reports drift.
4. **2026-10-16, workspace:** use cargo resolver 3 and edition 2024.
5. **2026-10-16, python matrix:** use python 3.11 as the floor; provision
   supported interpreters through uv where the host does not provide them.
6. **2026-10-16, python 3.15:** treat the final release as a target after
   checking interpreter availability and running its suite.
7. **2026-10-16, zip dependency:** update the requested 9.0.3 floor to 9.0.4
   after reviewing the newer release's fixes and confirming no used call depends
   on the changed behavior.
8. **2026-10-16, unicode collision handling:** add full unicode case folding
   because lowercase conversion is not equivalent to unicode case folding.
9. **2026-10-16, documentation status:** describe the implementation in the
   repository, not every feature in the target specification; keep incomplete
   behavior visible in the support matrix and gate ledger.
10. **2026-10-16, xz checksum dispatch:** enable liblzma's runtime-checked
    CLMUL CRC64 path for x86_64 builds because it improved local decode timings
    while retaining the generic implementation as a fallback. Linux x86_64 was
    measured locally; other configured target toolchains still require CI builds.
    Custom target-specific C flags must retain `HAVE_USABLE_CLMUL` to keep this
    optimization enabled.

11. **2026-10-18, repository checkout:** the working tree has no `.git`
    directory; do not initialize one. `tools/check_repository.py` falls back to
    a filesystem walk with the same excluded directories when git is unavailable.
12. **2026-10-18, dependency bumps:** update zip to 9.0.5, sevenz-rust2 to
    0.24.1, zstd to 0.14.3, unicode-normalization to 0.1.26, hypothesis to
    6.170.1, and lzma-rust2 to 0.23.0.
13. **2026-10-18, free-threaded python:** build and test against cpython 3.14t
    with the gil disabled before claiming support; record the result in
    `docs/verification.md`.
14. **2026-10-18, yanked dependency:** update locked `inout` to 0.2.4 after
    cargo audit and cargo deny reported 0.2.3 as yanked.
