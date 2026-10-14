# security model

## threat boundary

the archive contents are treated as untrusted. the destination root and process
environment are trusted. capability-relative filesystem access is intended to
keep writes within the opened destination directory. a hostile process that
concurrently changes destination entries can still cause operations to fail;
oxar does not claim to make such a race harmless on every filesystem.

the extraction planner is shared by format readers and sinks. format readers
provide names and byte streams; the planner validates names and applies policy;
sinks perform writes. zip and tar are currently the generic extraction paths.
the 7z helpers are not wired into the generic extraction adapter.

## controls in the current source

| control | attack addressed | implementation evidence | remaining qualification |
|---|---|---|---|
| name sanitizer rejects traversal and absolute names | archive path escape | `path.rs` unit and property tests | platform matrix is not complete |
| zip-like and tar-like separator rules | backslash traversal differences | `extract::NameRule` and path tests | full malicious corpus remains open |
| nfc and unicode case-fold collision keys | two names targeting one filesystem name | sanitizer and extraction duplicate checks | filesystem-specific normalization differs |
| symlink target validation | link-based path escapes | `validate_symlink_target` and sink tests | cross-platform integration tests remain open |
| hardlinks must resolve through extracted entries | link to arbitrary outside path | `extract.rs` and sink implementation | full malicious archive matrix remains open |
| special-file policy | device and fifo creation | policy and sink entry-kind handling | windows and unix integration coverage remains open |
| temporary regular-file writes, crc and size checks | partial output and corrupt payload | `FsSink::put_file` and sink tests | cleanup after process termination is not guaranteed |
| entry and byte budgets | count and expansion bombs | `Budget` and extraction tests | chunk-level overshoot and every limit need gate evidence |
| zip central/local header checks and range validation | differential zip parsing and overlap | `zip_validate.rs` tests | full polyglot corpus and fuzz duration remain open |
| positional reads | sigbus from a truncated mmap | `fsio.rs` positional reader | concurrent source mutation can still produce i/o errors |

the table names implementation locations rather than claiming all security
gates have passed. docs/verification.md records executed checks.

The Rust and Python default policies enable timestamp preservation, cleanup on
failure, strict ZIP structure validation, and destination creation. Set
`create_dest=False` to require an existing destination. Limits can be disabled
individually with `None`; path traversal rejection, capability confinement, and
checksum checks cannot be disabled.

## resource limits

`Policy::default()` includes entry-count, per-entry and total output,
expansion-ratio, path, decoder-memory, pax, zip extra-field, sparse-region,
and 7z solid-block limits. the decoder memory limit is not yet uniformly
verified for every codec and 7z coder chain. do not treat a configured limit as
proof of pre-allocation enforcement until the relevant tests pass.

## filesystem behavior

`FsSink` is built around `cap_std::fs::Dir`. it resolves sanitized paths
relative to its opened directory handle and does not use a canonicalize-then-
open sequence. it tracks objects created during the run for cleanup. cleanup is
best effort, and replacing an existing file cannot restore the replaced bytes
if a later operation fails. permission behavior and symlink privileges differ
across platforms.

## passwords

rust secrets use the `Secret` wrapper and zeroizing storage. never put a
password in logs, exception text, command-line arguments, or diagnostic output.
the python cli's final password handling behavior must be verified against its
current implementation before use in unattended deployments.
