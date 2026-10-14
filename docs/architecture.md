# architecture

## crates and package boundary

`oxar-core` is a rust library with no pyo3 dependency. it owns codec wrappers,
container readers and writers, path validation, operation budgets, extraction
planning, filesystem sinks, and create helpers. `oxar-py` builds the
`oxar._oxar` extension. `python/oxar` adds python records, convenience
functions, the cli entry point, type declarations, and asyncio wrappers.

the python extension is narrower than the core. it exposes zip and tar
creation with filesystem sources, but does not yet expose general archive
writer options, rewrite operations, custom extraction policy conversion, or
python file objects. the public contract and gaps are listed in [api.md](api.md).

## core module map

| module | responsibility |
|---|---|
| `budget` | shared counters and per-entry scopes for produced and consumed bytes |
| `codec` | one-shot and streaming wrappers for ten raw codec formats |
| `create` | source traversal and archive creation helpers |
| `detect` | prefix and suffix probing for formats and codecs |
| `error` | structured rust errors and location context |
| `extract` | entry policy, path planning, budget use, and sink dispatch |
| `format` | entry vocabulary and reader/writer traits |
| `format/tar` | tar parsing and writing |
| `format/zip` | zip parsing and writing, with a separate validator |
| `format/sevenz` | 7z helpers; not yet a complete generic reader/extractor |
| `fsio` | input abstractions and positional reads |
| `path` | name normalization, safety checks, and collision keys |
| `policy` | extraction rules and resource limits |
| `progress` | progress events and cancellation state |
| `secret` | zeroizing secret wrapper |
| `sink` | `FsSink` and `VirtualSink` implementations |
| `test_archive` | integrity checks for supported readers |

## data flow

for reading, an `Input` is inspected by detection or an explicit format
selection, then a format reader yields entry metadata and payload readers.
extraction passes each name through the path sanitizer and policy planner. the
planner opens a budget scope and sends data and expected integrity metadata to
a `Sink`. the filesystem sink owns destination operations. no format reader
is given an extraction destination.

for creation, source paths are enumerated and represented as new entries. a
format writer consumes entry bytes and serializes container metadata. the
current python `create` function walks source trees, streams file contents into
the zip or tar writer, finalizes a temporary file, then renames it to the
destination. Python creation currently uses default metadata and compression
settings and does not expose rewrite operations.

## error flow

core operations return `oxar_core::Result<T>`. errors can include a
`Location` containing format, entry, and offset information. the pyo3 layer
translates selected core errors into python exceptions. python exception
coverage remains incomplete; consult the actual api surface and tests before
depending on variant-specific attributes.

## threading and ownership

the core traits require reader and sink values to satisfy the relevant rust
thread-safety bounds. this does not by itself mean every operation uses a
parallel pipeline. the binding detaches the GIL around large or multi-threaded
compression, decompression, listing, entry reads, extraction, integrity checks,
creation, and zip rewriting. for small one-shot buffers (<512 KiB) on single-threaded
codecs, execution runs synchronously without buffer copies or thread detachment
overhead. Python value conversion and exception construction happen
after the Rust operation returns. tests exercise GIL progress during
creation and extraction. callback dispatch, Python file-like adapters, and
parallel operation controls are not implemented in the binding.
