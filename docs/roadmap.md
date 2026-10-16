# roadmap

this file records scope and implementation gaps, not release promises. the
source of current gate state is [docs/verification.md](verification.md).

## python surface

- expose the remaining rust archive creation options through pyo3, including
  passwords, compression settings, filters, progress, and cancellation.
- add file-like source and sink adapters, including seek and short-read cases.
- wire python `Policy`, progress callbacks, and cancellation to core calls.
- add streaming python codec reader and writer objects.
- complete the asyncio wrappers and cli against implemented operations.
- complete the python exception mapping and api contract tests.

## format coverage

- finish general 7z reading and extraction through the common reader and sink
  interfaces.
- verify solid-block memory bounds and encrypted-header interoperability.
- complete external-tool interoperability for zip encryption, zip64, compressed
  tar variants, sparse tar, and 7z.
- extend append, update, and delete to tar and add bounded conversion across
  supported formats.

## verification and distribution

- complete malicious corpus coverage and fuzz campaigns.
- run platform extraction tests on linux, macos, and windows.
- verify all requested wheel targets and dynamic library dependencies.
- generate benchmark data only from the repository's benchmark scripts.

rar, iso, cab, cpio, ar, deb, wim, multi-volume archives, archive repair,
extended attributes, acls, ownership restoration, native async i/o, fuse,
python versions before 3.11, 32-bit platforms, and wasm remain outside the
version 1.0 scope described by the engineering specification.
