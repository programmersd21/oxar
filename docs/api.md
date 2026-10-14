# python api

this page describes the python package in this checkout. the runtime api is in
`python/oxar/__init__.py`; the extension declarations are in
`python/oxar/_oxar.pyi`. read both when changing a signature.

## install and import

```python
import oxar

print(oxar.__version__)
entries = oxar.list("backup.zip")
for entry in entries:
    print(entry.kind.value, entry.size, entry.path)
```

## archive reads

`open(source, mode="r")` returns the `Archive` facade. archive read, list,
test, and extract operations accept paths and binary file-like objects. A
file-like source is spooled to a private temporary file in 256 KiB blocks,
with an 8 GiB input ceiling. `Archive` owns that temporary file until `close`.
The caller's current stream position is consumed and is not restored. The
facade supports iteration, `entries`,
`names`, `getinfo`, `read`, `open_entry`, `extract`, and `test`.

`read` materializes the whole member as `bytes`. set `max_size` for untrusted
members. `open_entry` wraps a bounded read in a buffer; it is not an incremental
decoder stream.

```python
with oxar.open("backup.zip") as archive:
    entry = archive.getinfo("notes.txt")
    content = archive.read(entry, max_size=1 << 20)
    report = archive.test()
```

## create archives

`create(dest, sources, format="zip")` writes a new archive from filesystem
paths. `format` accepts `zip` or `tar`. Directory contents are stored relative
to each source directory; the directory's own name is not prepended. Symlinks
found while walking a directory are skipped. The implementation uses the Rust
zip or tar writer and writes to a same-directory temporary file before
renaming it into place.

```python
report = oxar.create("backup.zip", ["project/"], format="zip")
print(report.entries, report.bytes_in, report.bytes_out)
```

This entry point uses default writer settings. It does not expose passwords,
compression levels, filters, reproducible timestamps, progress, or cancellation.
It does not yet provide 7z creation.

`append(archive, files)` supports ZIP archives. It copies the original to a
temporary file beside it, adds the new entries to that copy, and replaces the
original after the central directory is finalized. Tar append, encryption
settings for new entries, compression overrides, and progress callbacks are
not exposed by this binding.

```python
report = oxar.append("backup.zip", ["new-report.txt"])
```

For an archive opened in read mode, `Archive.delete(names)` hides matching
entries from the ZIP central directory. `Archive.update(files)` replaces
entries whose stored names match the names discovered from those paths. Both
operations use a temporary copy and replace the archive after writing finishes.
They do not compact old local data, and `update(root=...)` is not yet supported.

## extraction and integrity

`extract(source, dest, members=...)` uses the rust extraction path with default
policy and supports selecting entry names. A supplied `Policy` is converted to
the core policy, including the size, ratio, path, overwrite, link, and mode
settings. The returned report uses counts from the extraction run. Progress
callbacks and parallel extraction controls are not wired through this binding.
`test` returns a `TestReport` for the implemented zip and tar reader paths.

## conversion

`convert(source, dest, format=...)` streams entries from ZIP or plain TAR into
ZIP or plain TAR. Names and links pass the core path checks, configured size
limits apply, and output is built beside the destination before it is renamed
into place. Encrypted ZIP input accepts `password`; encrypted ZIP output accepts
`dest_password`.

```python
report = oxar.convert("backup.zip", "backup.tar", format="tar")
print(report.entries, report.bytes_in, report.bytes_out)
```

Compressed TAR conversion, 7z conversion, and file-like destinations are
unsupported. Conversion level, outer compression, threading, callbacks, and
reproducible output controls are also unsupported by this binding. `bytes_in`
is the source archive file size; `bytes_out` is the committed output archive
size.

## raw codecs and detection

`compress` and `decompress` are one-shot byte-buffer operations. supported codec
names are `gzip`, `zlib`, `deflate`, `bzip2`, `xz`, `lzma`, `zstd`, `lz4`,
`brotli`, and `snappy`. `detect` accepts bytes-like values or filesystem paths.
raw deflate and brotli have no reliable magic signature, so pass their codec
name explicitly to `decompress`.

```python
encoded = oxar.compress(b"payload", "gzip", level=6)
plain = oxar.decompress(encoded, "gzip", max_size=4096)
```

## records and exceptions

entry, policy, report, progress, detection, and cancellation records are
implemented in `python/oxar/_models.py`. the public stub is maintained by hand
in `_oxar.pyi`. the python exception mapping is not one-to-one with every rust
error variant; only rely on attributes implemented by the python package.

## unavailable operations

python `create` supports filesystem paths to zip and plain tar with default
writer settings. zip append, delete, and update are supported with the limits
above. archive write modes, file-like archive sinks, and streaming codec
objects are not implemented. custom policy conversion, callback
dispatch, and parts of the asyncio contract are also incomplete. see [format
support](format-support.md) for operation-level coverage.
