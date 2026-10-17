# examples

These scripts use the installed `oxar` package and Python's standard library.
Each script creates its own temporary input data and removes it when it exits.

Run from the repository root after installing the package:

```sh
python -m pip install -e .
python examples/inspect_archive.py
python examples/safe_extract.py
python examples/create_convert.py
python examples/raw_codecs.py
```

`inspect_archive.py` lists metadata, reads one member with a size cap, and
checks archive integrity. `safe_extract.py` shows selected-member extraction
and a policy limit. `create_convert.py` creates ZIP and TAR archives and
converts between them. `raw_codecs.py` shows bounded one shot compression and
decompression.

The scripts use only the Python binding features currently exposed by oxar.
See [format support](../docs/format-support.md) for the implemented API
boundary.
