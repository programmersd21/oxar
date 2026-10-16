# comparison

this page describes project scope and repository evidence. it does not make
performance claims. no competitor benchmark table is published until a
benchmark run records versions, machine details, output sizes, and timings.

| project | scope and interface | evidence used here |
|---|---|---|
| python `zipfile` and `tarfile` | standard-library zip and tar apis | python standard library documentation; not a unified 7z api |
| `py7zr` | python 7z package | separate package and api |
| `fastar` | rust-backed tar-focused package | not a general zip and 7z object model |
| `archivefile` | python wrapper over other archive implementations | wrapper interface differs from direct format apis |
| `exarch` | rust-backed python archive package with security-focused extraction | existing project; oxar does not claim to be first in rust-backed or safe extraction |
| `oxar` | rust core, pyo3 extension, and python package | current support is recorded in [format-support.md](format-support.md) |

the intended oxar api includes common archive operations, entry streams, raw
codecs, policy-controlled extraction, and a python object model. several of
those python surfaces remain unfinished in this repository. feature intent is
not a basis for claiming parity; use the support matrix and gate ledger.
