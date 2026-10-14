# rust core api

`oxar-core` is a rust library without pyo3 or python runtime dependencies. the
crate's public modules are documented by rustdoc. build that reference with:

``sh
cargo doc --no-deps --workspace
``

the crate is not published yet. use the workspace path dependency while
working in this repository.

## codecs

one-shot codec entry points live in `oxar_core::codec`. they take a codec enum,
input bytes, level and thread count, plus codec options. decoders receive
`Limits` and an optional output cap.

``rust
use oxar_core::codec::{self, codecoptions};
use oxar_core::{codec, limits};

fn round_trip(input: &[u8]) -> oxar_core::result<vec<u8>> {
    let encoded = codec::compress(
        codec::gzip,
        input,
        6,
        1,
        codecoptions::default(),
    )?;
    codec::decompress(
        codec::gzip,
        &encoded,
        &limits::default(),
        some(1024 * 1024),
    )
}
``

streaming adapters are under `oxar_core::codec::stream`. writers must be
finished explicitly so final frame bytes and write errors are reported.

## container traits

`oxar_core::format::ArchiveReader` exposes `format`, `next_entry`,
`open_current`, `open_entry`, and `is_random_access`. `ArchiveWriter` accepts a
`NewEntry` and a byte reader, then has an explicit finish operation. zip and
tar have reader and writer implementations. the 7z module has helper paths but
does not yet provide a generic reader that participates in the shared safe
extraction planner.

## extraction

applications should pass a format reader to `oxar_core::extract::extract` and
send output through a `Sink`. `FsSink` writes beneath a directory capability;
`VirtualSink` supports in-memory behavior tests. format parsing and filesystem
mutation therefore have separate interfaces.

the full signatures and field documentation are in rustdoc. see
[architecture](architecture.md), [security model](security-model.md), and
[format support](format-support.md) for current constraints.
