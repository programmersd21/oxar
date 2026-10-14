# format support

this matrix describes the implementation and tested coverage visible in the
current repository. `supported and tested` means a repository test exercises
the behavior. `supported with caveat` means the code exists but material
coverage or an implementation constraint remains. `not supported` means no
usable path is exposed.

## container operations

| container | rust list and read | rust extract | rust create | python list/read | python extract | python create and rewrite | python convert |
|---|---|---|---|---|---|---|---|
| zip | supported and tested | supported and tested | supported and tested | supported and tested | supported and tested | supported with caveat: create, append, update, and delete use default entry settings | supported with caveat: ZIP to ZIP or plain TAR only; encrypted conversion lacks third-party interoperability coverage |
| plain tar | supported and tested | supported and tested | supported and tested | supported and tested | supported and tested | supported with caveat: create uses default entry settings; rewrite and append are absent | supported with caveat: plain TAR to ZIP or plain TAR only |
| compressed tar | supported with caveat: compression interoperability coverage is incomplete | supported with caveat: full codec matrix is not tested | supported with caveat: writer coverage is incomplete | supported with caveat: detection and reader paths cover tested variants | supported with caveat: relies on the core detected reader path | not supported | supported with caveat: reads compressed TAR and writes ZIP or plain TAR; ratio accounting relies on declared sizes |
| 7z | supported with caveat: listing and selected reads use the common reader | supported with caveat: generic extraction is implemented; solid-block memory bounds remain open | supported with caveat: helper creation exists, interoperability and resource bounds remain open | supported with caveat: metadata and selected reads are exposed | not supported | not supported | not supported |

python read, list, test, and extract accept paths or file-like sources. file-like
sources are spooled to a private temporary file, up to an 8 GiB limit. extraction
accepts selected member names. file-like sinks and archive write modes on
`open` are not implemented. Conversion accepts ZIP and plain TAR sources and
writes ZIP or plain TAR output. It validates paths and links, applies policy
limits, and commits through a same-directory temporary file.
python create writes zip or plain tar from filesystem paths. zip append is
implemented by modifying a temporary copy and replacing the original only when
the new central directory is complete. tar append is unsupported. these write
operations do not expose the full core writer options, and 7z creation is not
exposed. update and delete are currently zip-only and modify the central
directory of a transactional copy, so deleted compressed payloads remain as
unreferenced bytes until a future compaction rewrite.

## zip features

| feature | state |
|---|---|
| stored, deflate, bzip2, zstd, lzma methods | supported with caveat: method paths exist; independent interoperability is incomplete |
| deflate64 | supported with caveat: depends on the configured zip crate method support |
| zip64 and self-extracting prefixes | supported with caveat: implementation paths exist; large-file gates remain open |
| winzip aes | supported with caveat: core round-trip tests exist; third-party matrix remains open |
| zipcrypto read | supported with caveat: weak legacy encryption, interoperability coverage remains open |
| strict central/local header checks and range overlap validation | supported with caveat: unit tampering cases exist; full malicious corpus and fuzz gates remain open |
| unicode path and cp437 decoding | supported with caveat: rust core paths exist; python encoding override is not exposed |

## tar features

| feature | state |
|---|---|
| ustar, gnu and pax parsing | supported with caveat: fixture and parser coverage is incomplete |
| tar writing | supported with caveat: output tests exist; full external metadata matrix remains open |
| sparse formats | supported with caveat: parser paths exist; interoperability is incomplete |
| symlink and hardlink policy in extraction | supported with caveat: sink-level tests exist; cross-format malicious tests remain open |
| append, delete, and update | not supported through the public python api |

## 7z features

| feature | state |
|---|---|
| listing and selected-entry reads | supported with caveat: helper reader paths exist; solid memory bounds need verification |
| archive creation helpers | supported with caveat: third-party read compatibility is not fully established |
| aes and encrypted headers | supported with caveat: password code exists; bidirectional 7-zip checks remain open |
| bounded solid-block decoding | not supported by the current generic adapter |
| safe generic extraction | supported with caveat: implemented through the common sink; memory bounds remain open |

## raw codecs

the rust core has one-shot and streaming adapters for gzip, zlib, raw deflate,
bzip2, xz, lzma, zstd, lz4 frame, brotli, and snappy framed. the python
binding has one-shot compression and decompression. round-trip tests exist, but
boundary levels, hostile memory requests, concatenated streams, trailing data,
and external cli interoperability are not complete for every codec.

## out of scope

rar, iso, cab, cpio, ar, deb, wim, multi-volume archives, archive repair,
extended attributes, acls, ownership restoration, native async i/o, fuse,
python versions before 3.11, 32-bit platforms, and wasm are outside the 1.0
scope.
