# changelog

all notable changes to this project are documented here. the format follows
keep a changelog.

## [0.1.1] - 2026-10-18

### fixed

- windows builds: unix only permission and path helpers are behind cfg gates,
  so oxar-core and the bindings compile on windows again.
- tar interop and write tests generate their fixtures with the platform tar
  instead of reading files outside the repository.
- ci free threading check records import warnings reliably.

## [0.1.0] - 2026-10-18

### added

- rust core for zip, tar, and 7z reading, writing, extraction, conversion,
  integrity testing, detection, and ten raw codecs.
- python package with archive operations, codecs, policy, cancellation, asyncio
  wrappers, cli, and streaming codec objects.
- security model with path validation, confined filesystem sink, resource
  limits, and malicious-input tests.
- documentation, dependency audit, release procedure, and verification record.

### changed

- updated zip to 9.0.5, sevenz-rust2 to 0.24.1, zstd to 0.14.3,
  unicode-normalization to 0.1.26, hypothesis to 6.170.1, and inout to 0.2.4.

### fixed

- yanked inout dependency removed from the lock file.
- compressed tar conversion and generic 7z extraction enabled.
- cached thread count to reduce repeated filesystem probes.
