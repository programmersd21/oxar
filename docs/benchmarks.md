# benchmarks

generated from [`bench/results/2026-10-18-091846-566808-nyx.json`](../bench/results/2026-10-18-091846-566808-nyx.json).

run date: 2026-10-18T09:18:46.507560+00:00
method: warm-cache repeated local run; archive generation excluded from timed samples.

## environment

- platform: Linux-7.2.9-2-cachyos-x86_64-with-glibc2.44
- cpu: 12th Gen Intel(R) Core(TM) i5-1235U
- logical processors: 12
- memory: 8028516352 bytes
- python: 3.14.8 (main, Oct 13 2026, 10:33:10) [GCC 16.2.1 20260810]
- rustc: rustc 1.98.1 (48a229cea 2026-09-01)
- source revision: None
- working tree dirty: none
- oxar: 0.1.0
- stdlib zlib runtime: 1.3.1.zlib-ng
- stdlib lzma module: `/usr/lib/python3.14/lzma.py`
- stdlib bz2 module: `/usr/lib/python3.14/bz2.py`
- stdlib zstd module: `/usr/lib/python3.14/compression/zstd/__init__.py`

## workload

- entries: 250 files of 4096 bytes
- codec input: 262144 bytes
- repetitions: 7
- zip size: 550475 bytes
- tar.gz size: 523166 bytes
- input sha256: `f0dfcf0a7a654c0fd09b1bd84632cef79783ad071a0f16698bfc1285eb407aec`

## results

timings are seconds. iqr is the interquartile range across raw samples.
archive generation is excluded; extraction target creation is included.
the run is warm-cache and uses the same host for each paired operation.

| operation | median (s) | iqr (s) | output bytes |
|---|---:|---:|---:|
| `oxar.zip.list` | 0.001386 | 0.000091 |  |
| `stdlib.zip.list` | 0.000487 | 0.000016 |  |
| `oxar.zip.read_middle` | 0.000304 | 0.000092 | 4096 |
| `stdlib.zip.read_middle` | 0.000544 | 0.000040 | 4096 |
| `oxar.zip.extract` | 0.005376 | 0.000260 |  |
| `stdlib.zip.extract` | 0.006121 | 0.000178 |  |
| `oxar.tar_gz.list` | 0.002263 | 0.000112 |  |
| `stdlib.tar_gz.list` | 0.005376 | 0.000038 |  |
| `oxar.tar_gz.read_middle` | 0.000993 | 0.000071 | 4096 |
| `stdlib.tar_gz.read_middle` | 0.006578 | 0.000039 | 4096 |
| `oxar.tar_gz.extract` | 0.005504 | 0.000519 |  |
| `stdlib.tar_gz.extract` | 0.015795 | 0.000506 |  |
| `oxar.codec.gzip.compressible.compress` | 0.000095 | 0.000011 | 1338 |
| `stdlib.codec.gzip.compressible.compress` | 0.000069 | 0.000014 | 1338 |
| `oxar.codec.gzip.compressible.decompress` | 0.000043 | 0.000006 | 262144 |
| `stdlib.codec.gzip.compressible.decompress` | 0.000034 | 0.000011 | 262144 |
| `oxar.codec.bzip2.compressible.compress` | 0.028184 | 0.000584 | 132 |
| `stdlib.codec.bzip2.compressible.compress` | 0.030015 | 0.000455 | 132 |
| `oxar.codec.bzip2.compressible.decompress` | 0.001563 | 0.000200 | 262144 |
| `stdlib.codec.bzip2.compressible.decompress` | 0.001115 | 0.000022 | 262144 |
| `oxar.codec.xz.compressible.compress` | 0.011231 | 0.000296 | 200 |
| `stdlib.codec.xz.compressible.compress` | 0.004444 | 0.000330 | 200 |
| `oxar.codec.xz.compressible.decompress` | 0.000126 | 0.000009 | 262144 |
| `stdlib.codec.xz.compressible.decompress` | 0.000137 | 0.000016 | 262144 |
| `oxar.codec.zstd.compressible.compress` | 0.000034 | 0.000003 | 60 |
| `stdlib.codec.zstd.compressible.compress` | 0.000034 | 0.000009 | 60 |
| `oxar.codec.zstd.compressible.decompress` | 0.000098 | 0.000003 | 262144 |
| `stdlib.codec.zstd.compressible.decompress` | 0.000112 | 0.000005 | 262144 |
| `oxar.codec.gzip.random.compress` | 0.004356 | 0.000088 | 262244 |
| `stdlib.codec.gzip.random.compress` | 0.003570 | 0.000038 | 262244 |
| `oxar.codec.gzip.random.decompress` | 0.000035 | 0.000007 | 262144 |
| `stdlib.codec.gzip.random.decompress` | 0.000036 | 0.000005 | 262144 |
| `oxar.codec.bzip2.random.compress` | 0.019558 | 0.000161 | 263702 |
| `stdlib.codec.bzip2.random.compress` | 0.019876 | 0.000488 | 263702 |
| `oxar.codec.bzip2.random.decompress` | 0.010774 | 0.000115 | 262144 |
| `stdlib.codec.bzip2.random.decompress` | 0.010239 | 0.000048 | 262144 |
| `oxar.codec.xz.random.compress` | 0.051843 | 0.003745 | 262216 |
| `stdlib.codec.xz.random.compress` | 0.047256 | 0.002699 | 262216 |
| `oxar.codec.xz.random.decompress` | 0.000042 | 0.000015 | 262144 |
| `stdlib.codec.xz.random.decompress` | 0.000038 | 0.000007 | 262144 |
| `oxar.codec.zstd.random.compress` | 0.000067 | 0.000038 | 262159 |
| `stdlib.codec.zstd.random.compress` | 0.000082 | 0.000038 | 262159 |
| `oxar.codec.zstd.random.decompress` | 0.000019 | 0.000006 | 262144 |
| `stdlib.codec.zstd.random.decompress` | 0.000025 | 0.000005 | 262144 |

## paired winners

paired cases: 22. oxar wins 13, stdlib wins 9, ties 0.

winner is the implementation with the lower median time. the factor is the slower median divided by the faster median; for example, 2.0x means the winner's median was half the other median. these are descriptive medians, not a statistical significance test.

| operation | winner | median factor | oxar median (s) | stdlib median (s) |
|---|---|---:|---:|---:|
| `codec.bzip2.compressible.compress` | oxar | 1.06x | 0.028184 | 0.030015 |
| `codec.bzip2.compressible.decompress` | stdlib | 1.40x | 0.001563 | 0.001115 |
| `codec.bzip2.random.compress` | oxar | 1.02x | 0.019558 | 0.019876 |
| `codec.bzip2.random.decompress` | stdlib | 1.05x | 0.010774 | 0.010239 |
| `codec.gzip.compressible.compress` | stdlib | 1.39x | 0.000095 | 0.000069 |
| `codec.gzip.compressible.decompress` | stdlib | 1.26x | 0.000043 | 0.000034 |
| `codec.gzip.random.compress` | stdlib | 1.22x | 0.004356 | 0.003570 |
| `codec.gzip.random.decompress` | oxar | 1.02x | 0.000035 | 0.000036 |
| `codec.xz.compressible.compress` | stdlib | 2.53x | 0.011231 | 0.004444 |
| `codec.xz.compressible.decompress` | oxar | 1.09x | 0.000126 | 0.000137 |
| `codec.xz.random.compress` | stdlib | 1.10x | 0.051843 | 0.047256 |
| `codec.xz.random.decompress` | stdlib | 1.10x | 0.000042 | 0.000038 |
| `codec.zstd.compressible.compress` | oxar | 1.00x | 0.000034 | 0.000034 |
| `codec.zstd.compressible.decompress` | oxar | 1.14x | 0.000098 | 0.000112 |
| `codec.zstd.random.compress` | oxar | 1.22x | 0.000067 | 0.000082 |
| `codec.zstd.random.decompress` | oxar | 1.31x | 0.000019 | 0.000025 |
| `tar_gz.extract` | oxar | 2.87x | 0.005504 | 0.015795 |
| `tar_gz.list` | oxar | 2.38x | 0.002263 | 0.005376 |
| `tar_gz.read_middle` | oxar | 6.62x | 0.000993 | 0.006578 |
| `zip.extract` | oxar | 1.14x | 0.005376 | 0.006121 |
| `zip.list` | stdlib | 2.85x | 0.001386 | 0.000487 |
| `zip.read_middle` | oxar | 1.79x | 0.000304 | 0.000544 |

## limits

paired winner counts use lower medians as a descriptive rule and do not indicate statistical significance. results can vary with workload, platform, compiler, and standard library build.

these are local measurements, not a cross-machine performance claim. archive fixtures are created by python's standard library. the tested subset compares zip and tar.gz listing, member reads, and extraction, plus gzip, bzip2, xz, and, where the Python version provides it, zstd one-shot codecs on compressible and random data. it does not measure 7z, archive creation in oxar, cold-cache behavior, or the larger workloads specified for release benchmarking.
