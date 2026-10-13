#!/usr/bin/env python3
"""Render docs/benchmarks.md from the newest raw benchmark result."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "bench" / "results"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-dir", type=Path, default=RESULTS)
    args = parser.parse_args()
    files = sorted(args.results_dir.glob("*.json"), key=lambda path: path.stat().st_mtime_ns)
    if not files:
        raise SystemExit("no raw benchmark JSON files found")
    data = json.loads(files[-1].read_text())
    machine = data["machine"]
    workload = data["workload"]
    paired: dict[str, dict[str, dict[str, float]]] = {}
    for result in data["results"]:
        prefix, separator, operation = result["name"].partition(".")
        if separator and prefix in {"oxar", "stdlib"}:
            paired.setdefault(operation, {})[prefix] = result

    winners = []
    for operation, implementations in sorted(paired.items()):
        if "oxar" not in implementations or "stdlib" not in implementations:
            continue
        oxar_median = implementations["oxar"]["median_seconds"]
        stdlib_median = implementations["stdlib"]["median_seconds"]
        if math.isclose(oxar_median, stdlib_median, rel_tol=1e-12, abs_tol=0.0):
            winner = "tie"
            ratio = 1.0
        elif oxar_median < stdlib_median:
            winner = "oxar"
            ratio = stdlib_median / oxar_median
        else:
            winner = "stdlib"
            ratio = oxar_median / stdlib_median
        winners.append((operation, winner, ratio, oxar_median, stdlib_median))

    lines = [
        "# benchmarks",
        "",
        f"generated from [`{files[-1].relative_to(ROOT)}`](../{files[-1].relative_to(ROOT)}).",
        "",
        f"run date: {data['date_utc']}",
        f"method: {data['method']}.",
        "",
        "## environment",
        "",
        f"- platform: {machine['platform']}",
        f"- cpu: {machine['cpu']}",
        f"- logical processors: {machine['logical_cpus']}",
        f"- memory: {machine['memory_bytes']} bytes",
        f"- python: {machine['python'].splitlines()[0]}",
        f"- rustc: {machine['rustc']}",
        f"- source revision: {machine['git_revision']}",
        f"- working tree dirty: {str(machine['git_dirty']).lower()}",
        f"- oxar: {machine['oxar']}",
        f"- stdlib zlib runtime: {machine['stdlib_codecs']['zlib_runtime']}",
        f"- stdlib lzma module: `{machine['stdlib_codecs']['lzma_module']}`",
        f"- stdlib bz2 module: `{machine['stdlib_codecs']['bz2_module']}`",
        f"- stdlib zstd module: `{machine['stdlib_codecs']['zstd_module']}`",
        "",
        "## workload",
        "",
        f"- entries: {workload['entries']} files of {workload['bytes_per_entry']} bytes",
        f"- codec input: {workload['codec_bytes']} bytes",
        f"- repetitions: {workload['repeats']}",
        f"- zip size: {workload['zip_bytes']} bytes",
        f"- tar.gz size: {workload['tar_gz_bytes']} bytes",
        f"- input sha256: `{workload['payload_sha256']}`",
        "",
        "## results",
        "",
        "timings are seconds. iqr is the interquartile range across raw samples.",
        "archive generation is excluded; extraction target creation is included.",
        "the run is warm-cache and uses the same host for each paired operation.",
        "",
        "| operation | median (s) | iqr (s) | output bytes |",
        "|---|---:|---:|---:|",
    ]
    for result in data["results"]:
        output = "" if result["output_bytes"] is None else str(result["output_bytes"])
        lines.append(
            f"| `{result['name']}` | {result['median_seconds']:.6f} "
            f"| {result['iqr_seconds']:.6f} | {output} |"
        )
    lines.extend(
        [
            "",
            "## paired winners",
            "",
            f"paired cases: {len(winners)}. oxar wins {sum(winner == 'oxar' for _, winner, *_ in winners)}, "
            f"stdlib wins {sum(winner == 'stdlib' for _, winner, *_ in winners)}, "
            f"ties {sum(winner == 'tie' for _, winner, *_ in winners)}.",
            "",
            "winner is the implementation with the lower median time. the factor "
            "is the slower median divided by the faster median; for example, 2.0x "
            "means the winner's median was half the other median. these are "
            "descriptive medians, not a statistical significance test.",
            "",
            "| operation | winner | median factor | oxar median (s) | stdlib median (s) |",
            "|---|---|---:|---:|---:|",
        ]
    )
    for operation, winner, ratio, oxar_median, stdlib_median in winners:
        factor = "1.00x" if winner == "tie" else f"{ratio:.2f}x"
        lines.append(
            f"| `{operation}` | {winner} | {factor} | {oxar_median:.6f} | {stdlib_median:.6f} |"
        )
    lines.extend(
        [
            "",
            "## limits",
            "",
            "paired winner counts use lower medians as a descriptive rule and "
            "do not indicate statistical significance. results can vary with "
            "workload, platform, compiler, and standard library build.",
            "",
            "these are local measurements, not a cross-machine performance claim. "
            "archive fixtures are created by python's standard library. the tested "
            "subset compares zip and tar.gz listing, member reads, and extraction, "
            "plus gzip, bzip2, xz, and, where the Python version provides it, zstd one-shot codecs on compressible and random data. "
            "it does not measure 7z, "
            "archive creation in oxar, cold-cache behavior, or the larger workloads "
            "specified for release benchmarking.",
            "",
        ]
    )
    (ROOT / "docs" / "benchmarks.md").write_text("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
