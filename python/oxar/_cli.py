"""Command-line interface for the oxar package."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from dataclasses import asdict
from getpass import getpass
from pathlib import Path
from typing import Any


def _password(args: argparse.Namespace) -> str | None:
    """Read a password without placing it in the process argument list."""
    path = args.password_file
    if path:
        return Path(path).read_text(encoding="utf-8").rstrip("\r\n")
    environment_value = os.environ.get("OXAR_PASSWORD")
    if environment_value is not None:
        return environment_value
    if sys.stdin.isatty():
        return getpass("Password: ")
    return None


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="oxar", description="Inspect and extract supported archives"
    )
    commands = parser.add_subparsers(dest="command", required=True)

    listing = commands.add_parser("list", aliases=["ls"], help="list archive entries")
    listing.add_argument("archive")
    listing.add_argument("--json", action="store_true")
    listing.add_argument("--password-file")

    extracting = commands.add_parser("extract", aliases=["x"], help="extract an archive")
    extracting.add_argument("archive")
    extracting.add_argument("dest")
    extracting.add_argument("--password-file")

    creating = commands.add_parser("create", aliases=["c"], help="create an archive")
    creating.add_argument("archive")
    creating.add_argument("inputs", nargs="+")
    creating.add_argument("--format", choices=("zip", "tar"), default="zip")

    appending = commands.add_parser("append", help="append files to an archive")
    appending.add_argument("archive")
    appending.add_argument("inputs", nargs="+")

    checking = commands.add_parser("test", aliases=["t"], help="check archive entry streams")
    checking.add_argument("archive")
    checking.add_argument("--json", action="store_true")
    checking.add_argument("--password-file")

    converting = commands.add_parser("convert", help="convert an archive")
    converting.add_argument("source")
    converting.add_argument("dest")
    converting.add_argument("--password-file")

    info = commands.add_parser("info", help="show detected archive information")
    info.add_argument("source")
    info.add_argument("--json", action="store_true")

    detection = commands.add_parser("detect", help="detect an archive or codec")
    detection.add_argument("source")
    detection.add_argument("--json", action="store_true")
    return parser


def _json_value(value: Any) -> str:
    """Serialize public dataclasses into JSON-compatible values."""
    return json.dumps(
        value, default=lambda item: item.value if hasattr(item, "value") else str(item)
    )


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command-line interface and return its process exit code."""
    import oxar

    args = _parser().parse_args(argv)
    try:
        if args.command in ("list", "ls"):
            entries = oxar.list(args.archive, password=_password(args))
            if args.json:
                print(_json_value([asdict(entry) for entry in entries]))
            else:
                path_width = max((len(entry.path) for entry in entries), default=4)
                print(f"{'KIND':4} {'SIZE':>12}  PATH")
                for entry in entries:
                    size = "" if entry.size is None else str(entry.size)
                    print(f"{entry.kind.value:4} {size:>12}  {entry.path:<{path_width}}")
        elif args.command in ("extract", "x"):
            extract_report = oxar.extract(args.archive, args.dest, password=_password(args))
            print(f"extracted {extract_report.entries} entries to {args.dest}")
        elif args.command in ("test", "t"):
            test_report = oxar.test(args.archive, password=_password(args))
            print(
                _json_value(asdict(test_report))
                if args.json
                else f"{'ok' if test_report.ok else 'failed'}: {test_report.entries} entries"
            )
            if not test_report.ok:
                return 4
        elif args.command in ("detect", "info"):
            result = oxar.detect(args.source)
            output = asdict(result)
            print(_json_value(output) if args.json or args.command == "info" else output)
        elif args.command == "create":
            report = oxar.create(args.archive, args.inputs, format=args.format)
            print(f"created {report.entries} entries in {args.archive}")
        elif args.command == "append":
            report = oxar.append(args.archive, args.inputs)
            print(f"appended {report.entries} entries to {args.archive}")
        elif args.command == "convert":
            oxar.convert(args.source, args.dest, password=_password(args))
    except KeyboardInterrupt:
        return 130
    except oxar.UsageError as error:
        print(f"oxar: {error}", file=sys.stderr)
        return 2
    except oxar.SecurityError as error:
        print(f"oxar: {error}", file=sys.stderr)
        return 3
    except (oxar.FormatError, oxar.UnsupportedFeature) as error:
        print(f"oxar: {error}", file=sys.stderr)
        return 4
    except Exception as error:
        print(f"oxar: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
