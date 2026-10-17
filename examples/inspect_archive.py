"""Create a sample archive, inspect its entries, and verify its contents."""

from pathlib import Path
from tempfile import TemporaryDirectory

import oxar


def main() -> None:
    with TemporaryDirectory(prefix="oxar-inspect-") as temporary:
        root = Path(temporary)
        source = root / "input"
        source.mkdir()
        (source / "notes.txt").write_text("archive inspection example\n", encoding="utf-8")
        archive_path = root / "sample.zip"
        oxar.create(archive_path, [source])

        for entry in oxar.list(archive_path):
            print(f"{entry.kind.value:8} {entry.size!s:>8}  {entry.path}")

        with oxar.open(archive_path) as archive:
            member = archive.names()[0]
            content = archive.read(member, max_size=1024)
            print(f"read {member}: {content.decode('utf-8').rstrip()}")

        result = oxar.test(archive_path)
        print(f"integrity: {'ok' if result.ok else 'failed'} ({result.entries} entries)")


if __name__ == "__main__":
    main()
