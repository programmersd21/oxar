"""Extract selected archive members with an explicit output size limit."""

from pathlib import Path
from tempfile import TemporaryDirectory

import oxar


def main() -> None:
    with TemporaryDirectory(prefix="oxar-extract-") as temporary:
        root = Path(temporary)
        source = root / "input"
        source.mkdir()
        (source / "keep.txt").write_text("selected member\n", encoding="utf-8")
        (source / "also-here.txt").write_text("not selected\n", encoding="utf-8")
        archive_path = root / "sample.zip"
        oxar.create(archive_path, [source])

        # The selected name is obtained from the archive to avoid assuming how
        # the source directory is represented in member paths.
        entries = oxar.list(archive_path)
        selected = next(entry.path for entry in entries if entry.path.endswith("keep.txt"))
        destination = root / "restored"
        policy = oxar.Policy(max_entry_size=1024, max_total_size=1024)
        report = oxar.extract(archive_path, destination, members=[selected], policy=policy)

        print(f"extracted {report.entries} entry to {destination.name}/")
        print((destination / selected).read_text(encoding="utf-8"), end="")


if __name__ == "__main__":
    main()
