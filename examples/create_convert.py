"""Create ZIP and TAR archives, then convert ZIP to TAR."""

from pathlib import Path
from tempfile import TemporaryDirectory

import oxar


def main() -> None:
    with TemporaryDirectory(prefix="oxar-create-") as temporary:
        root = Path(temporary)
        project = root / "project"
        project.mkdir()
        (project / "readme.txt").write_text("created by oxar\n", encoding="utf-8")
        (project / "data.bin").write_bytes(bytes(range(256)))

        zip_path = root / "project.zip"
        tar_path = root / "project.tar"
        converted_path = root / "converted.tar"

        created = oxar.create(zip_path, [project], format="zip")
        oxar.create(tar_path, [project], format="tar")
        converted = oxar.convert(zip_path, converted_path, format="tar")

        print(f"created ZIP: {created.entries} entries, {created.bytes_out} bytes")
        print(f"created TAR: {len(oxar.list(tar_path))} entries")
        print(f"converted ZIP to TAR: {converted.entries} entries")


if __name__ == "__main__":
    main()
