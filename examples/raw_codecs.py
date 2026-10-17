"""Compress and decompress a byte string with an explicit output cap."""

import oxar


def main() -> None:
    original = b"oxar raw codec example\n" * 4096
    encoded = oxar.compress(original, "zstd", level=3)
    restored = oxar.decompress(encoded, "zstd", max_size=len(original))
    if restored != original:
        raise RuntimeError("codec round trip changed the input")

    print(f"input: {len(original)} bytes")
    print(f"compressed: {len(encoded)} bytes")
    print(f"decompressed: {len(restored)} bytes")


if __name__ == "__main__":
    main()
