use oxar_core::codec;
#[test]
fn gzip_roundtrip() {
    let data = b"the quick brown fox".repeat(10);
    let c = codec::gzip::compress(&data, 6, 1).unwrap();
    let d = codec::gzip::decompress(&c, &oxar_core::Limits::default(), None).unwrap();
    assert_eq!(data, d);
}
#[test]
fn zlib_roundtrip() {
    let data = b"hello world!".repeat(5);
    let c = codec::zlib::compress(&data, 6);
    let d = codec::zlib::decompress(&c, &oxar_core::Limits::default(), None).unwrap();
    assert_eq!(data, d);
}
#[test]
fn deflate_roundtrip() {
    let data = b"deflate me".repeat(20);
    let c = codec::deflate::compress(&data, 6);
    let d = codec::deflate::decompress(&c, &oxar_core::Limits::default(), None).unwrap();
    assert_eq!(data, d);
}
#[test]
fn bzip2_roundtrip() {
    let data = b"bzip2 payload".repeat(20);
    let c = codec::bzip2::compress(&data, 9);
    let d = codec::bzip2::decompress(&c, &oxar_core::Limits::default(), None).unwrap();
    assert_eq!(data, d);
}
#[test]
fn xz_roundtrip() {
    let data = b"xz payload".repeat(20);
    let c = codec::xz::compress(&data, 6, false, 1).unwrap();
    let d = codec::xz::decompress(&c, &oxar_core::Limits::default(), None).unwrap();
    assert_eq!(data, d);
}
#[test]
fn lzma_roundtrip_ignores_unsupported_parallelism() {
    let data = b"lzma payload".repeat(20);
    let c = codec::lzma::compress(&data, 6, false, 8).unwrap();
    let d = codec::lzma::decompress(&c, &oxar_core::Limits::default(), None).unwrap();
    assert_eq!(data, d);
}
#[test]
fn zstd_roundtrip() {
    let data = b"zstd payload".repeat(20);
    let c = codec::zstd::compress(&data, 3, 1, 20, false).unwrap();
    let d = codec::zstd::decompress(&c, &oxar_core::Limits::default(), None).unwrap();
    assert_eq!(data, d);
}
#[test]
fn lz4_roundtrip() {
    let data = b"lz4 payload".repeat(20);
    let c = codec::lz4::compress(&data, 0).unwrap();
    let d = codec::lz4::decompress(&c, &oxar_core::Limits::default(), None).unwrap();
    assert_eq!(data, d);
}
#[test]
fn snappy_roundtrip() {
    let data = b"snappy payload".repeat(20);
    let c = codec::snappy::compress(&data).unwrap();
    let d = codec::snappy::decompress(&c, &oxar_core::Limits::default(), None).unwrap();
    assert_eq!(data, d);
}
#[test]
fn brotli_roundtrip() {
    let data = b"brotli payload".repeat(20);
    let c = codec::brotli::compress(&data, 6, 22).unwrap();
    let d = codec::brotli::decompress(&c, &oxar_core::Limits::default(), None).unwrap();
    assert_eq!(data, d);
}
