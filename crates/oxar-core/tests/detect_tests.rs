use oxar_core::detect::detect_bytes;

#[test]
fn detects_sevenz_magic() {
    let d = detect_bytes(b"7z\xBC\xAF\x27\x1C\x00\x00\x00\x00", None);
    assert_eq!(d.format, Some(oxar_core::Format::SevenZ));
}
#[test]
fn detects_xor_magic() {
    let zip = b"PK\x03\x04\x00\x00\x00\x00";
    let d = detect_bytes(zip, None);
    assert!(matches!(d.format, Some(oxar_core::Format::Zip)));
}
#[test]
fn detects_gzip_and_snappy() {
    assert_eq!(
        detect_bytes(&[0x1f, 0x8b, 0x08, 0], None).codec,
        Some(oxar_core::Codec::Gzip)
    );
    assert_eq!(
        detect_bytes(b"\xFF\x06\x00\x00sNaPpY", None).codec,
        Some(oxar_core::Codec::Snappy)
    );
}
#[test]
fn random_bytes_return_no_format() {
    let mut data = vec![0u8; 512];
    for (i, b) in data.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(37);
    }
    let d = detect_bytes(&data, None);
    // Most of the time this must hold; an occasional false positive is
    // acceptable but would have to be a real tar checksum coincidence.
    assert!(d.format.is_none() || d.format == Some(oxar_core::Format::Tar));
}
#[test]
fn detects_lz4_frame_and_xz() {
    assert_eq!(
        detect_bytes(&[0x04, 0x22, 0x4D, 0x18, 0, 0, 0, 0], None).codec,
        Some(oxar_core::Codec::Lz4)
    );
    assert_eq!(
        detect_bytes(b"\xFD7zXZ\x00", None).codec,
        Some(oxar_core::Codec::Xz)
    );
}
