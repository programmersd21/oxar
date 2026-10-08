use oxar_core::extract::extract;
use oxar_core::fsio::RandomSource;
use oxar_core::policy::Policy;
use oxar_core::progress::CancelToken;
use oxar_core::sink::{FsSink, Sink};
use std::sync::Arc;

#[test]
fn zip_roundtrip_through_reader_and_sink() {
    // Create zip
    let items = vec![(
        oxar_core::format::NewEntry {
            path: "a/b.txt".into(),
            kind: oxar_core::format::EntryKind::File,
            mode: Some(0o644),
            mtime_ns: Some(1_000_000_000),
            link_target: None,
            size_hint: Some(4),
            method: None,
            level: None,
            password: None,
        },
        b"spam".to_vec(),
    )];
    let mut buf = Vec::new();
    {
        let mut writer = std::io::Cursor::new(&mut buf);
        oxar_core::format::zip::write_zip(&mut writer, &items, Some("comment"), None).unwrap();
    }

    // Read via ZipReader
    let source = RandomSource::from_bytes(std::sync::Arc::from(buf.into_boxed_slice()));
    let mut reader = oxar_core::format::zip_reader::ZipReader::new(source).unwrap();

    // Extract
    let dest_binding = tempfile::tempdir().unwrap();
    let dest = dest_binding.path().join("dest");
    std::fs::create_dir_all(&dest).unwrap();
    let sink: Arc<dyn Sink> = Arc::new(FsSink::new(&dest, Arc::new(Policy::default())).unwrap());
    let report = extract(
        &mut reader,
        sink,
        Policy::default(),
        None,
        &CancelToken::new(),
    )
    .unwrap();
    assert_eq!(report.entries, 1);
    assert_eq!(
        std::fs::read_to_string(dest.join("a").join("b.txt")).unwrap(),
        "spam".to_string()
    );
}
