use oxar_core::extract::extract as extract_archive;
use oxar_core::format;
use oxar_core::fsio::RandomSource;
use oxar_core::sink::{FsSink, Sink};

#[test]
fn tar_roundtrip_through_reader_and_sink() {
    let items = vec![(
        format::NewEntry {
            path: "a/b.txt".into(),
            kind: format::EntryKind::File,
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
    format::tar::write_tar(&mut buf, &items).unwrap();
    let source = RandomSource::from_bytes(std::sync::Arc::from(buf.clone().into_boxed_slice()));
    let mut reader = format::tar::TarReader::from_reader(source).unwrap();

    use oxar_core::policy::Policy;
    use oxar_core::progress::CancelToken;
    use std::sync::Arc;

    let binding = tempfile::tempdir().unwrap();
    let dest = binding.path().join("dest");
    std::fs::create_dir_all(&dest).unwrap();

    let sink: Arc<dyn Sink> = Arc::new(FsSink::new(&dest, Arc::new(Policy::default())).unwrap());
    let report = extract_archive(
        &mut reader,
        sink,
        Policy::default(),
        None,
        &CancelToken::new(),
    )
    .unwrap();
    assert_eq!(report.entries, 1);
    assert!(dest.join("a").join("b.txt").exists());
    assert_eq!(
        std::fs::read_to_string(dest.join("a").join("b.txt")).unwrap(),
        "spam".to_string()
    );
}
