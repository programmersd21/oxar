use oxar_core::format;
use oxar_core::format::zip;

#[test]
fn zip_roundtrip_plain() {
    let items = vec![(
        format::NewEntry {
            path: "hello.txt".into(),
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
    {
        let mut writer = std::io::Cursor::new(&mut buf);
        oxar_core::format::zip::write_zip(&mut writer, &items, Some("comment"), None).unwrap();
    }
    let entries = zip::read_zip_entries(std::io::Cursor::new(buf), None).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].path, "hello.txt");
    assert_eq!(entries[0].size, Some(4));
    assert_eq!(entries[0].comment, None); // entry-level only
}
#[test]
fn zip_roundtrip_aes() {
    let items = vec![(
        format::NewEntry {
            path: "secret.txt".into(),
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
    {
        let mut writer = std::io::Cursor::new(&mut buf);
        oxar_core::format::zip::write_zip(&mut writer, &items, None, Some(b"pass")).unwrap();
    }
    let entries = zip::read_zip_entries(std::io::Cursor::new(buf), Some(b"pass")).unwrap();
    assert_eq!(entries.len(), 1);
    assert!(entries[0].encrypted);
}
