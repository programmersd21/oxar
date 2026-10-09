use oxar_core::format;

#[test]
fn tar_name_sanity() {
    // Build minimal tar with one entry and read it back
    let items = vec![(
        format::NewEntry {
            path: "hello.txt".to_string(),
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
    let entries = format::tar::read_entries(std::io::Cursor::new(buf));
    let entries: Vec<_> = entries.into_iter().collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].path, "hello.txt");
    assert_eq!(entries[0].size, Some(4));
}
