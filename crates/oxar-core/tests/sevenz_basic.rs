#[test]
fn sevenz_create_and_list() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.7z");
    let items = vec![(
        oxar_core::format::NewEntry {
            path: "hello.txt".into(),
            kind: oxar_core::format::EntryKind::File,
            mode: Some(0o644),
            mtime_ns: Some(1),
            link_target: None,
            size_hint: Some(4),
            method: None,
            level: None,
            password: None,
        },
        b"spam".to_vec(),
    )];
    let f = oxar_core::format::sevenz::create_sevenz(
        std::fs::File::create(&out).unwrap(),
        &items,
        None,
    )
    .unwrap();
    drop(f);
    let names = oxar_core::format::sevenz::list_sevenz(&out, None).unwrap();
    assert!(names.iter().any(|n| n.contains("hello.txt")), "{:?}", names);
}
#[test]
fn sevenz_create_and_list_password() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("enc.7z");
    let items = vec![(
        oxar_core::format::NewEntry {
            path: "secret.txt".into(),
            kind: oxar_core::format::EntryKind::File,
            mode: Some(0o644),
            mtime_ns: Some(1),
            link_target: None,
            size_hint: Some(4),
            method: None,
            level: None,
            password: None,
        },
        b"spam".to_vec(),
    )];
    let f = oxar_core::format::sevenz::create_sevenz(
        std::fs::File::create(&out).unwrap(),
        &items,
        Some("pass"),
    )
    .unwrap();
    drop(f);
    assert!(oxar_core::format::sevenz::list_sevenz(&out, Some("pass")).is_ok());
    assert!(oxar_core::format::sevenz::list_sevenz(&out, None).is_err());
}
