#[test]
fn reads_sevenz_from_7z_binary() {
    use oxar_core::format::sevenz;
    let d = tempfile::tempdir().unwrap();
    let out = d.path().join("x.7z");
    std::fs::write(d.path().join("a.txt"), b"hello").unwrap();
    let r = std::process::Command::new("7z")
        .arg("a")
        .arg(&out)
        .arg(d.path().join("a.txt"))
        .output();
    let r = match r {
        Ok(r) => r,
        Err(_) => {
            eprintln!("skipping: 7z is not available");
            return;
        }
    };
    assert!(r.status.success(), "{}", String::from_utf8_lossy(&r.stderr));
    let names = sevenz::list_sevenz(&out, None).unwrap();
    assert!(names.iter().any(|n| n.contains("a.txt")), "{names:?}");
    let _ = sevenz::read_sevenz_entries(&out, None).unwrap();
}
#[test]
fn sevenz_roundtrip_geo() {
    use oxar_core::format::sevenz;
    let d = tempfile::tempdir().unwrap();
    let out = d.path().join("ox.7z");
    let items = vec![(
        oxar_core::format::NewEntry {
            path: "g/x.txt".into(),
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
    let f = sevenz::create_sevenz(std::fs::File::create(&out).unwrap(), &items, None).unwrap();
    drop(f);
    let status = std::process::Command::new("7z").arg("t").arg(&out).output();
    let status = match status {
        Ok(status) => status,
        Err(_) => {
            eprintln!("skipping: 7z is not available");
            return;
        }
    };
    assert!(
        status.status.success(),
        "7z t failed: {}",
        String::from_utf8_lossy(&status.stderr)
    );
}
