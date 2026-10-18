use oxar_core::format::tar::TarWriter;
use oxar_core::format::{EntryKind, NewEntry};

fn entry(path: &str, kind: EntryKind, size: Option<u64>) -> NewEntry {
    NewEntry {
        path: path.to_string(),
        kind,
        mode: Some(if kind == EntryKind::Dir { 0o755 } else { 0o644 }),
        mtime_ns: Some(1_700_000_000_500_000_000),
        link_target: None,
        size_hint: size,
        method: None,
        level: None,
        password: None,
    }
}

#[test]
fn gnu_tar_reads_what_we_write() {
    let long = "a/very/long/path/that/exceeds/one/hundred/bytes/\
                and/keeps/going/for/a/while/name.txt";
    let unicode = "café/日本語.txt";
    let mut out = Vec::new();
    let mut writer = TarWriter::new(&mut out);
    let mut data: &[u8] = b"hello";
    writer
        .add(&entry("plain.txt", EntryKind::File, Some(5)), &mut data)
        .unwrap();
    let big = vec![7u8; 300_000];
    let mut reader: &[u8] = &big;
    writer
        .add(&entry(long, EntryKind::File, Some(300_000)), &mut reader)
        .unwrap();
    let mut reader: &[u8] = "unicode content".as_bytes();
    writer
        .add(&entry(unicode, EntryKind::File, Some(15)), &mut reader)
        .unwrap();
    writer.finish().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("written.tar");
    std::fs::write(&archive, &out).unwrap();
    let status = match std::process::Command::new("tar")
        .arg("-tf")
        .arg(&archive)
        .output()
    {
        Ok(status) => status,
        Err(_) => {
            eprintln!("skipping: system tar is not available");
            return;
        }
    };
    assert!(
        status.status.success(),
        "tar -tf failed: {}",
        String::from_utf8_lossy(&status.stderr)
    );
    let listing = String::from_utf8_lossy(&status.stdout);
    assert!(listing.contains("plain.txt"), "{listing}");
    assert!(listing.contains("name.txt"), "{listing}");
    #[cfg(not(windows))]
    assert!(listing.contains("日本語.txt"), "{listing}");
    let extract_dir = dir.path().join("out");
    std::fs::create_dir(&extract_dir).unwrap();
    let extract = std::process::Command::new("tar")
        .arg("-xf")
        .arg(&archive)
        .arg("-C")
        .arg(&extract_dir)
        .output()
        .unwrap();
    assert!(extract.status.success());
}
