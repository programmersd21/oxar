use oxar_core::format::tar::TarReader;
use oxar_core::format::{ArchiveReader, EntryKind};
use oxar_core::fsio::{Input, RandomSource};
use oxar_core::policy::{Limits, Policy};
use std::sync::Arc;

fn read_all(path: &str) -> Vec<(String, u64, EntryKind, Option<Vec<u8>>)> {
    let source = RandomSource::from_file(std::fs::File::open(path).unwrap()).unwrap();
    let input = Input::Random(source);
    let mut reader = TarReader::open(
        &input,
        None,
        Arc::new(Limits::default()),
        Default::default(),
    )
    .unwrap();
    let mut out = Vec::new();
    while let Some(entry) = reader.next_entry().unwrap() {
        let mut data = Vec::new();
        if entry.kind == EntryKind::File {
            use std::io::Read;
            let mut r = reader.open_current().unwrap();
            r.read_to_end(&mut data).unwrap();
        }
        out.push((
            entry.path.clone(),
            entry.size.unwrap_or(0),
            entry.kind,
            Some(data),
        ));
    }
    out
}

#[test]
fn reads_gnu_tar_plain() {
    let entries = read_all("/tmp/opencode/plain.tar");
    let names: Vec<_> = entries.iter().map(|e| e.0.as_str()).collect();
    assert!(names.contains(&"a.txt"), "{names:?}");
    assert!(names.contains(&"link.txt"), "{names:?}");
    assert!(names.contains(&"sparse.bin"), "{names:?}");
    let sparse = entries.iter().find(|e| e.0 == "sparse.bin").unwrap();
    assert_eq!(sparse.1, 4 * 1024 * 1024);
    let data = sparse.3.as_ref().unwrap();
    assert!(data.iter().any(|b| *b != 0));
}

#[test]
fn reads_gnu_tar_pax() {
    let entries = read_all("/tmp/opencode/pax.tar");
    assert!(entries.iter().any(|e| e.0 == "a.txt"));
}

#[test]
fn _policy_unused() {
    let _ = Policy::default();
}
