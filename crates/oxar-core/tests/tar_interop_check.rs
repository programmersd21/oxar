use oxar_core::format::tar::TarReader;
use oxar_core::format::{ArchiveReader, EntryKind};
use oxar_core::fsio::{Input, RandomSource};
use oxar_core::policy::{Limits, Policy};
use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;

fn read_all(path: &Path) -> Vec<(String, u64, EntryKind, Option<Vec<u8>>)> {
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

fn run_tar(args: &[&str], cwd: &Path) -> bool {
    match Command::new("tar").args(args).current_dir(cwd).output() {
        Ok(output) => output.status.success(),
        Err(_) => false,
    }
}

/// Build the fixtures with the platform tar. Returns None when tar is absent.
fn make_plain_tar(dir: &Path) -> Option<std::path::PathBuf> {
    std::fs::write(dir.join("a.txt"), b"hello from oxar\n").ok()?;
    #[cfg(unix)]
    std::os::unix::fs::symlink("a.txt", dir.join("link.txt")).ok()?;
    let mut sparse = std::fs::File::create(dir.join("sparse.bin")).ok()?;
    let mut data = vec![0u8; 4 * 1024 * 1024];
    data[0] = b's';
    if let Some(last) = data.last_mut() {
        *last = b'e';
    }
    sparse.write_all(&data).ok()?;
    drop(sparse);
    for with_sparse_flag in [true, false] {
        let mut args = Vec::new();
        if with_sparse_flag {
            args.push("--sparse");
        }
        args.extend(["-cf", "plain.tar", "a.txt"]);
        #[cfg(unix)]
        args.push("link.txt");
        args.push("sparse.bin");
        if run_tar(&args, dir) {
            return Some(dir.join("plain.tar"));
        }
    }
    None
}

fn make_pax_tar(dir: &Path) -> Option<std::path::PathBuf> {
    std::fs::write(dir.join("a.txt"), b"hello from oxar\n").ok()?;
    if run_tar(&["--format=pax", "-cf", "pax.tar", "a.txt"], dir) {
        Some(dir.join("pax.tar"))
    } else {
        None
    }
}

#[test]
fn reads_gnu_tar_plain() {
    let dir = tempfile::tempdir().unwrap();
    let Some(plain) = make_plain_tar(dir.path()) else {
        eprintln!("skipping: system tar is not available");
        return;
    };
    let entries = read_all(&plain);
    let names: Vec<_> = entries.iter().map(|e| e.0.as_str()).collect();
    assert!(names.contains(&"a.txt"), "{names:?}");
    #[cfg(unix)]
    assert!(names.contains(&"link.txt"), "{names:?}");
    assert!(names.contains(&"sparse.bin"), "{names:?}");
    let sparse = entries.iter().find(|e| e.0 == "sparse.bin").unwrap();
    assert_eq!(sparse.1, 4 * 1024 * 1024);
    let data = sparse.3.as_ref().unwrap();
    assert!(data.iter().any(|b| *b != 0));
}

#[test]
fn reads_gnu_tar_pax() {
    let dir = tempfile::tempdir().unwrap();
    let Some(pax) = make_pax_tar(dir.path()) else {
        eprintln!("skipping: system tar is not available");
        return;
    };
    let entries = read_all(&pax);
    assert!(entries.iter().any(|e| e.0 == "a.txt"));
}

#[test]
fn _policy_unused() {
    let _ = Policy::default();
}
