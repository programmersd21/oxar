use std::fs;
use std::sync::Arc;

use oxar_core::budget::{Budget, EntryScope};
use oxar_core::path;
use oxar_core::path::SeparatorRule;
use oxar_core::policy::Policy;
use oxar_core::progress::CancelToken;
use oxar_core::sink::{FileAttrs, FsSink, Sink, VirtualSink};

fn make_safe(name: &[u8]) -> path::SafePath {
    path::sanitize(
        name,
        SeparatorRule::BackslashIsSeparator,
        &Policy::default(),
        false,
    )
    .unwrap()
}

#[test]
fn fs_sink_round_trips_a_file() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("dest");
    fs::create_dir_all(&dest).unwrap();
    let sink = FsSink::new(&dest, Arc::new(Policy::default())).unwrap();
    let p = make_safe(b"a/b.txt");
    let mut data = std::io::Cursor::new(b"hello".to_vec());
    let mut scope = EntryScope::detached(Budget::new(Policy::default().limits, CancelToken::new()));
    assert_eq!(
        sink.put_file(
            &p,
            &FileAttrs::default(),
            &oxar_core::EntryExpect::default(),
            &mut data,
            &mut scope
        )
        .unwrap(),
        oxar_core::PutOutcome::Written(5)
    );
    sink.finish().unwrap();
    assert_eq!(fs::read(dest.join("a").join("b.txt")).unwrap(), b"hello");
}

#[cfg(unix)]
#[test]
fn fs_sink_blocks_symlink_prefix() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("dest");
    fs::create_dir_all(&dest).unwrap();
    let outside = dir.path().join("outside");
    fs::create_dir_all(&outside).unwrap();
    fs::write(outside.join("secret"), b"do-not-touch").unwrap();
    std::os::unix::fs::symlink(&outside, dest.join("evil")).unwrap();
    let sink = FsSink::new(&dest, Arc::new(Policy::default())).unwrap();
    let p = make_safe(b"evil/x");
    let mut data = std::io::Cursor::new(b"payload".to_vec());
    let mut scope = EntryScope::detached(Budget::new(Policy::default().limits, CancelToken::new()));
    assert!(
        sink.put_file(
            &p,
            &FileAttrs::default(),
            &oxar_core::EntryExpect::default(),
            &mut data,
            &mut scope
        )
        .is_err()
    );
    assert_eq!(fs::read(outside.join("secret")).unwrap(), b"do-not-touch");
}

#[test]
fn virtual_sink_root_invariant_holds() {
    let v = VirtualSink::new(Arc::new(Policy::default()));
    let p = make_safe(b"root/deep/file.txt");
    let mut data = std::io::Cursor::new(b"payload".to_vec());
    let mut scope = EntryScope::detached(Budget::new(Policy::default().limits, CancelToken::new()));
    v.put_file(
        &p,
        &FileAttrs::default(),
        &oxar_core::EntryExpect::default(),
        &mut data,
        &mut scope,
    )
    .unwrap();
    let target = make_safe(b"root/link_target");
    let mut d2 = std::io::Cursor::new(b"x".to_vec());
    let mut s2 = EntryScope::detached(Budget::new(Policy::default().limits, CancelToken::new()));
    v.put_file(
        &target,
        &FileAttrs::default(),
        &oxar_core::EntryExpect::default(),
        &mut d2,
        &mut s2,
    )
    .unwrap();
    for key in v.nodes().keys() {
        assert!(!key.is_empty());
        for comp in key {
            assert!(!comp.is_empty());
        }
    }
}

#[test]
fn virtual_sink_symlink_prefix_blocks_write() {
    let v = VirtualSink::new(Arc::new(Policy::default()));
    let link = make_safe(b"l");
    v.put_symlink(&link, b"value", &FileAttrs::default())
        .unwrap();
    let file = make_safe(b"l/x");
    let mut data = std::io::Cursor::new(b"hello".to_vec());
    let mut scope = EntryScope::detached(Budget::new(Policy::default().limits, CancelToken::new()));
    assert!(
        v.put_file(
            &file,
            &FileAttrs::default(),
            &oxar_core::EntryExpect::default(),
            &mut data,
            &mut scope
        )
        .is_err()
    );
}

#[test]
fn virtual_sink_crc_mismatch_fails() {
    let v = VirtualSink::new(Arc::new(Policy::default()));
    let p = make_safe(b"a");
    let mut data = std::io::Cursor::new(b"hello".to_vec());
    let mut scope = EntryScope::detached(Budget::new(Policy::default().limits, CancelToken::new()));
    let res = v.put_file(
        &p,
        &FileAttrs::default(),
        &oxar_core::EntryExpect {
            crc32: Some(0),
            size: None,
        },
        &mut data,
        &mut scope,
    );
    assert!(res.is_err());
}
