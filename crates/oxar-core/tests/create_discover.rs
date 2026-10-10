use oxar_core::create::{discover, to_new_entries};
use std::fs;
#[test]
fn discover_orders_and_lists() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("b.txt"), b"b").unwrap();
    fs::create_dir(dir.path().join("a")).unwrap();
    fs::write(dir.path().join("a").join("c.txt"), b"c").unwrap();
    let entries = discover(dir.path(), false).unwrap();
    let names: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
    // deterministic byte sort
    let mut sorted = names.clone();
    sorted.sort();
    assert_eq!(names, sorted);
    assert!(names.contains(&"a/c.txt"));
    assert!(names.contains(&"b.txt"));
    let ne = to_new_entries(&entries);
    assert_eq!(ne.len(), entries.len());
}
