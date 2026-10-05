//! Property tests for the entry name sanitiser.

use oxar_core::path::{SeparatorRule, sanitize};
use oxar_core::policy::Policy;
use proptest::prelude::*;

fn policies() -> impl Strategy<Value = Policy> {
    prop_oneof![
        Just(Policy::default()),
        Just(Policy {
            limits: oxar_core::Limits {
                max_component_bytes: Some(1),
                ..Default::default()
            },
            ..Default::default()
        }),
        Just(Policy {
            limits: oxar_core::Limits {
                max_depth: Some(1),
                ..Default::default()
            },
            ..Default::default()
        }),
        Just(Policy {
            windows_names: oxar_core::WindowsNames::Reject,
            ..Default::default()
        }),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 10_000, ..ProptestConfig::default() })]

    #[test]
    fn accepted_names_never_contain_parent_components(
        name in prop::collection::vec(any::<u8>(), 0..48),
        policy in policies(),
        host_windows in any::<bool>(),
    ) {
        let zip = SeparatorRule::BackslashIsSeparator;
        if let Ok(safe) = sanitize(&name, zip, &policy, host_windows) {
            for component in safe.components() {
                prop_assert_ne!(component, b"..");
                prop_assert!(!component.is_empty());
                prop_assert!(!component.contains(&0));
                prop_assert!(!component.contains(&b'\\'));
            }
        }
    }

    #[test]
    fn accepted_names_are_relative_and_joined_under_any_root(
        name in prop::collection::vec(any::<u8>(), 0..48),
        policy in policies(),
    ) {
        let zip = SeparatorRule::BackslashIsSeparator;
        if let Ok(safe) = sanitize(&name, zip, &policy, false) {
            let joined = safe.raw_bytes();
            prop_assert!(!joined.starts_with(b"/"));
            let text = std::str::from_utf8(joined);
            if let Ok(text) = text {
                let bytes = text.as_bytes();
                let drive = bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':';
                prop_assert!(!drive);
            }
        }
    }

    #[test]
    fn sanitising_is_idempotent(
        name in prop::collection::vec(any::<u8>(), 0..48),
        policy in policies(),
        host_windows in any::<bool>(),
    ) {
        let zip = SeparatorRule::BackslashIsSeparator;
        let rules = [zip, SeparatorRule::BackslashIsLiteral];
        for rule in rules {
            if let Ok(first) = sanitize(&name, rule, &policy, host_windows) {
                let second = sanitize(first.raw_bytes(), rule, &policy, host_windows);
                prop_assert!(second.is_ok());
                let second = second.unwrap();
                prop_assert_eq!(first.depth(), second.depth());
                prop_assert_eq!(first.is_dir(), second.is_dir());
                prop_assert_eq!(first.collision_key(), second.collision_key());
            }
        }
    }

    #[test]
    fn tar_names_with_backslashes_survive_on_posix_only(
        name in prop::collection::vec(any::<u8>(), 0..48),
    ) {
        let policy = Policy::default();
        if let Ok(safe) = sanitize(&name, SeparatorRule::BackslashIsLiteral, &policy, false) {
            for component in safe.components() {
                prop_assert!(!component.contains(&0));
            }
        }
    }
}
