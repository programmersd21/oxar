#![no_main]
use libfuzzer_sys::fuzz_target;
use oxar_core::path::{sanitize, SeparatorRule};
use oxar_core::policy::Policy;

fuzz_target!(|data: &[u8]| {
    let policy = Policy::default();
    let _ = sanitize(data, SeparatorRule::BackslashIsSeparator, &policy, false);
    let _ = sanitize(data, SeparatorRule::BackslashIsLiteral, &policy, false);
});
