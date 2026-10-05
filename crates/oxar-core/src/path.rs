//! Entry name sanitisation: raw name bytes in, a `SafePath` that can only
//! name something inside the destination root, or an error.
//!
//! The rules here cannot be disabled by policy: no `..` component anywhere, no
//! absolute name, no drive prefix, no UNC prefix, no NUL byte, and a collision
//! key that folds case and Unicode normalisation so two names that a
//! case-insensitive or normalising filesystem would treat as one are
//! detected before anything is written.

use std::path::PathBuf;

use caseless::default_case_fold_str;
use unicode_normalization::UnicodeNormalization;

use crate::error::{Error, Location, Result};
use crate::policy::Policy;

/// How a format treats the backslash character in stored names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeparatorRule {
    /// Backslash is a path separator and is rewritten to `/`. Zip and 7z
    /// entries written by Windows tools use it this way.
    BackslashIsSeparator,
    /// Backslash is an ordinary name character. Tar names keep it literally
    /// on POSIX hosts and are rejected on Windows hosts.
    BackslashIsLiteral,
}

/// A name that is safe to combine with a destination root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafePath {
    components: Vec<Vec<u8>>,
    is_dir: bool,
    raw: Vec<u8>,
    display: String,
    key: String,
}

impl SafePath {
    /// Path components, separator free, in order.
    pub fn components(&self) -> impl Iterator<Item = &[u8]> {
        self.components.iter().map(Vec::as_slice)
    }

    /// Number of components.
    #[must_use]
    pub fn depth(&self) -> usize {
        self.components.len()
    }

    /// Whether the name ended with a separator.
    #[must_use]
    pub fn is_dir(&self) -> bool {
        self.is_dir
    }

    /// Normalised name bytes, joined with `/`.
    #[must_use]
    pub fn raw_bytes(&self) -> &[u8] {
        &self.raw
    }

    /// Display form; bytes that are not valid UTF-8 are rendered with the
    /// replacement character. The binding layer re-decodes `raw_bytes` with
    /// surrogateescape to build the Python `str`.
    #[must_use]
    pub fn display(&self) -> &str {
        &self.display
    }

    /// Collision key: per component, NFC then full case fold for valid UTF-8,
    /// or tagged hex for invalid bytes.
    #[must_use]
    pub fn collision_key(&self) -> &str {
        &self.key
    }

    /// A platform path built from the components. Fails on Windows when a
    /// component is not valid UTF-8, because Windows paths are UTF-16.
    pub fn to_path_buf(&self) -> Result<PathBuf> {
        let mut path = PathBuf::new();
        for component in &self.components {
            if cfg!(windows) {
                let text = std::str::from_utf8(component).map_err(|_| Error::UnsafePath {
                    detail: "name is not valid UTF-8 and cannot be represented on Windows".into(),
                    loc: Location::new(),
                })?;
                path.push(text);
            } else {
                use std::os::unix::ffi::OsStrExt;
                path.push(std::ffi::OsStr::from_bytes(component));
            }
        }
        Ok(path)
    }

    /// Whether this path is a strict ancestor of `other`.
    #[must_use]
    pub fn is_ancestor_of(&self, other: &SafePath) -> bool {
        let own = self.components.len();
        other.components.len() > own
            && self
                .components
                .iter()
                .zip(other.components.iter())
                .all(|(a, b)| a == b)
    }
}

fn component_key(component: &[u8]) -> String {
    match std::str::from_utf8(component) {
        Ok(text) => {
            let nfc: String = text.nfc().collect();
            let mut key = String::with_capacity(nfc.len().saturating_add(1));
            key.push('u');
            key.push_str(&default_case_fold_str(&nfc));
            key
        }
        Err(_) => {
            let mut key =
                String::with_capacity(component.len().saturating_mul(2).saturating_add(1));
            key.push('b');
            for byte in component {
                key.push_str(&format!("{byte:02x}"));
            }
            key
        }
    }
}

fn is_windows_reserved(component: &[u8]) -> bool {
    let base = match component.iter().position(|byte| *byte == b'.') {
        Some(position) => &component[..position],
        None => component,
    };
    const NAMES: [&[u8]; 22] = [
        b"CON", b"PRN", b"AUX", b"NUL", b"COM1", b"COM2", b"COM3", b"COM4", b"COM5", b"COM6",
        b"COM7", b"COM8", b"COM9", b"LPT1", b"LPT2", b"LPT3", b"LPT4", b"LPT5", b"LPT6", b"LPT7",
        b"LPT8", b"LPT9",
    ];
    let upper: Vec<u8> = base.iter().map(u8::to_ascii_uppercase).collect();
    NAMES.contains(&upper.as_slice())
}

fn looks_like_drive(component: &[u8]) -> bool {
    component.len() >= 2 && component[0].is_ascii_alphabetic() && component[1] == b':'
}

fn check_windows_component(component: &[u8], display: &str) -> Result<()> {
    let unsafe_path = |detail: &str| Error::UnsafePath {
        detail: detail.to_owned(),
        loc: Location::new(),
    };
    if component.iter().any(|byte| *byte < 0x20) {
        return Err(unsafe_path("name contains a control character"));
    }
    if component.iter().any(|byte| b"<>:\"|?*".contains(byte)) {
        return Err(unsafe_path(
            "name contains a character that is invalid on Windows",
        ));
    }
    if component
        .last()
        .is_some_and(|byte| *byte == b'.' || *byte == b' ')
    {
        return Err(unsafe_path("name ends with a dot or a space"));
    }
    if is_windows_reserved(component) {
        return Err(unsafe_path("name is a reserved device name on Windows"));
    }
    if display.is_empty() {
        return Err(unsafe_path("name component is empty"));
    }
    Ok(())
}

/// Sanitise one entry name.
///
/// `host_windows` selects the host rule set and is explicit so tests can
/// exercise both rule sets on any platform.
pub fn sanitize(
    raw: &[u8],
    separators: SeparatorRule,
    policy: &Policy,
    host_windows: bool,
) -> Result<SafePath> {
    let reject = |detail: &str| -> Error {
        Error::UnsafePath {
            detail: detail.to_owned(),
            loc: Location::new(),
        }
    };

    if raw.is_empty() {
        return Err(reject("name is empty"));
    }
    if raw.contains(&0) {
        return Err(reject("name contains a NUL byte"));
    }

    // Zip and 7z names written on Windows use backslashes as separators.
    let normalised: Vec<u8> = match separators {
        SeparatorRule::BackslashIsSeparator => raw
            .iter()
            .map(|byte| if *byte == b'\\' { b'/' } else { *byte })
            .collect(),
        SeparatorRule::BackslashIsLiteral => {
            if host_windows && raw.contains(&b'\\') {
                return Err(reject("name contains a backslash on Windows"));
            }
            raw.to_vec()
        }
    };

    if normalised.first() == Some(&b'/') {
        return Err(reject("name is absolute"));
    }
    if looks_like_drive(&normalised) {
        return Err(reject("name starts with a drive letter"));
    }
    if !matches!(separators, SeparatorRule::BackslashIsLiteral)
        && normalised.len() >= 2
        && normalised[1] == b':'
        && normalised[0].is_ascii_alphabetic()
    {
        return Err(reject("name starts with a drive letter"));
    }

    let is_dir = normalised.last() == Some(&b'/') && normalised.len() > 1;
    let mut components: Vec<Vec<u8>> = Vec::new();
    for piece in normalised.split(|byte| *byte == b'/') {
        match piece {
            [] | b"." => continue,
            b".." => return Err(reject("name contains a parent directory component")),
            _ => components.push(piece.to_vec()),
        }
    }
    if components.is_empty() {
        return Err(reject("name resolves to no path components"));
    }

    let limits = &policy.limits;
    if let Some(max) = limits.max_depth
        && components.len() > max
    {
        return Err(Error::UnsafePath {
            detail: format!("name has more than {max} path components"),
            loc: Location::new(),
        });
    }
    if let Some(max) = limits.max_component_bytes
        && let Some(over) = components.iter().find(|component| component.len() > max)
    {
        return Err(Error::UnsafePath {
            detail: format!(
                "name component of {} bytes exceeds the {max} byte limit",
                over.len()
            ),
            loc: Location::new(),
        });
    }
    let joined_len = components
        .iter()
        .map(Vec::len)
        .fold(0usize, usize::saturating_add)
        .saturating_add(components.len().saturating_sub(1));
    if let Some(max) = limits.max_path_bytes
        && joined_len > max
    {
        return Err(Error::UnsafePath {
            detail: format!("name of more than {max} bytes"),
            loc: Location::new(),
        });
    }

    let windows_rules =
        policy.windows_names_active() || (host_windows && policy.windows_names_active());
    let verbose =
        windows_rules && matches!(policy.windows_names, crate::policy::WindowsNames::Auto);

    let display_pieces: Vec<String> = components
        .iter()
        .map(|component| String::from_utf8_lossy(component).into_owned())
        .collect();
    if windows_rules {
        for (component, display) in components.iter().zip(display_pieces.iter()) {
            check_windows_component(component, display)?;
        }
    }
    let _ = verbose;

    let display = display_pieces.join("/");
    let mut raw_out = Vec::with_capacity(joined_len);
    for (position, component) in components.iter().enumerate() {
        if position > 0 {
            raw_out.push(b'/');
        }
        raw_out.extend_from_slice(component);
    }
    if is_dir {
        raw_out.push(b'/');
    }

    let key = components
        .iter()
        .map(|component| component_key(component))
        .collect::<Vec<_>>()
        .join("/");

    Ok(SafePath {
        components,
        is_dir,
        raw: raw_out,
        display,
        key,
    })
}

/// Validate a symlink target under the `contained` policy.
///
/// The target must be relative, must not contain a NUL or a backslash, and
/// after dropping `.` components must consist of an optional prefix of `..`
/// followed by ordinary components: a `..` after an ordinary component is
/// rejected even when the lexical resolution would stay inside the root,
/// because an intermediate symlink can change the real resolution. The
/// resolved depth is checked against the entry's parent directory depth and
/// must never go below the root.
pub fn validate_symlink_target(
    target: &[u8],
    parent_depth: usize,
    policy: &Policy,
) -> Result<Vec<Vec<u8>>> {
    let reject = |detail: &str| -> Error {
        Error::UnsafeLink {
            detail: detail.to_owned(),
            loc: Location::new(),
        }
    };
    if target.is_empty() {
        return Err(reject("link target is empty"));
    }
    if target.contains(&0) {
        return Err(reject("link target contains a NUL byte"));
    }
    if target.contains(&b'\\') {
        return Err(reject("link target contains a backslash"));
    }
    if target.first() == Some(&b'/') {
        return Err(reject("link target is absolute"));
    }
    if looks_like_drive(target) {
        return Err(reject("link target starts with a drive letter"));
    }

    let mut resolved: Vec<Vec<u8>> = Vec::new();
    let mut depth = parent_depth;
    let mut seen_ordinary = false;
    for piece in target.split(|byte| *byte == b'/') {
        match piece {
            [] | b"." => continue,
            b".." => {
                if seen_ordinary {
                    return Err(reject(
                        "link target has a parent component after an ordinary component",
                    ));
                }
                if depth == 0 {
                    return Err(reject("link target escapes the destination"));
                }
                depth = depth.saturating_sub(1);
                resolved.pop();
            }
            other => {
                if let Some(max) = policy.limits.max_component_bytes
                    && other.len() > max
                {
                    return Err(reject("link target component exceeds the size limit"));
                }
                seen_ordinary = true;
                resolved.push(other.to_vec());
                depth = depth.saturating_add(1);
            }
        }
    }
    if let Some(max) = policy.limits.max_depth
        && depth > max
    {
        return Err(reject("link target resolves deeper than the depth limit"));
    }
    Ok(resolved)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn policy() -> Policy {
        Policy::default()
    }

    #[test]
    fn rejects_traversal_and_absolute_names() {
        let p = policy();
        for name in [
            &b"../x"[..],
            b"a/../../x",
            b"/abs",
            b"//server/share/x",
            b"C:\\x",
            b"C:/x",
            b"..\\x",
            b"a\\..\\..\\x",
            b"x\0y",
            b"",
            b"../",
        ] {
            assert!(
                sanitize(name, SeparatorRule::BackslashIsSeparator, &p, false).is_err(),
                "expected rejection of {name:?}"
            );
        }
    }

    #[test]
    fn accepts_and_normalises_ordinary_names() {
        let p = policy();
        let safe = sanitize(
            b"a\\b/c//d/",
            SeparatorRule::BackslashIsSeparator,
            &p,
            false,
        )
        .unwrap();
        assert_eq!(safe.display(), "a/b/c/d");
        assert_eq!(safe.raw_bytes(), b"a/b/c/d/");
        assert!(safe.is_dir());
        assert_eq!(safe.depth(), 4);
    }

    #[test]
    fn dots_are_dropped() {
        let p = policy();
        let safe = sanitize(b"./a/./b", SeparatorRule::BackslashIsSeparator, &p, false).unwrap();
        assert_eq!(safe.display(), "a/b");
    }

    #[test]
    fn collision_key_folds_case_and_normalisation() {
        let p = policy();
        let upper = sanitize(b"AbC", SeparatorRule::BackslashIsSeparator, &p, false).unwrap();
        let lower = sanitize(b"abc", SeparatorRule::BackslashIsSeparator, &p, false).unwrap();
        assert_eq!(upper.collision_key(), lower.collision_key());
        // NFD "e" + combining acute versus NFC "é"
        let nfd = sanitize(
            "e\u{0301}.txt".as_bytes(),
            SeparatorRule::BackslashIsSeparator,
            &p,
            false,
        )
        .unwrap();
        let nfc = sanitize(
            "\u{e9}.txt".as_bytes(),
            SeparatorRule::BackslashIsSeparator,
            &p,
            false,
        )
        .unwrap();
        assert_eq!(nfd.collision_key(), nfc.collision_key());
        // Full case folding: sharp s folds to ss
        let sharp = sanitize(
            "stra\u{df}e".as_bytes(),
            SeparatorRule::BackslashIsSeparator,
            &p,
            false,
        )
        .unwrap();
        let ss = sanitize(
            "strasse".as_bytes(),
            SeparatorRule::BackslashIsSeparator,
            &p,
            false,
        )
        .unwrap();
        assert_eq!(sharp.collision_key(), ss.collision_key());
    }

    #[test]
    fn windows_rules() {
        let p = Policy {
            windows_names: crate::policy::WindowsNames::Reject,
            ..Policy::default()
        };
        for name in [
            &b"NUL"[..],
            b"nul.txt",
            b"COM1",
            b"a.",
            b"a ",
            b"a:b",
            b"a<b",
        ] {
            assert!(
                sanitize(name, SeparatorRule::BackslashIsSeparator, &p, false).is_err(),
                "expected rejection of {name:?}"
            );
        }
        assert!(sanitize(b"nul.txt", SeparatorRule::BackslashIsSeparator, &p, false).is_err());
        assert!(sanitize(b"console", SeparatorRule::BackslashIsSeparator, &p, false).is_ok());
    }

    #[test]
    fn tar_backslash_is_literal_on_posix() {
        let p = policy();
        let safe = sanitize(b"a\\b", SeparatorRule::BackslashIsLiteral, &p, false).unwrap();
        assert_eq!(safe.depth(), 1);
        assert_eq!(safe.display(), "a\\b");
        assert!(sanitize(b"a\\b", SeparatorRule::BackslashIsLiteral, &p, true).is_err());
    }

    #[test]
    fn limits_are_enforced() {
        let mut p = policy();
        p.limits.max_component_bytes = Some(3);
        assert!(sanitize(b"abcd", SeparatorRule::BackslashIsSeparator, &p, false).is_err());
        let mut p = policy();
        p.limits.max_depth = Some(2);
        assert!(sanitize(b"a/b/c", SeparatorRule::BackslashIsSeparator, &p, false).is_err());
        let mut p = policy();
        p.limits.max_path_bytes = Some(3);
        assert!(sanitize(b"ab/cd", SeparatorRule::BackslashIsSeparator, &p, false).is_err());
    }

    #[test]
    fn symlink_target_rules() {
        let p = policy();
        assert!(validate_symlink_target(b"../x", 2, &p).is_ok());
        assert!(validate_symlink_target(b"../../x", 2, &p).is_ok());
        assert!(validate_symlink_target(b"../../../x", 2, &p).is_err());
        assert!(validate_symlink_target(b"a/../b", 2, &p).is_err());
        assert!(validate_symlink_target(b"b/../../x", 2, &p).is_err());
        assert!(validate_symlink_target(b"/etc", 2, &p).is_err());
        assert!(validate_symlink_target(b"a\\b", 2, &p).is_err());
        assert!(validate_symlink_target(b"C:x", 2, &p).is_err());
        assert!(validate_symlink_target(b"", 2, &p).is_err());
        let resolved = validate_symlink_target(b"../dir/file", 2, &p).unwrap();
        assert_eq!(resolved.len(), 2);
    }
}
