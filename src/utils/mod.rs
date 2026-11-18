//! Cross-cutting helpers (binary detection, paths, entropy, masking).

pub mod hashing;
pub mod logging;

use regex::Regex;
use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;

/// Decides whether a content must be treated as binary.
///
/// Heuristic close to Git's: a NUL byte in the first
/// 8000 bytes, or a high proportion of control bytes.
pub fn is_binary(data: &[u8]) -> bool {
    let window = &data[..data.len().min(8000)];
    if window.contains(&0) {
        return true;
    }
    if std::str::from_utf8(window).is_ok() {
        return false;
    }
    let control = window.iter().filter(|&&b| b < 0x09 || (b > 0x0d && b < 0x20)).count();
    control * 10 > window.len()
}

/// Converts content to text, normalising line endings (CRLF -> LF).
pub fn to_normalized_text(data: &[u8]) -> String {
    String::from_utf8_lossy(data).replace("\r\n", "\n")
}

/// Shannon entropy (bits per character).
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = std::collections::HashMap::new();
    let mut total = 0usize;
    for c in s.chars() {
        *counts.entry(c).or_insert(0usize) += 1;
        total += 1;
    }
    counts
        .values()
        .map(|&n| {
            let p = n as f64 / total as f64;
            -p * p.log2()
        })
        .sum()
}

/// Masks a sensitive value: only a few prefix characters are kept.
pub fn mask_secret(value: &str) -> String {
    let n = value.chars().count();
    if n <= 8 {
        return format!("{} ({} car.)", "*".repeat(n.max(4)), n);
    }
    let prefix: String = value.chars().take(4).collect();
    format!("{prefix}********** ({n} car.)")
}

/// Truncates a line for display in a report.
pub fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let t: String = s.chars().take(max).collect();
        format!("{t}…")
    }
}

/// Short hash for display.
pub fn short(hash: &str) -> &str {
    &hash[..hash.len().min(10)]
}

/// Lower-case extension of a relative path (without the dot).
pub fn extension(path: &str) -> Option<String> {
    let name = basename(path);
    let idx = name.rfind('.')?;
    if idx == 0 {
        return None;
    }
    Some(name[idx + 1..].to_ascii_lowercase())
}

/// Last component of a `/`-separated relative path.
pub fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Parent directory of a `/`-separated relative path ("" for the root).
pub fn dirname(path: &str) -> &str {
    match path.rfind('/') {
        Some(i) => &path[..i],
        None => "",
    }
}

/// Tells whether a path is likely a test or example file.
///
/// These files are **never** considered safe: the information is only
/// used to tone down the confidence level of a finding.
pub fn is_test_or_example_path(path: &str) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(
            r"(?i)(^|/)(tests?|spec|specs|__tests__|testdata|test-data|fixtures?|examples?|samples?|demo|mocks?)(/|$)|(^|/)(test_[^/]*|[^/]*(_test|\.test|\.spec|_spec)\.[^/]+)$|\.(example|sample|dist|template)$",
        )
        .expect("valid regex")
    });
    re.is_match(path)
}

/// Converts a `/` relative path into a safe path (rejects `..` and absolute paths).
pub fn safe_relative_path(p: &str) -> Option<PathBuf> {
    let path = Path::new(p);
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::Normal(s) => out.push(s),
            Component::CurDir => {}
            _ => return None,
        }
    }
    if out.as_os_str().is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Normalises a code line to compare "equivalent" lines.
pub fn normalize_code_line(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Is a code line a comment (multi-language heuristic)?
pub fn is_comment_line(s: &str) -> bool {
    let t = s.trim_start();
    t.starts_with("//")
        || t.starts_with('#') && !t.starts_with("#[") && !t.starts_with("#include") && !t.starts_with("#!")
        || t.starts_with("/*")
        || t.starts_with("* ")
        || t == "*"
        || t.starts_with("-- ")
        || t == "--"
        || t.starts_with("<!--")
        || t.starts_with(';')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_detection() {
        assert!(is_binary(b"abc\0def"));
        assert!(!is_binary("héllo\nworld".as_bytes()));
    }

    #[test]
    fn masking_hides_value() {
        let m = mask_secret(&format!("{}{}", "AKIA", "ABCDEFGHIJKLMNOP"));
        assert!(m.starts_with("AKIA"));
        assert!(!m.contains("MNOP"));
    }

    #[test]
    fn safe_paths() {
        assert!(safe_relative_path("../etc/passwd").is_none());
        assert!(safe_relative_path("/etc/passwd").is_none());
        assert_eq!(safe_relative_path("a/b.rs").unwrap(), PathBuf::from("a/b.rs"));
    }

    #[test]
    fn test_paths() {
        assert!(is_test_or_example_path("tests/a.rs"));
        assert!(is_test_or_example_path("src/foo.test.js"));
        assert!(is_test_or_example_path("config.example"));
        assert!(!is_test_or_example_path("src/latest.rs"));
    }
}
