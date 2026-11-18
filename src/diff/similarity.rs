//! Content similarity and diff hunk construction.

use super::{DiffLine, Hunk, LineKind};
use similar::{Algorithm, ChangeTag, TextDiff};
use std::time::Duration;

const DIFF_TIMEOUT: Duration = Duration::from_secs(3);

/// Line-based similarity (0..1) between two texts.
pub fn similarity(old: &str, new: &str) -> f64 {
    if old == new {
        return 1.0;
    }
    if old.is_empty() || new.is_empty() {
        return 0.0;
    }
    TextDiff::configure()
        .algorithm(Algorithm::Myers)
        .timeout(DIFF_TIMEOUT)
        .diff_lines(old, new)
        .ratio() as f64
}

/// Builds the hunks (with `context` context lines) and counts added/removed lines.
pub fn build_hunks(old: &str, new: &str, context: usize) -> (Vec<Hunk>, usize, usize) {
    let diff = TextDiff::configure()
        .algorithm(Algorithm::Myers)
        .timeout(DIFF_TIMEOUT)
        .diff_lines(old, new);
    let mut added = 0;
    let mut removed = 0;
    let mut hunks = Vec::new();
    for group in diff.grouped_ops(context) {
        let (Some(first), Some(last)) = (group.first(), group.last()) else {
            continue;
        };
        let old_start = first.old_range().start;
        let old_end = last.old_range().end;
        let new_start = first.new_range().start;
        let new_end = last.new_range().end;
        let mut lines = Vec::new();
        for op in &group {
            for change in diff.iter_changes(op) {
                let kind = match change.tag() {
                    ChangeTag::Equal => LineKind::Context,
                    ChangeTag::Delete => {
                        removed += 1;
                        LineKind::Removed
                    }
                    ChangeTag::Insert => {
                        added += 1;
                        LineKind::Added
                    }
                };
                lines.push(DiffLine {
                    kind,
                    old_no: change.old_index().map(|i| i + 1),
                    new_no: change.new_index().map(|i| i + 1),
                    text: change.value().trim_end_matches(['\n', '\r']).to_string(),
                });
            }
        }
        hunks.push(Hunk {
            old_start: old_start + 1,
            old_lines: old_end - old_start,
            new_start: new_start + 1,
            new_lines: new_end - new_start,
            lines,
        });
    }
    (hunks, added, removed)
}

/// Single hunk for a fully added (`added = true`) or deleted file.
pub fn whole_file_hunk(text: &str, added: bool) -> (Vec<Hunk>, usize) {
    let lines: Vec<DiffLine> = text
        .lines()
        .enumerate()
        .map(|(i, l)| DiffLine {
            kind: if added { LineKind::Added } else { LineKind::Removed },
            old_no: if added { None } else { Some(i + 1) },
            new_no: if added { Some(i + 1) } else { None },
            text: l.to_string(),
        })
        .collect();
    let n = lines.len();
    if n == 0 {
        return (vec![], 0);
    }
    let hunk = if added {
        Hunk {
            old_start: 0,
            old_lines: 0,
            new_start: 1,
            new_lines: n,
            lines,
        }
    } else {
        Hunk {
            old_start: 1,
            old_lines: n,
            new_start: 0,
            new_lines: 0,
            lines,
        }
    };
    (vec![hunk], n)
}

/// Renders as a unified diff.
pub fn render_unified(old_path: Option<&str>, new_path: Option<&str>, hunks: &[Hunk]) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "--- {}\n",
        old_path.map(|p| format!("a/{p}")).unwrap_or_else(|| "/dev/null".into())
    ));
    s.push_str(&format!(
        "+++ {}\n",
        new_path.map(|p| format!("b/{p}")).unwrap_or_else(|| "/dev/null".into())
    ));
    for h in hunks {
        s.push_str(&format!(
            "@@ -{},{} +{},{} @@\n",
            h.old_start, h.old_lines, h.new_start, h.new_lines
        ));
        for l in &h.lines {
            let c = match l.kind {
                LineKind::Context => ' ',
                LineKind::Added => '+',
                LineKind::Removed => '-',
            };
            s.push(c);
            s.push_str(&l.text);
            s.push('\n');
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_lines() {
        let (h, a, r) = build_hunks("a\nb\nc\n", "a\nB\nc\nd\n", 1);
        assert_eq!((a, r), (2, 1));
        assert!(!h.is_empty());
        assert!(similarity("a\nb\nc\n", "a\nb\nc\n") == 1.0);
        assert!(similarity("a\nb\nc\nd\n", "a\nb\nc\nx\n") > 0.7);
    }
}
