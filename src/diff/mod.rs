//! File comparison between the source reference and the fork.

pub mod compare;
pub mod files;
pub mod similarity;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Status of a file relative to the reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ChangeStatus {
    Added,
    Deleted,
    Modified,
    /// File name changed (possibly also moved).
    Renamed,
    /// Same name, different directory.
    Moved,
    Identical,
}

impl ChangeStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Added => "added",
            Self::Deleted => "deleted",
            Self::Modified => "modified",
            Self::Renamed => "renamed",
            Self::Moved => "moved",
            Self::Identical => "identical",
        }
    }
}

/// Origin of a change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ChangeOrigin {
    /// Change written by the fork (the fork's own commits).
    #[serde(rename = "fork")]
    Client,
    /// Change present only in the working tree (uncommitted / untracked).
    Uncommitted,
    /// Content identical to a newer source version or another branch (backport).
    #[serde(rename = "source_newer")]
    UpstreamNewer,
    /// Content identical to a source version older than the reference (rollback).
    #[serde(rename = "source_older")]
    UpstreamOlder,
    /// Introduced by a fork commit copied from a source commit (cherry-pick).
    #[serde(rename = "source_cherry_pick")]
    UpstreamCherryPick,
    /// Undetermined origin (e.g. merge resolution).
    Undetermined,
}

impl ChangeOrigin {
    pub fn label(self) -> &'static str {
        match self {
            Self::Client => "fork",
            Self::Uncommitted => "fork (uncommitted)",
            Self::UpstreamNewer => "source (newer version)",
            Self::UpstreamOlder => "source (older version)",
            Self::UpstreamCherryPick => "source (cherry-pick)",
            Self::Undetermined => "undetermined",
        }
    }
    /// Is the change attributable to the fork?
    pub fn is_client(self) -> bool {
        matches!(self, Self::Client | Self::Uncommitted | Self::Undetermined)
    }
    pub const ALL: [ChangeOrigin; 6] = [
        Self::Client,
        Self::Uncommitted,
        Self::Undetermined,
        Self::UpstreamCherryPick,
        Self::UpstreamNewer,
        Self::UpstreamOlder,
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LineKind {
    Context,
    Added,
    Removed,
}

/// Line of a hunk.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DiffLine {
    pub kind: LineKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_no: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_no: Option<usize>,
    pub text: String,
}

/// Block of contiguous changes.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Hunk {
    pub old_start: usize,
    pub old_lines: usize,
    pub new_start: usize,
    pub new_lines: usize,
    pub lines: Vec<DiffLine>,
}

/// Change of a file.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct FileChange {
    /// Path in the fork (or in the reference for a deleted file).
    pub path: String,
    /// Former path (rename / move).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_path: Option<String>,
    pub status: ChangeStatus,
    pub is_binary: bool,
    /// Type change (executable, symbolic link…).
    pub mode_changed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_sha256: Option<String>,
    pub lines_added: usize,
    pub lines_removed: usize,
    /// Content similarity (0-1) with the reference version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub similarity: Option<f64>,
    /// Only line endings differ.
    pub eol_only: bool,
    /// File too large for a line diff.
    pub too_large: bool,
    /// File not tracked by Git in the fork.
    pub untracked: bool,
    /// Origin of the change.
    pub origin: ChangeOrigin,
    /// Explanation of the origin.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin_detail: Option<String>,
    /// Source commit the content comes from (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "source_commit")]
    pub upstream_commit: Option<String>,
    /// Hunks (included in the JSON only with `--full-diff`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hunks: Vec<Hunk>,
    /// Relative path of the `.diff` file generated in the output directory.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diff_file: Option<String>,
    /// Fork commits that touched this file.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub commits: Vec<String>,
}

impl FileChange {
    pub fn new(path: String, status: ChangeStatus) -> Self {
        Self {
            path,
            old_path: None,
            status,
            is_binary: false,
            mode_changed: false,
            old_size: None,
            new_size: None,
            old_sha256: None,
            new_sha256: None,
            lines_added: 0,
            lines_removed: 0,
            similarity: None,
            eol_only: false,
            too_large: false,
            untracked: false,
            origin: ChangeOrigin::Client,
            origin_detail: None,
            upstream_commit: None,
            hunks: vec![],
            diff_file: None,
            commits: vec![],
        }
    }

    /// Added lines with their number (new file side) and hunk index.
    pub fn added_lines(&self) -> impl Iterator<Item = (usize, Option<usize>, &str)> {
        self.hunks.iter().enumerate().flat_map(|(hi, h)| {
            h.lines
                .iter()
                .filter(|l| l.kind == LineKind::Added)
                .map(move |l| (hi, l.new_no, l.text.as_str()))
        })
    }

    /// Removed lines with their number (old file side) and hunk index.
    pub fn removed_lines(&self) -> impl Iterator<Item = (usize, Option<usize>, &str)> {
        self.hunks.iter().enumerate().flat_map(|(hi, h)| {
            h.lines
                .iter()
                .filter(|l| l.kind == LineKind::Removed)
                .map(move |l| (hi, l.old_no, l.text.as_str()))
        })
    }
}

/// Parses a unified diff patch produced by `git show` / `git log -p`.
pub fn parse_unified_diff(text: &str) -> Vec<FileChange> {
    let mut out: Vec<FileChange> = Vec::new();
    let mut cur: Option<FileChange> = None;
    let (mut old_no, mut new_no) = (0usize, 0usize);
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("diff --git ") {
            if let Some(c) = cur.take() {
                out.push(c);
            }
            let path = rest
                .split_once(" b/")
                .map(|(_, b)| b.to_string())
                .unwrap_or_else(|| rest.trim_start_matches("a/").to_string());
            cur = Some(FileChange::new(unquote(&path), ChangeStatus::Modified));
            continue;
        }
        let Some(c) = cur.as_mut() else { continue };
        if line.starts_with("new file mode") {
            c.status = ChangeStatus::Added;
        } else if line.starts_with("deleted file mode") {
            c.status = ChangeStatus::Deleted;
        } else if line.starts_with("Binary files") || line.starts_with("GIT binary patch") {
            c.is_binary = true;
        } else if line.starts_with("old mode") || line.starts_with("new mode") {
            c.mode_changed = true;
        } else if let Some(h) = line.strip_prefix("@@ ") {
            let (os, ol, ns, nl) = parse_hunk_header(h);
            old_no = os;
            new_no = ns;
            c.hunks.push(Hunk {
                old_start: os,
                old_lines: ol,
                new_start: ns,
                new_lines: nl,
                lines: vec![],
            });
        } else if line.starts_with("--- ") || line.starts_with("+++ ") {
            if c.hunks.is_empty() {
                continue;
            }
            push_line(c, line, &mut old_no, &mut new_no);
        } else if !c.hunks.is_empty() && (line.starts_with('+') || line.starts_with('-') || line.starts_with(' ')) {
            push_line(c, line, &mut old_no, &mut new_no);
        }
    }
    if let Some(c) = cur.take() {
        out.push(c);
    }
    out
}

fn push_line(c: &mut FileChange, line: &str, old_no: &mut usize, new_no: &mut usize) {
    let Some(h) = c.hunks.last_mut() else { return };
    let (kind, text) = match line.as_bytes()[0] {
        b'+' => (LineKind::Added, &line[1..]),
        b'-' => (LineKind::Removed, &line[1..]),
        _ => (LineKind::Context, &line[1..]),
    };
    let dl = match kind {
        LineKind::Added => {
            c.lines_added += 1;
            *new_no += 1;
            DiffLine {
                kind,
                old_no: None,
                new_no: Some(*new_no - 1),
                text: text.to_string(),
            }
        }
        LineKind::Removed => {
            c.lines_removed += 1;
            *old_no += 1;
            DiffLine {
                kind,
                old_no: Some(*old_no - 1),
                new_no: None,
                text: text.to_string(),
            }
        }
        LineKind::Context => {
            *old_no += 1;
            *new_no += 1;
            DiffLine {
                kind,
                old_no: Some(*old_no - 1),
                new_no: Some(*new_no - 1),
                text: text.to_string(),
            }
        }
    };
    h.lines.push(dl);
}

fn parse_hunk_header(h: &str) -> (usize, usize, usize, usize) {
    let mut parts = h.split_whitespace();
    let parse = |s: Option<&str>, prefix: char| -> (usize, usize) {
        let s = s.unwrap_or("").trim_start_matches(prefix);
        let mut it = s.split(',');
        let start = it.next().and_then(|x| x.parse().ok()).unwrap_or(0);
        let len = it.next().and_then(|x| x.parse().ok()).unwrap_or(1);
        (start, len)
    };
    let (os, ol) = parse(parts.next(), '-');
    let (ns, nl) = parse(parts.next(), '+');
    (os, ol, ns, nl)
}

/// Removes Git's C-style quoting from special paths.
fn unquote(p: &str) -> String {
    let p = p.trim();
    if p.starts_with('"') && p.ends_with('"') && p.len() >= 2 {
        p[1..p.len() - 1]
            .replace("\\\"", "\"")
            .replace("\\\\", "\\")
            .replace("\\t", "\t")
    } else {
        p.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_git_patch() {
        let patch = "diff --git a/src/a.py b/src/a.py\nindex 1..2 100644\n--- a/src/a.py\n+++ b/src/a.py\n@@ -1,3 +1,3 @@\n def f(u):\n-    if u.is_admin:\n+    if True:\n         pass\ndiff --git a/n.txt b/n.txt\nnew file mode 100644\n--- /dev/null\n+++ b/n.txt\n@@ -0,0 +1 @@\n+hello\n";
        let c = parse_unified_diff(patch);
        assert_eq!(c.len(), 2);
        assert_eq!(c[0].path, "src/a.py");
        assert_eq!(c[0].lines_added, 1);
        assert_eq!(c[0].lines_removed, 1);
        let removed: Vec<_> = c[0].removed_lines().collect();
        assert_eq!(removed[0].1, Some(2));
        assert_eq!(c[1].status, ChangeStatus::Added);
        assert_eq!(c[1].added_lines().next().unwrap().1, Some(1));
    }
}
