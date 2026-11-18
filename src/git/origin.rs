//! Origin of changes: separates what the fork actually wrote from what
//! comes from the source through another path than the reference's
//! ancestry (cherry-pick, backport of a newer version, rollback to an
//! older version, file deleted later in the source).
//!
//! The main criterion is **content**: a fork file whose Git blob is
//! identical to a source version of the same path was not written by
//! the fork, whatever the history (even without Git history).

use super::patch_id::{MatchKind, PatchMatch};
use super::reference::UPSTREAM_REVS;
use super::repository::TempRepo;
use crate::diff::files::Snapshot;
use crate::diff::{ChangeOrigin, ChangeStatus, FileChange};
use crate::git::history::HistoryAnalysis;
use crate::utils::short;
use anyhow::Result;
use std::collections::{HashMap, HashSet};

/// Known source versions of a path.
#[derive(Debug, Default)]
struct PathVersions {
    /// blob → (most recent) source commit that produced this content.
    blobs: HashMap<String, String>,
    /// Source commits that deleted this path.
    deletions: Vec<String>,
}

/// Indexes, for the given paths, every content taken in the source history.
fn upstream_versions(repo: &TempRepo, paths: &[String]) -> Result<HashMap<String, PathVersions>> {
    let mut out: HashMap<String, PathVersions> = HashMap::new();
    for chunk in paths.chunks(400) {
        let mut args: Vec<String> = vec![
            "log".into(),
            "--raw".into(),
            "--no-abbrev".into(),
            "--no-renames".into(),
            "--no-merges".into(),
            "--format=%x1e%H".into(),
            UPSTREAM_REVS[0].into(),
            UPSTREAM_REVS[1].into(),
            "--".into(),
        ];
        args.extend(chunk.iter().map(|p| format!(":(literal){p}")));
        let text = repo.run(&args)?;
        for rec in text.split('\x1e') {
            let mut lines = rec.lines();
            let Some(commit) = lines.next().map(|s| s.trim().to_string()) else {
                continue;
            };
            for l in lines {
                // :100644 100644 <old> <new> M\tpath
                let Some((meta, path)) = l.split_once('\t') else {
                    continue;
                };
                let f: Vec<&str> = meta.split_whitespace().collect();
                if f.len() < 5 {
                    continue;
                }
                let v = out.entry(path.to_string()).or_default();
                if f[4].starts_with('D') {
                    v.deletions.push(commit.clone());
                } else {
                    // The log goes from newest to oldest: keep the first one seen.
                    v.blobs.entry(f[3].to_string()).or_insert_with(|| commit.clone());
                }
            }
        }
    }
    Ok(out)
}

/// Determines the origin of each change.
pub fn attribute_origins(
    repo: &TempRepo,
    base: &str,
    client: &Snapshot,
    changes: &mut [FileChange],
    history: Option<&HistoryAnalysis>,
) -> Result<()> {
    let paths: Vec<String> = changes.iter().map(|c| c.path.clone()).collect();
    let versions = upstream_versions(repo, &paths)?;
    let mut ancestor_cache: HashMap<String, bool> = HashMap::new();
    let mut is_older = |commit: &str| -> bool {
        *ancestor_cache
            .entry(commit.to_string())
            .or_insert_with(|| repo.is_ancestor(commit, base).unwrap_or(false))
    };

    // Fork commits matching source commits (patch-id).
    let upstream_copies: HashMap<&str, &PatchMatch> = history
        .map(|h| {
            h.patch_matches
                .iter()
                .filter(|m| matches!(m.kind, MatchKind::CherryPick | MatchKind::Rewritten))
                .map(|m| (m.client_commit.as_str(), m))
                .collect()
        })
        .unwrap_or_default();
    let uncommitted: HashSet<&str> = history
        .map(|h| {
            let wt = &h.working_tree;
            wt.staged
                .iter()
                .chain(wt.unstaged.iter())
                .map(|e| e.path.as_str())
                .chain(wt.untracked.iter().map(|s| s.as_str()))
                .chain(wt.ignored.iter().map(|s| s.as_str()))
                .collect()
        })
        .unwrap_or_default();
    let has_merges = history.map(|h| h.merge_commits > 0).unwrap_or(false);

    for c in changes.iter_mut() {
        let v = versions.get(&c.path);
        // 1. Content identical to a source version of the same path.
        if c.status != ChangeStatus::Deleted {
            if let (Some(v), Some(entry)) = (v, client.entries.get(&c.path)) {
                if let Some(commit) = v.blobs.get(&entry.oid) {
                    let older = is_older(commit);
                    c.origin = if older {
                        ChangeOrigin::UpstreamOlder
                    } else {
                        ChangeOrigin::UpstreamNewer
                    };
                    c.upstream_commit = Some(commit.clone());
                    c.origin_detail = Some(if older {
                        format!(
                            "content identical to the source version of commit {} (older than the reference: rollback)",
                            short(commit)
                        )
                    } else {
                        format!("content identical to the source version of commit {} (newer than the reference or another branch)", short(commit))
                    });
                    continue;
                }
            }
        } else if let Some(d) = v.and_then(|v| v.deletions.iter().find(|d| !is_older(d))) {
            c.origin = ChangeOrigin::UpstreamNewer;
            c.upstream_commit = Some(d.clone());
            c.origin_detail = Some(format!("file also deleted in the source by commit {}", short(d)));
            continue;
        }

        // 2. Without history: change presumed to come from the fork.
        let Some(_h) = history else {
            c.origin = ChangeOrigin::Client;
            c.origin_detail = Some("presumed fork (no Git history available)".into());
            continue;
        };

        let in_worktree = uncommitted.contains(c.path.as_str())
            || c.old_path.as_deref().map(|p| uncommitted.contains(p)).unwrap_or(false);
        let own: Vec<&String> = c
            .commits
            .iter()
            .filter(|h| !upstream_copies.contains_key(h.as_str()))
            .collect();
        let copies: Vec<&PatchMatch> = c
            .commits
            .iter()
            .filter_map(|h| upstream_copies.get(h.as_str()).copied())
            .collect();

        if !own.is_empty() {
            c.origin = ChangeOrigin::Client;
            c.origin_detail = Some(format!(
                "{} fork commit(s){}",
                own.len(),
                if in_worktree { " + uncommitted changes" } else { "" }
            ));
        } else if in_worktree {
            c.origin = ChangeOrigin::Uncommitted;
            c.origin_detail = Some(if c.untracked {
                "file not tracked by Git".into()
            } else {
                "uncommitted change".into()
            });
        } else if !copies.is_empty() {
            c.origin = ChangeOrigin::UpstreamCherryPick;
            c.upstream_commit = Some(copies[0].upstream_commit.clone());
            c.origin_detail = Some(format!(
                "brought by a copy of source commit {} ({}), content then different from every source version",
                short(&copies[0].upstream_commit),
                copies[0].kind.label()
            ));
        } else {
            c.origin = ChangeOrigin::Undetermined;
            c.origin_detail = Some(if has_merges {
                "no non-merge fork commit touches this file: change probably introduced while resolving a merge".into()
            } else {
                "no fork commit touches this file".into()
            });
        }
    }
    Ok(())
}
